/*
 * Copyright (C) 2021 SUSE LLC
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License version
 * 2 as published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
 *
 * This file implements a simple monitor for NVMe-related uevents.
 */

#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <libudev.h>
#include <signal.h>
#include <time.h>
#include <limits.h>
#include <syslog.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/epoll.h>

#include "common.h"
#include "nvme-status.h"
#include "nvme.h"
#include "util/argconfig.h"
#include "fabrics.h"
#include "monitor.h"
#include "conn-db.h"
#define LOG_FUNCNAME 1
#include "log.h"

static struct monitor_config {
	bool autoconnect;
	bool skip_udev_on_exit;
} mon_cfg;

static struct udev *udev;

static void close_ptr(int *p)
{
	if (*p != -1) {
		close(*p);
		*p = -1;
	}
}

CLEANUP_FUNC(char)

static void cleanup_monitor(struct udev_monitor **pmon)
{
	if (*pmon) {
		udev_monitor_unref(*pmon);
		*pmon = NULL;
	}
}

static int create_udev_monitor(struct udev_monitor **pmon)
{
	struct udev_monitor *mon __attribute((cleanup(cleanup_monitor))) = NULL;
	int ret;

	if (!udev) {
		udev = udev_new();
		if (!udev)
			return -ENOMEM;
	}
	mon = udev_monitor_new_from_netlink(udev, "kernel");
	if (!mon)
		return errno ? -errno : -ENOMEM;

	/* Add match for NVMe controller devices */
	ret = udev_monitor_filter_add_match_subsystem_devtype(mon, "nvme", NULL);
	/* Add match for fc_udev_device */
	ret = udev_monitor_filter_add_match_subsystem_devtype(mon, "fc", NULL);
	/*
	 * This fails in unpriviliged mode. Use the same value as udevd.
	 * We may able to decrease this buffer size later.
	 */
	(void)udev_monitor_set_receive_buffer_size(mon, 128*1024*1024);
	ret = udev_monitor_enable_receiving(mon);
	if (ret < 0)
		return ret;
	*pmon = mon;
	mon = NULL;
	return 0;
}

static sig_atomic_t must_exit;

static void monitor_int_handler(int sig)
{
	must_exit = 1;
}

static sig_atomic_t got_sigchld;

static void monitor_chld_handler(int sig)
{
	got_sigchld = 1;
}

static sigset_t orig_sigmask;

static int monitor_init_signals(void)
{
	sigset_t mask;
	struct sigaction sa = { .sa_handler = monitor_int_handler, };

	/*
	 * Block all signals. They will be unblocked when we wait
	 * for events.
	 */
	sigfillset(&mask);
	if (sigprocmask(SIG_BLOCK, &mask, &orig_sigmask) == -1)
		return -errno;
	if (sigaction(SIGTERM, &sa, NULL) == -1)
		return -errno;
	if (sigaction(SIGINT, &sa, NULL) == -1)
		return -errno;
	sa.sa_handler = monitor_chld_handler;
	if (sigaction(SIGCHLD, &sa, NULL) == -1)
		return -errno;
	return 0;
}

static int child_reset_signals(void)
{
	int err = 0;
	struct sigaction sa = { .sa_handler = SIG_DFL, };

	if (sigaction(SIGTERM, &sa, NULL) == -1)
		err = errno;
	if (sigaction(SIGINT, &sa, NULL) == -1 && !err)
		err = errno;
	if (sigaction(SIGCHLD, &sa, NULL) == -1 && !err)
		err = errno;

	if (sigprocmask(SIG_SETMASK, &orig_sigmask, NULL) == -1 && !err)
		err = errno;

	if (err)
		log(LOG_ERR, "error resetting signal handlers and mask\n");
	return -err;
}

static int monitor_get_fc_uev_props(struct udev_device *ud,
				    char *traddr, size_t tra_sz,
				    char *host_traddr, size_t htra_sz)
{
	const char *sysname = udev_device_get_sysname(ud);
	const char *tra = NULL, *host_tra = NULL;
	bool fc_event_seen = false;
	struct udev_list_entry *entry;

	entry = udev_device_get_properties_list_entry(ud);
	if (!entry) {
		log(LOG_NOTICE, "%s: emtpy properties list\n", sysname);
		return -ENOENT;
	}

	for (; entry; entry = udev_list_entry_get_next(entry)) {
		const char *name = udev_list_entry_get_name(entry);

		if (!strcmp(name, "FC_EVENT") &&
		    !strcmp(udev_list_entry_get_value(entry), "nvmediscovery"))
				fc_event_seen = true;
		else if (!strcmp(name, "NVMEFC_HOST_TRADDR"))
			host_tra = udev_list_entry_get_value(entry);
		else if (!strcmp(name, "NVMEFC_TRADDR"))
			tra = udev_list_entry_get_value(entry);
	}
	if (!fc_event_seen) {
		log(LOG_DEBUG, "%s: FC_EVENT property missing or unsupported\n",
		    sysname);
		return -EINVAL;
	}
	if (!tra || !host_tra) {
		log(LOG_WARNING, "%s: transport properties missing\n", sysname);
		return -EINVAL;
	}

	if (!memccpy(traddr, tra, '\0', tra_sz) ||
	    !memccpy(host_traddr, host_tra, '\0', htra_sz)) {
		log(LOG_ERR, "traddr (%zu) or host_traddr (%zu) overflow\n",
		    strlen(traddr), strlen(host_traddr));
		return -ENAMETOOLONG;
	}

	return 0;
}

static int monitor_discovery(const char *transport, const char *traddr,
			     const char *trsvcid, const char *host_traddr,
			     const char *devname)
{
	char argstr[BUF_SIZE];
	pid_t pid;
	int rc, db_rc;
	struct nvme_connection *co = NULL;
	char *device = NULL;

	db_rc = conndb_add(transport, traddr, trsvcid, host_traddr, &co);
	if (db_rc != 0 && db_rc != -EEXIST)
		return db_rc;

	if (co->status == CS_DISC_RUNNING) {
		co->discovery_pending = 1;
		return -EAGAIN;
	}

	pid = fork();
	if (pid == -1) {
		log(LOG_ERR, "failed to fork discovery task: %m");
		return -errno;
	} else if (pid > 0) {
		log(LOG_DEBUG, "started discovery task %ld\n", (long)pid);

		co->discovery_pending = 0;
		co->status = CS_DISC_RUNNING;
		co->discovery_task = pid;
		if (devname) {
			int instance = ctrl_instance(devname);

			if (instance < 0) {
				log(LOG_ERR, "unexpected devname: %s\n",
				    devname);
			} else
				co->discovery_instance = instance;
		}
		return 0;
	}

	child_reset_signals();

	log(LOG_NOTICE, "starting discovery for <%s>: %s ==> %s(%s) in state %s\n",
	    transport, host_traddr, traddr,
	    trsvcid && *trsvcid ? trsvcid : "none",
	    conn_status_str(co->status));

	/*
	 * Try to re-use existing controller. do_discovery() will check
	 * if it matches the connection parameters.
	 */
	if (!devname && co->discovery_instance >= 0) {
		if (asprintf(&device, "nvme%d", co->discovery_instance) == -1)
			device = NULL;
		else
			devname = device;
	}

	if (devname)
		log(LOG_INFO, "using discovery controller %s\n", devname);

	cfg.nqn = NVME_DISC_SUBSYS_NAME;
	cfg.transport = transport;
	cfg.traddr = traddr;
	cfg.trsvcid = trsvcid && *trsvcid ? trsvcid : NULL;
	cfg.host_traddr = host_traddr && *host_traddr ? host_traddr : NULL;
	cfg.device = devname;
	/* Without the following, the kernel returns EINVAL */
	cfg.tos = -1;

	rc = build_options(argstr, sizeof(argstr), true);
	log(LOG_DEBUG, "%s\n", argstr);
	rc = do_discover(argstr, mon_cfg.autoconnect);

	free(device);
	exit(-rc);
	/* not reached */
	return rc;
}

static void monitor_handle_fc_uev(struct udev_device *ud)
{
	const char *action = udev_device_get_action(ud);
	const char *sysname = udev_device_get_sysname(ud);
	char traddr[NVMF_TRADDR_SIZE], host_traddr[NVMF_TRADDR_SIZE];

	if (strcmp(action, "change") || strcmp(sysname, "fc_udev_device"))
		return;

	if (monitor_get_fc_uev_props(ud, traddr, sizeof(traddr),
				     host_traddr, sizeof(host_traddr)))
		return;

	monitor_discovery("fc", traddr, NULL, host_traddr, NULL);
}

static int monitor_get_nvme_uev_props(struct udev_device *ud,
				      char *transport, size_t tr_sz,
				      char *traddr, size_t tra_sz,
				      char *trsvcid, size_t trs_sz,
				      char *host_traddr, size_t htra_sz)
{
	const char *sysname = udev_device_get_sysname(ud);
	bool aen_disc = false;
	struct udev_list_entry *entry;

	entry = udev_device_get_properties_list_entry(ud);
	if (!entry) {
		log(LOG_NOTICE, "%s: emtpy properties list\n", sysname);
		return -ENOENT;
	}

	*transport = *traddr = *trsvcid = *host_traddr = '\0';
	for (; entry; entry = udev_list_entry_get_next(entry)) {
		const char *name = udev_list_entry_get_name(entry);

		if (!strcmp(name, "NVME_AEN") &&
		    !strcmp(udev_list_entry_get_value(entry), "0x70f002"))
				aen_disc = true;
		else if (!strcmp(name, "NVME_TRTYPE"))
			memccpy(transport, udev_list_entry_get_value(entry),
				'\0', tr_sz);
		else if (!strcmp(name, "NVME_TRADDR"))
			memccpy(traddr, udev_list_entry_get_value(entry),
				'\0', htra_sz);
		else if (!strcmp(name, "NVME_TRSVCID"))
			memccpy(trsvcid, udev_list_entry_get_value(entry),
				'\0', trs_sz);
		else if (!strcmp(name, "NVME_HOST_TRADDR"))
			memccpy(host_traddr, udev_list_entry_get_value(entry),
				'\0', tra_sz);
	}
	if (!aen_disc) {
		log(LOG_DEBUG, "%s: not a \"discovery log changed\" AEN, ignoring event\n",
		    sysname);
		return -EINVAL;
	}

	if (!*traddr || !*transport) {
		log(LOG_WARNING, "%s: transport properties missing\n", sysname);
		return -EINVAL;
	}

	return 0;
}

static void monitor_handle_nvme_uev(struct udev_device *ud)
{
	char traddr[NVMF_TRADDR_SIZE], host_traddr[NVMF_TRADDR_SIZE];
	char trsvcid[NVMF_TRSVCID_SIZE], transport[5];

	if (strcmp(udev_device_get_action(ud), "change"))
		return;

	if (monitor_get_nvme_uev_props(ud, transport, sizeof(transport),
				       traddr, sizeof(traddr),
				       trsvcid, sizeof(trsvcid),
				       host_traddr, sizeof(host_traddr)))
		return;

	monitor_discovery(transport, traddr,
			  strcmp(trsvcid, "none") ? trsvcid : NULL, host_traddr,
			  udev_device_get_sysname(ud));
}

static void monitor_handle_udevice(struct udev_device *ud)
{
	const char *subsys  = udev_device_get_subsystem(ud);

	if (log_level >= LOG_INFO) {
		const char *action = udev_device_get_action(ud);
		const char *syspath = udev_device_get_syspath(ud);

		log(LOG_INFO, "%s %s\n", action, syspath);
	}
	if (!strcmp(subsys, "fc"))
		monitor_handle_fc_uev(ud);
	else if (!strcmp(subsys, "nvme"))
		monitor_handle_nvme_uev(ud);
}

static void monitor_handle_uevents(struct udev_monitor *monitor)
{
	struct udev_device *ud;

	for (ud = udev_monitor_receive_device(monitor);
	     ud;
	     ud = udev_monitor_receive_device(monitor)) {
		monitor_handle_udevice(ud);
		udev_device_unref(ud);
	}
}

static void handle_sigchld(void)
{
	while (true) {
	struct nvme_connection *co;
		int wstatus;
		pid_t pid;

		pid = waitpid(-1, &wstatus, WNOHANG);
		switch(pid) {
		case -1:
			if (errno != ECHILD)
				log(LOG_ERR, "error in waitpid: %m\n");
			return;
		case 0:
			return;
		default:
			break;
		}
		co = conndb_find_by_pid(pid);
		if (!co) {
			log(LOG_ERR, "no connection found for discovery task %ld\n",
			    (long)pid);
			continue;
		}
		if (!WIFEXITED(wstatus)) {
			log(LOG_WARNING, "child %ld didn't exit normally\n",
			    (long)pid);
			co->status = CS_FAILED;
		} else if (WEXITSTATUS(wstatus) != 0) {
			log(LOG_NOTICE, "child %ld exited with status \"%s\"\n",
			    (long)pid, strerror(WEXITSTATUS(wstatus)));
			co->status = CS_FAILED;
			co->did_discovery = 1;
			co->discovery_result = WEXITSTATUS(wstatus);
		} else {
			log(LOG_DEBUG, "child %ld exited normally\n", (long)pid);
			co->status = CS_ONLINE;
			co->successful_discovery = co->did_discovery = 1;
			co->discovery_result = 0;
		}
		if (co->discovery_pending) {
			log(LOG_NOTICE, "new discovery pending - restarting\n");
			monitor_discovery(co->transport, co->traddr,
					  co->trsvcid, co->host_traddr, NULL);
		}
	};
}

#define MAX_EVENTS 1
static int monitor_main_loop(struct udev_monitor *monitor)
{
	int ep_fd __attribute__((cleanup(close_ptr))) = -1;
	int ret;
	struct epoll_event ep_ev = { .events = EPOLLIN, };
	struct epoll_event events[MAX_EVENTS];
	sigset_t ep_mask;

	ep_fd = epoll_create1(0);
	if (ep_fd == -1)
		return -errno;
	ep_ev.data.ptr = monitor;
	ret = epoll_ctl(ep_fd, EPOLL_CTL_ADD,
			udev_monitor_get_fd(monitor), &ep_ev);
	if (ret == -1)
		return -errno;

	sigfillset(&ep_mask);
	sigdelset(&ep_mask, SIGTERM);
	sigdelset(&ep_mask, SIGINT);
	sigdelset(&ep_mask, SIGCHLD);
	while (1) {
		int rc, i;

		rc = epoll_pwait(ep_fd, events, MAX_EVENTS, -1, &ep_mask);
		if (rc == -1 && errno == EINTR) {
			if (must_exit) {
				log(LOG_NOTICE, "monitor: exit signal received\n");
				return 0;
			} else if (got_sigchld) {
				got_sigchld = 0;
				handle_sigchld();
			}
		} else if (rc == -1) {
			log(LOG_ERR, "monitor: epoll_wait: %m\n");
			return -errno;
		} else if (rc == 0 || rc > MAX_EVENTS) {
			log(LOG_ERR, "monitor: epoll_wait: unexpected rc=%d\n", rc);
			continue;
		}
		for (i = 0; i < MAX_EVENTS; i++) {
			if (events[i].data.ptr == monitor)
				(void)monitor_handle_uevents(monitor);
			else
				log(LOG_ERR, "monitor: unexpected event\n");
		}
	}
	return ret;
}

static const char autoconnect_rules[] = "/run/udev/rules.d/70-nvmf-autoconnect.rules";

static int monitor_disable_udev_rules(void)
{
	CLEANUP(char, path) = strdup(autoconnect_rules);
	char *s1, *s2;
	int rc;

	if (!path)
		return -ENOMEM;

	s2 = strrchr(path, '/');
	for (s1 = s2 - 1; s1 > path && *s1 != '/'; s1--);

	*s2 = *s1 = '\0';
	rc = mkdir(path, 0755);
	if (rc == 0 || errno == EEXIST) {
		*s1 = '/';
		rc = mkdir(path, 0755);
		if (rc == 0 || errno == EEXIST) {
			*s2 = '/';
			rc = symlink("/dev/null", path);
		}
	}
	if (rc) {
		if (errno == EEXIST) {
			char target[PATH_MAX];

			if (readlink(path, target, sizeof(target)) != -1 &&
			    !strcmp(target, "/dev/null")) {
				log(LOG_INFO,
				    "symlink %s -> /dev/null exists already\n",
				    autoconnect_rules);
				return 1;
			}
		}
		log(LOG_ERR, "error creating %s: %m\n", autoconnect_rules);
	} else
		log(LOG_INFO, "created %s\n", autoconnect_rules);

	return rc ? (errno ? -errno : -EIO) : 0;
}

static void monitor_enable_udev_rules(void)
{
	if (unlink(autoconnect_rules) == -1 && errno != ENOENT)
		log(LOG_ERR, "error removing %s: %m\n", autoconnect_rules);
	else
		log(LOG_INFO, "removed %s\n", autoconnect_rules);
}

static int monitor_parse_opts(const char *desc, int argc, char **argv)
{
	bool quiet = false;
	bool verbose = false;
	bool debug = false;
	int ret = 0;

	OPT_ARGS(opts) = {
		OPT_FLAG("autoconnect",    'A', &mon_cfg.autoconnect, "automatically connect newly discovered controllers"),
		OPT_FLAG("persistent",     'p', &cfg.persistent,      "persistent discovery connections"),
		OPT_FLAG("silent",         'S', &quiet,               "log level: silent"),
		OPT_FLAG("verbose",        'v', &verbose,             "log level: verbose"),
		OPT_FLAG("debug",          'D', &debug,               "log level: debug"),
		OPT_FLAG("clockstamps",    'C', &log_timestamp,       "print log timestamps"),
		OPT_END()
	};

	ret = argconfig_parse(argc, argv, desc, opts);
	if (ret)
		return ret;
	if (quiet)
		log_level = LOG_WARNING;
	if (verbose)
		log_level = LOG_INFO;
	if (debug)
		log_level = LOG_DEBUG;
	if (mon_cfg.autoconnect) {
		ret = monitor_disable_udev_rules();
		if (ret < 0) {
			mon_cfg.autoconnect = false;
			log(LOG_WARNING, "autoconnect disabled\n");
			ret = 0;
		} else if (ret > 0) {
			mon_cfg.skip_udev_on_exit = true;
			ret = 0;
		}
	}

	if (cfg.persistent && !cfg.keep_alive_tmo)
		cfg.keep_alive_tmo = NVMF_DEF_DISC_TMO;

	return ret;
}

int aen_monitor(const char *desc, int argc, char **argv)
{
	int ret;
	struct udev_monitor *monitor;

	ret = monitor_parse_opts(desc, argc, argv);
	if (ret)
		goto out;
	ret = monitor_init_signals();
	if (ret != 0) {
		log(LOG_ERR, "monitor: failed to initialize signals: %m\n");
		goto out;
	}
	ret = create_udev_monitor(&monitor);
	if (ret == 0) {
		ret = monitor_main_loop(monitor);
		udev_monitor_unref(monitor);
	}
	udev = udev_unref(udev);
	if (mon_cfg.autoconnect && !mon_cfg.skip_udev_on_exit)
		monitor_enable_udev_rules();
out:
	return nvme_status_to_errno(ret, true);
}
