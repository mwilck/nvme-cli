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
#include <sys/epoll.h>

#include "common.h"
#include "nvme-status.h"
#include "nvme.h"
#include "util/argconfig.h"
#include "fabrics.h"
#include "monitor.h"
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

static int monitor_init_signals(void)
{
	sigset_t mask;
	struct sigaction sa = { .sa_handler = monitor_int_handler, };

	/*
	 * Block all signals. They will be unblocked when we wait
	 * for events.
	 */
	sigfillset(&mask);
	if (sigprocmask(SIG_BLOCK, &mask, NULL) == -1)
		return -errno;
	if (sigaction(SIGTERM, &sa, NULL) == -1)
		return -errno;
	if (sigaction(SIGINT, &sa, NULL) == -1)
		return -errno;
	return 0;
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

static int monitor_discovery(char *transport, char *traddr, char *trsvcid,
			     char *host_traddr)
{
	char argstr[BUF_SIZE];
	pid_t pid;
	int rc;

	pid = fork();
	if (pid == -1) {
		log(LOG_ERR, "failed to fork discovery task: %m");
		return -errno;
	} else if (pid > 0)
		return 0;

	log(LOG_NOTICE, "starting %s discovery for %s==>%s(%s)\n",
	    transport, host_traddr, traddr, trsvcid ? trsvcid : "none");
	cfg.nqn = NVME_DISC_SUBSYS_NAME;
	cfg.transport = transport;
	cfg.traddr = traddr;
	cfg.trsvcid = trsvcid;
	cfg.host_traddr = host_traddr;
	/* Without the following, the kernel returns EINVAL */
	cfg.tos = -1;

	rc = build_options(argstr, sizeof(argstr), true);
	log(LOG_DEBUG, "%s\n", argstr);
	rc = do_discover(argstr, mon_cfg.autoconnect);

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

	monitor_discovery("fc", traddr, NULL, host_traddr);
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
	while (1) {
		int rc, i;

		rc = epoll_pwait(ep_fd, events, MAX_EVENTS, -1, &ep_mask);
		if (rc == -1 && errno == EINTR) {
			log(LOG_NOTICE, "monitor: exit signal received\n");
			return 0;
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
