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
#include <unistd.h>
#include <errno.h>
#include <libudev.h>
#include <signal.h>
#include <sys/epoll.h>

#include "nvme-status.h"
#include "monitor.h"

static struct udev *udev;

static void close_ptr(int *p)
{
	if (*p != -1) {
		close(*p);
		*p = -1;
	}
}

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

static void monitor_handle_udevice(struct udev_device *ud)
{
	fprintf(stderr, "uevent: %s %s\n",
		udev_device_get_action(ud),
		udev_device_get_sysname(ud));
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
			fprintf(stderr, "monitor: exit signal received\n");
			return 0;
		} else if (rc == -1) {
			fprintf(stderr, "monitor: epoll_wait: %m\n");
			return -errno;
		} else if (rc == 0 || rc > MAX_EVENTS) {
			fprintf(stderr, "monitor: epoll_wait: unexpected rc=%d\n", rc);
			continue;
		}
		for (i = 0; i < MAX_EVENTS; i++) {
			if (events[i].data.ptr == monitor)
				(void)monitor_handle_uevents(monitor);
			else
				fprintf(stderr, "monitor: unexpected event\n");
		}
	}
	return ret;
}

int aen_monitor(const char *desc, int argc, char **argv)
{
	int ret;
	struct udev_monitor *monitor;

	ret = monitor_init_signals();
	if (ret != 0) {
		fprintf(stderr, "monitor: failed to initialize signals: %m\n");
		goto out;
	}
	ret = create_udev_monitor(&monitor);
	if (ret == 0) {
		ret = monitor_main_loop(monitor);
		udev_monitor_unref(monitor);
	}
	udev = udev_unref(udev);
out:
	return nvme_status_to_errno(ret, true);
}
