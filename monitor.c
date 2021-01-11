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
#include <errno.h>
#include <libudev.h>

#include "nvme-status.h"
#include "monitor.h"

static struct udev *udev;

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

int aen_monitor(const char *desc, int argc, char **argv)
{
	int ret;
	struct udev_monitor *monitor;

	ret = create_udev_monitor(&monitor);
	if (ret == 0)
		udev_monitor_unref(monitor);
	udev = udev_unref(udev);
	return nvme_status_to_errno(ret, true);
}
