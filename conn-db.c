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
 * This file implements a simple registry for NVMe connections, i.e.
 * (transport type, host_traddr, traddr, trsvcid) tuples.
 */

#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <syslog.h>
#include <time.h>

#include "common.h"
#include "util/cleanup.h"
#include "list.h"
#include "nvme.h"
#include "fabrics.h"
#include "conn-db.h"

#define LOG_FUNCNAME 1
#include "util/log.h"

struct conn_int {
	struct nvme_connection c;
	struct list_head lst;
};

#define conn2internal(co) container_of(co, struct conn_int, c)

static LIST_HEAD(connections);

static const char * const _status_str[] = {
	[CS_NEW] = "new",
	[CS_DISC_RUNNING] = "discovery-running",
	[CS_ONLINE] = "online",
	[CS_FAILED] = "failed",
};

const char *conn_status_str(int status)
{
	return arg_str(_status_str, ARRAY_SIZE(_status_str), status);
}

#define _log_conn(lvl, mesg, transport, traddr, trsvcid, host_traddr)	\
	do {								\
		const char *__trs = trsvcid;				\
									\
		msg(lvl, "%s <%s>: %s ==> %s(%s)\n",			\
		    mesg, transport, host_traddr, traddr,		\
		    __trs && *__trs ? __trs : "none");			\
	} while (0)

#define log_conn(lvl, mesg, conn)					\
	_log_conn(lvl, mesg, (conn)->c.transport,			\
		  (conn)->c.traddr, (conn)->c.trsvcid,			\
		  (conn)->c.host_traddr)

static void conn_free(struct conn_int *ci)
{
	if (!ci)
		return;
	if (ci->c.traddr)
		free(ci->c.traddr);
	if (ci->c.trsvcid)
		free(ci->c.trsvcid);
	if (ci->c.host_traddr)
		free(ci->c.host_traddr);
	free(ci);
}

static int conn_del(struct conn_int *ci)
{
	if (!ci)
		return -ENOENT;
	if (list_empty(&ci->lst))
		return -EINVAL;
	log_conn(LOG_INFO, "forgetting connection", ci);
	list_del(&ci->lst);
	conn_free(ci);
	return 0;
}

bool conndb_matches(const char *transport, const char *traddr,
		    const char *trsvcid, const char *host_traddr,
		    const struct nvme_connection *co)
{
	if (!co)
		return false;
	if (!transport || strcmp(transport, co->transport))
		return false;
	if (!traddr || strncmp(traddr, co->traddr, NVMF_TRADDR_SIZE))
		return false;
	if ((!trsvcid && co->trsvcid) ||
	    (trsvcid && *trsvcid && (!co->trsvcid ||
			 strncmp(trsvcid, co->trsvcid, NVMF_TRSVCID_SIZE))))
		return false;
	if (!host_traddr || (strncmp(host_traddr, co->host_traddr,
				     NVMF_TRADDR_SIZE)))
		return false;
	return true;
}

static struct conn_int *conn_find(const char *transport, const char *traddr,
				  const char *trsvcid, const char *host_traddr)
{
	struct conn_int *ci;

	if (!transport || !traddr || !host_traddr)
		return NULL;
	list_for_each_entry(ci, &connections, lst) {
		if (conndb_matches(transport, traddr, trsvcid, host_traddr, &ci->c))
			return ci;
	}
	return NULL;
}

static bool is_supported_transport(const char *transport)
{

	return !strcmp(transport, "fc") || !strcmp(transport, "rdma") ||
	       !strcmp(transport, "tcp") || !strcmp(transport, "loop");
}

static DEFINE_CLEANUP_FUNC(conn_free_p, struct conn_int *, conn_free);

static int _conn_add(const char *transport, const char *traddr,
		     const char *trsvcid, const char *host_traddr,
		     struct conn_int **new_ci)
{
	struct conn_int *ci __cleanup__(conn_free_p) = NULL;

	if (!transport || !is_supported_transport(transport) || !traddr)
		return -EINVAL;

	if (!(ci = calloc(1, sizeof(*ci))) ||
	    !(ci->c.traddr = strndup(traddr, NVMF_TRADDR_SIZE)) ||
	    !(ci->c.host_traddr = strndup(host_traddr, NVMF_TRADDR_SIZE)) ||
	    (trsvcid && *trsvcid &&
	     !(ci->c.trsvcid = strndup(trsvcid, NVMF_TRSVCID_SIZE))))
		return -ENOMEM;
	memccpy(ci->c.transport, transport, '\0', sizeof(ci->c.transport));
	ci->c.status = CS_NEW;
	ci->c.discovery_instance = -1;
	list_add(&ci->lst, &connections);
	*new_ci = ci;
	ci = NULL;
	return 0;
}

static int conn_add(const char *transport, const char *traddr,
		    const char *trsvcid, const char *host_traddr,
		    struct conn_int **new_ci)
{
	struct conn_int *ci = conn_find(transport, traddr, trsvcid, host_traddr);
	int rc;

	if (ci) {
		*new_ci = ci;
		return -EEXIST;
	}
	rc = _conn_add(transport, traddr, trsvcid, host_traddr, new_ci);
	if (!rc)
		log_conn(LOG_DEBUG, "added connection", *new_ci);
	else
		_log_conn(LOG_ERR, "failed to add", transport, traddr,
			  trsvcid, host_traddr);
	return rc;
}

int conndb_add(const char *transport, const char *traddr,
	       const char *trsvcid, const char *host_traddr,
	       struct nvme_connection **new_conn)
{
	struct conn_int *ci = NULL;
	int rc = conn_add(transport, traddr, trsvcid, host_traddr, &ci);

	if (rc != 0 && rc != -EEXIST)
		return rc;
	if (new_conn)
		*new_conn = &ci->c;
	return rc;
}

struct nvme_connection *conndb_find(const char *transport, const char *traddr,
				    const char *trsvcid, const char *host_traddr)
{
	struct conn_int *ci;

	ci = conn_find(transport, traddr, trsvcid, host_traddr);
	if (ci)
		return &ci->c;
	else
		return NULL;
}

struct nvme_connection *conndb_find_by_pid(pid_t pid)
{
	struct conn_int *ci;

	list_for_each_entry(ci, &connections, lst) {
		if (ci->c.status == CS_DISC_RUNNING &&
		    ci->c.discovery_task == pid)
			return &ci->c;
	}
	return NULL;
}

struct nvme_connection *conndb_find_by_ctrl(const char *devname)
{
	struct conn_int *ci;
	int instance;

	instance = ctrl_instance(devname);
	if (!instance)
		return NULL;

	list_for_each_entry(ci, &connections, lst) {
		if (ci->c.discovery_instance == instance)
			return &ci->c;
	}
	return NULL;
}

int conndb_delete(struct nvme_connection *co)
{
	if (!co)
		return -ENOENT;
	return conn_del(conn2internal(co));
}

void conndb_free(void)
{
	struct conn_int *ci, *next;

	list_for_each_entry_safe(ci, next, &connections, lst)
		conn_del(ci);
}

int conndb_init_from_sysfs(void)
{
	struct dirent **devices;
	int i, n, ret = 0;
	char syspath[PATH_MAX];

	n = scandir(SYS_NVME, &devices, scan_ctrls_filter, alphasort);
	if (n <= 0)
		return n;

	for (i = 0; i < n; i++) {
		int len, rc;
		struct conn_int *ci;
		char *transport __cleanup__(cleanup_charp) = NULL;
		char *address __cleanup__(cleanup_charp) = NULL;
		char *traddr __cleanup__(cleanup_charp) = NULL;
		char *trsvcid __cleanup__(cleanup_charp) = NULL;
		char *host_traddr __cleanup__(cleanup_charp) = NULL;
		char *subsysnqn __cleanup__(cleanup_charp) = NULL;

		len = snprintf(syspath, sizeof(syspath), SYS_NVME "/%s",
			       devices[i]->d_name);
		if (len < 0 || len >= sizeof(syspath))
			continue;

		transport = nvme_get_ctrl_attr(syspath, "transport");
		address = nvme_get_ctrl_attr(syspath, "address");
		if (!transport || !address)
			continue;
		traddr = parse_conn_arg(address, ' ', "traddr");
		trsvcid = parse_conn_arg(address, ' ', "trsvcid");
		host_traddr = parse_conn_arg(address, ' ', "host_traddr");

		rc = conn_add(transport, traddr, trsvcid, host_traddr, &ci);
		if (rc != 0 && rc != -EEXIST)
			continue;

		if (rc == 0)
			ret ++;
		subsysnqn = nvme_get_ctrl_attr(syspath, "subsysnqn");
		if (subsysnqn && !strcmp(subsysnqn, NVME_DISC_SUBSYS_NAME)) {
			int instance = ctrl_instance(devices[i]->d_name);

			if (instance >= 0) {
				ci->c.discovery_instance = instance;
				msg(LOG_DEBUG, "found discovery controller %s\n",
				    devices[i]->d_name);
			}
		}
		free(devices[i]);
	}
	free(devices);
	return ret;
}

int conndb_for_each(int (*callback)(struct nvme_connection *co, void *arg),
		    void *arg)
{
	struct conn_int *ci, *next;
	int ret = 0;

	list_for_each_entry_safe(ci, next, &connections, lst) {
		int rc = callback(&ci->c, arg);

		if (rc & ~(CD_CB_ERR|CD_CB_DEL|CD_CB_BREAK)) {
			msg(LOG_ERR,
			    "invalid return value 0x%x from callback\n", rc);
			ret = -EINVAL;
			continue;
		}
		if (rc & CD_CB_ERR) {
			msg(LOG_WARNING, "callback returned error\n");
			if (!ret)
				ret = errno ? -errno : -EIO;
		}
		if (rc & CD_CB_DEL)
			conn_del(ci);
		if (rc & CD_CB_BREAK)
			break;
	}
	return ret;
}
