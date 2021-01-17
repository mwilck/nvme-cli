#ifndef _DISCOVER_H
#define _DISCOVER_H

#define NVMF_DEF_DISC_TMO	30

extern char *hostnqn_read(void);

extern int fabrics_discover(const char *desc, int argc, char **argv, bool connect);
extern int fabrics_connect(const char *desc, int argc, char **argv);
extern int fabrics_disconnect(const char *desc, int argc, char **argv);
extern int fabrics_disconnect_all(const char *desc, int argc, char **argv);

/* Symbols used by monitor.c */

const char *arg_str(const char * const *strings, size_t array_size, size_t idx);

struct fabrics_config {
	char *nqn;
	char *transport;
	char *traddr;
	char *trsvcid;
	char *host_traddr;
	char *hostnqn;
	char *hostid;
	int  nr_io_queues;
	int  nr_write_queues;
	int  nr_poll_queues;
	int  queue_size;
	int  keep_alive_tmo;
	int  reconnect_delay;
	int  ctrl_loss_tmo;
	int  tos;
	char *raw;
	char *device;
	int  duplicate_connect;
	int  disable_sqflow;
	int  hdr_digest;
	int  data_digest;
	bool persistent;
	bool matching_only;
};
extern struct fabrics_config fabrics_cfg;

#define BUF_SIZE 4096

int build_options(char *argstr, int max_len, bool discover);
int do_discover(char *argstr, bool connect);
int ctrl_instance(char *device);
char *parse_conn_arg(char *conargs, const char delim, const char *field);
int remove_ctrl(int instance);

#endif
