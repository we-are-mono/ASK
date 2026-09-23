/* Runtime side of the offload daemon: backend state, nft I/O, device
 * enumeration, netlink. SPDX-License-Identifier: GPL-2.0+ */
#ifndef ASK_FLOWTABLE_RUNTIME_H
#define ASK_FLOWTABLE_RUNTIME_H

#include "policy.h"
#include <stdbool.h>
#include <stdint.h>

#define FT_PROC        "/proc/cdx_flowtable"
#define FT_CDX_MODULE  "/sys/module/cdx"
#define FT_LOCK      "/run/lock/ask-flowtable.lock"
#define FT_PAUSED      "/run/lock/ask-flowtable.paused"
#define FT_DEFAULT_CONF "/etc/ask/offload.conf"
#define FT_DAEMON_LOCK  "/run/lock/ask-flowtable-daemon.lock"
#define FT_SERVICE_LOCK "/run/lock/ask-flowtable-service.lock"
#define FT_CONTROL_LOCK "/run/lock/ask-flowtable-control.lock"
#define FT_SERVICE_SOCKET "/run/ask-flowtable.sock"
#define FT_WORKER_PID "/var/run/ask-flowtable.pid"
#define FT_SUPERVISOR_PID "/var/run/ask-flowtable-supervisor.pid"

/* The header of /proc/cdx_flowtable. present=false means the adapter is not
 * loaded. The DRAIN_FIELDS must all be zero before a rebind. */
struct ft_backend {
	bool     present;
	long     bindings, entries, handle_refs, neighbour_refs, quarantine;
	long     fatal, observe, invalidated;
	long     installs, deletes, rearms, errors;   /* observability, for the CLI result */
	uint32_t qos_mark_mask;
};

/* Emit a backend state as a JSON object (no trailing newline) to a buffer. */
int ft_backend_json(const struct ft_backend *b, char *buf, size_t n);

/* Read the /proc header. Returns 0 (b filled, b->present per availability) or
 * -1 with ctx->err on a malformed/partial read. */
int ft_backend_read(struct ft_ctx *ctx, struct ft_backend *b);

/* Poll until the DRAIN_FIELDS are zero or the adapter is gone. 0 on drained,
 * -1 on timeout/fatal (ctx->err set). */
int ft_backend_drain(struct ft_ctx *ctx, int timeout_ms);

/* Resolve "devices auto" against the live interface set: up fsl_dpa ports,
 * sorted. Fills p->devices/ndevices, leaves devices_auto set for status.
 * Returns the count (>=0). */
int ft_enumerate(struct ft_policy *p);

/* Internal process boundary: bounded I/O, execution and lease lifetime. */
int ft_nft_exec(char *const argv[], const char *input, char *out, size_t outlen, int keepfd);

/* nft interactions (shell out to the shipped nft). All return 0/-1 (ctx->err). */
int ft_nft_run(struct ft_ctx *ctx, const char *script, bool check_only, int keepfd);
int ft_nft_delete(struct ft_ctx *ctx, int keepfd);  /* delete our table if present */
/* Inspect our table: present, whether it carries our marker (owned) vs a
 * foreign table of the same name, the marker hash and, when devices is not
 * NULL, the devices an owned table's flowtable is bound to. */
int ft_nft_inspect(struct ft_ctx *ctx, bool *present, bool *owned, char hash[65],
		   struct ft_devices *devices, int keepfd);

/* flock the single-flight lock for the duration of an operation. Returns an fd
 * (>=0) to close when done, or -1 (ctx->err). */
int ft_lock(struct ft_ctx *ctx, int timeout_ms);
int ft_path_lock(struct ft_ctx *ctx, const char *path, int timeout_ms);

/* Foreground supervisor and serialized init-service lifecycle commands. */
int ft_supervise(const char *conf, int readyfd);
int ft_service(struct ft_ctx *ctx, const char *verb, const char *conf);
void ft_log(int priority, const char *format, ...) __attribute__((format(printf, 2, 3)));

/* Whether CDX is loaded. Without it there is no ASK hardware to own and the
 * daemon idles. The adapter on top of it may come and go; the controller
 * retries until it is back rather than giving up. */
bool ft_cdx_present(void);

/* Load policy: parse the conf file, or, when absent, the built-in default
 * (enabled, devices auto, ALG excludes). Returns 0/-1 (ctx->err). */
int ft_load_policy(struct ft_ctx *ctx, const char *path, struct ft_policy *p);

/* Apply / stop, mirroring the retired Python CLI. When emit is set, print the
 * JSON result (enabled, policy_hash, drained{}, backend{}) to stdout, which the
 * test harness consumes. Return 0/-1. */
int ft_apply(struct ft_ctx *ctx, struct ft_policy *p, bool emit);
int ft_stop(struct ft_ctx *ctx, bool emit);

#endif
