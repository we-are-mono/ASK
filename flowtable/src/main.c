/* ask-flowtable: default-on hardware flow-offload service.
 *
 * A Python-free replacement for tools/ask_flowtable.py. One-shot verbs
 * (apply|stop|status|check|render) preserve the retired tool's CLI so the test
 * harness is unchanged; `daemon` reconciles the configured policy and backend
 * health. Manual apply/stop retain control until an explicit `resume`.
 * SPDX-License-Identifier: GPL-2.0+
 */
#include "runtime.h"
#include "netlink.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <signal.h>
#include <poll.h>
#include <time.h>
#include <sys/stat.h>
#include <syslog.h>

#ifndef FT_HEALTH_MS
#define FT_HEALTH_MS 5000
#endif
#ifndef FT_RETRY_MIN_MS
#define FT_RETRY_MIN_MS 1000
#endif
#ifndef FT_RETRY_MAX_MS
#define FT_RETRY_MAX_MS 30000
#endif
#ifndef FT_DEBOUNCE_MS
#define FT_DEBOUNCE_MS 500
#endif

/* All accesses are serialized by FT_LOCK, including the daemon's decision
 * and its complete apply transaction. /run survives process restarts, not boot. */
static int paused_read(struct ft_ctx *ctx, bool *paused)
{
	struct stat st;
	if (lstat(FT_PAUSED, &st) == 0) {
		*paused = true;
		return 0;
	}
	if (errno == ENOENT) {
		*paused = false;
		return 0;
	}
	snprintf(ctx->err, sizeof(ctx->err), "cannot read reconciliation pause: %s", strerror(errno));
	return -1;
}

static int paused_set(struct ft_ctx *ctx, bool paused)
{
	if (!paused) {
		if (unlink(FT_PAUSED) == 0 || errno == ENOENT)
			return 0;
	} else {
		int fd = open(FT_PAUSED, O_WRONLY | O_CREAT | O_CLOEXEC | O_NOFOLLOW, 0600);
		if (fd >= 0) {
			close(fd);
			return 0;
		}
	}
	snprintf(ctx->err, sizeof(ctx->err), "cannot %s reconciliation pause: %s",
		 paused ? "set" : "clear", strerror(errno));
	return -1;
}

/* The built-in zero-config default, used when the conf file is absent: offload
 * every established TCP/UDP flow across the up CDX ports, minus the ALG control
 * channels whose helpers break if their control connection is accelerated. */
static const char DEFAULT_CONF[] =
	"enabled yes\n"
	"devices auto\n"
	"scope any\n"
	"exclude tcp 21\n"     /* FTP control */
	"exclude udp 5060\n"   /* SIP */
	"exclude tcp 1723\n";  /* PPTP control */

int ft_load_policy(struct ft_ctx *ctx, const char *path, struct ft_policy *p)
{
	char buf[FT_CONF_MAX + 1];
	int fd = open(path, O_RDONLY | O_CLOEXEC);
	if (fd < 0) {
		if (errno == ENOENT && !strcmp(path, FT_DEFAULT_CONF))
			return ft_conf_parse(ctx, DEFAULT_CONF, sizeof(DEFAULT_CONF) - 1, p);
		snprintf(ctx->err, sizeof(ctx->err), "cannot open %s: %s", path, strerror(errno));
		return -1;
	}
	ssize_t n = read(fd, buf, sizeof(buf));
	close(fd);
	if (n < 0) {
		snprintf(ctx->err, sizeof(ctx->err), "cannot read %s", path);
		return -1;
	}
	if ((size_t)n > FT_CONF_MAX) {
		snprintf(ctx->err, sizeof(ctx->err), "configuration exceeds 64 KiB");
		return -1;
	}
	return ft_conf_parse(ctx, buf, (size_t)n, p);
}

/* The apply transaction, mirroring the Python Runtime.apply(): drain the old
 * hardware before rebinding, never leave a foreign or half-applied table. */
static int apply_locked(struct ft_ctx *ctx, struct ft_policy *p, bool emit,
			int lock, bool reconcile)
{
	struct ft_backend st, drained;
	bool present, owned;
	char inhash[65], script[FT_CONF_MAX * 2];
	char dj[512], bj[512], hash[65];
	int rc = -1;
	memset(&drained, 0, sizeof(drained));

	if (ft_nft_inspect(ctx, &present, &owned, inhash, lock))
		goto out;
	if (present && !owned) {
		snprintf(ctx->err, sizeof(ctx->err),
			 "refusing to modify a table without this controller's ownership marker");
		goto out;
	}
	if (ft_backend_read(ctx, &st))
		goto out;
	if (!owned && st.present && st.bindings > 0) {
		snprintf(ctx->err, sizeof(ctx->err), "another flowtable owns the backend bindings");
		goto out;
	}

	if (p->enabled) {
		if (!st.present || strcmp(st.owner, "flowtable") || st.observe) {
			snprintf(ctx->err, sizeof(ctx->err), "an active flowtable provider is required");
			goto out;
		}
		if (st.fatal) {
			snprintf(ctx->err, sizeof(ctx->err), "hardware retirement failed; fresh boot required");
			goto out;
		}
		if (p->devices_auto)
			ft_enumerate(p);
		if (p->ndevices < 2) {
			snprintf(ctx->err, sizeof(ctx->err), "fewer than two offload-capable ports are up");
			goto out;
		}
		if (ft_render(ctx, p, st.qos_mark_mask, script, sizeof(script)) < 0)
			goto out;
		ft_policy_hash(p, hash);
		if (reconcile && owned && !strcmp(inhash, hash) &&
		    st.bindings == p->ndevices && !st.invalidated && !st.quarantine)
			return 0;
	} else if (reconcile && !present &&
		   (!st.present || (!st.bindings && !st.entries && !st.handle_refs &&
				   !st.neighbour_refs && !st.quarantine && !st.fatal))) {
		return 0;
	}

	/* Remove our previous table and let the hardware drain before rebinding. */
	if (present && owned && ft_nft_delete(ctx, lock))
		goto out;
	if (ft_backend_drain(ctx, 15000))
		goto out;
	if (ft_backend_read(ctx, &drained))  /* the post-remove state the CLI reports */
		goto out;

	if (!p->enabled) {
		rc = 0;
		if (emit) {
			ft_backend_json(&drained, dj, sizeof(dj));
			printf("{\"enabled\": false, \"drained\": %s}\n", dj);
		}
		goto out;   /* disabled: drained, nothing to install */
	}

	/* --check can invoke backend binding callbacks; only after the drain. */
	if (ft_nft_run(ctx, script, true, lock))
		goto out;
	if (ft_backend_drain(ctx, 15000))
		goto out;
	if (ft_nft_run(ctx, script, false, lock))
		goto out;

	/* Verify healthy bindings; roll back on any doubt. */
	if (ft_nft_inspect(ctx, &present, &owned, inhash, lock) || ft_backend_read(ctx, &st))
		goto rollback;
	ft_policy_hash(p, hash);
	if (!(present && owned && !strcmp(inhash, hash) &&
	      st.present && !strcmp(st.owner, "flowtable") && !st.observe &&
	      st.bindings == p->ndevices && !st.fatal && !st.invalidated && !st.quarantine)) {
		snprintf(ctx->err, sizeof(ctx->err), "new policy did not acquire healthy backend bindings");
		goto rollback;
	}
	rc = 0;
	if (emit) {
		ft_backend_json(&drained, dj, sizeof(dj));
		ft_backend_json(&st, bj, sizeof(bj));
		printf("{\"enabled\": true, \"policy_hash\": \"%s\", \"drained\": %s, \"backend\": %s}\n",
		       hash, dj, bj);
	}
	goto out;

rollback:
	{
		struct ft_ctx tmp;
		char why[sizeof(ctx->err)];
		snprintf(why, sizeof(why), "%s", ctx->err);
		if (ft_nft_delete(&tmp, lock) == 0 && ft_backend_drain(&tmp, 15000) == 0) {
			snprintf(ctx->err, sizeof(ctx->err), "apply failed, acceleration disabled: %.200s", why);
		} else {
			/* Left dirty: say so, mirroring the Python's compound error. */
			snprintf(ctx->err, sizeof(ctx->err),
				 "apply failed: %.110s; cleanup needs attention: %.90s", why, tmp.err);
		}
	}
out:
	return reconcile && !rc ? 1 : rc;
}

int ft_apply(struct ft_ctx *ctx, struct ft_policy *p, bool emit)
{
	int lock = ft_lock(ctx, 30000);
	if (lock < 0)
		return -1;
	/* A manual policy can be temporary or security-sensitive. The daemon must
	 * not replace it with its own configuration, even if this apply fails. */
	int rc = paused_set(ctx, true);
	if (!rc)
		rc = apply_locked(ctx, p, emit, lock, false);
	close(lock);
	return rc;
}

int ft_stop(struct ft_ctx *ctx, bool emit)
{
	struct ft_backend st, drained;
	bool present, owned;
	char inhash[65], dj[512];
	int lock, rc = -1;

	lock = ft_lock(ctx, 30000);
	if (lock < 0)
		return -1;
	if (paused_set(ctx, true))
		goto out;
	if (ft_nft_inspect(ctx, &present, &owned, inhash, lock))
		goto out;
	if (ft_backend_read(ctx, &st))
		goto out;
	if (!owned && st.present && st.bindings > 0) {
		snprintf(ctx->err, sizeof(ctx->err), "another flowtable owns the backend bindings");
		goto out;
	}
	if (present && owned && ft_nft_delete(ctx, lock))
		goto out;
	if (ft_backend_drain(ctx, 15000))
		goto out;
	if (emit && ft_backend_read(ctx, &drained))
		goto out;
	rc = 0;
	if (emit) {
		ft_backend_json(&drained, dj, sizeof(dj));
		printf("{\"enabled\": false, \"drained\": %s}\n", dj);
	}
out:
	close(lock);
	return rc;
}

static int cmd_status(struct ft_ctx *ctx)
{
	struct ft_backend st;
	bool present, owned, paused;
	char inhash[65];
	int lock = ft_lock(ctx, 30000);
	if (lock < 0)
		return -1;
	if (paused_read(ctx, &paused) || ft_nft_inspect(ctx, &present, &owned, inhash, lock) ||
	    ft_backend_read(ctx, &st)) {
		close(lock);
		return -1;
	}
	close(lock);
	bool ready = owned && st.present && !strcmp(st.owner, "flowtable") &&
		     st.bindings > 0 && !st.fatal && !st.invalidated && !st.observe && !st.quarantine;
	printf("{\"policy_installed\": %s, \"policy_hash\": %s%s%s, "
	       "\"reconciliation_paused\": %s, "
	       "\"admission_ready\": %s, \"backend\": {\"present\": %s, \"owner\": \"%s\", "
	       "\"bindings\": %ld, \"entries\": %ld, \"handle_refs\": %ld, \"neighbour_refs\": %ld, "
	       "\"quarantine\": %ld, \"fatal\": %ld, \"invalidated\": %ld, \"observe\": %ld}}\n",
	       owned ? "true" : "false",
	       owned ? "\"" : "null", owned ? inhash : "", owned ? "\"" : "",
	       paused ? "true" : "false",
	       ready ? "true" : "false",
	       st.present ? "true" : "false", st.owner,
	       st.bindings, st.entries, st.handle_refs, st.neighbour_refs, st.quarantine,
	       st.fatal, st.invalidated, st.observe);
	return 0;
}

static volatile sig_atomic_t stop_flag;
static void on_signal(int s) { (void)s; stop_flag = 1; }

/* Decide and repair under the same lease as manual control. A paused daemon
 * neither interprets its policy nor touches the manually controlled backend. */
static int reconcile(struct ft_ctx *ctx, const char *conf)
{
	struct ft_policy p;
	bool paused;
	/* Allow short status readers to finish without turning routine polling
	 * into repeated recovery backoff. Long manual operations remain bounded. */
	int rc = -1, lock = ft_lock(ctx, 1000);
	if (lock < 0)
		return -1;
	if (paused_read(ctx, &paused))
		goto out;
	if (paused) {
		rc = 0;
		goto out;
	}
	if (ft_load_policy(ctx, conf, &p))
		goto out;
	rc = apply_locked(ctx, &p, false, lock, true);
out:
	close(lock);
	return rc;
}

static int cmd_resume(struct ft_ctx *ctx)
{
	int lock = ft_lock(ctx, 30000);
	if (lock < 0)
		return -1;
	int rc = paused_set(ctx, false);
	close(lock);
	if (!rc)
		puts("{\"reconciliation_paused\": false}");
	return rc;
}

static int64_t now_ms(void)
{
	struct timespec ts;
	clock_gettime(CLOCK_MONOTONIC, &ts);
	return (int64_t)ts.tv_sec * 1000 + ts.tv_nsec / 1000000;
}

static int cmd_daemon(const char *conf)
{
	struct ft_ctx ctx = {0};
	char owner[16];
	int nl;
	int retry_ms = FT_RETRY_MIN_MS;
	int64_t due = 0;
	bool failed = false;

	ft_offload_owner(owner);
	if (strcmp(owner, "flowtable")) {
		fprintf(stderr, "ask-flowtable: offload owner is '%s', not flowtable; idle\n",
			owner[0] ? owner : "none");
		ft_log(LOG_NOTICE, "offload owner is '%s', not flowtable; idle", owner[0] ? owner : "none");
		return 0;   /* nothing to own; let the init system consider us done */
	}
	int instance = ft_path_lock(&ctx, FT_DAEMON_LOCK, 0);
	if (instance < 0) {
		fprintf(stderr, "ask-flowtable: another daemon is still running: %s\n", ctx.err);
		ft_log(LOG_WARNING, "another daemon is still running: %s", ctx.err);
		return 1;
	}

	signal(SIGTERM, on_signal);
	signal(SIGINT, on_signal);
	signal(SIGPIPE, SIG_IGN);

	nl = ft_nl_open();
	while (!stop_flag) {
		if (now_ms() >= due) {
			int rc = reconcile(&ctx, conf);
			failed = rc < 0;
			if (failed) {
				fprintf(stderr, "ask-flowtable: reconciliation deferred: %s; retry in %d ms\n",
					ctx.err, retry_ms);
				ft_log(LOG_WARNING, "reconciliation deferred: %s; retry in %d ms", ctx.err, retry_ms);
				due = now_ms() + retry_ms;
				if (retry_ms < FT_RETRY_MAX_MS)
					retry_ms = retry_ms > FT_RETRY_MAX_MS / 2 ? FT_RETRY_MAX_MS : retry_ms * 2;
			} else {
				if (rc > 0) {
					fprintf(stderr, "ask-flowtable: reconciled policy and backend\n");
					ft_log(LOG_NOTICE, "reconciled policy and backend");
				}
				retry_ms = FT_RETRY_MIN_MS;
				due = now_ms() + FT_HEALTH_MS;
			}
			if (nl < 0)
				nl = ft_nl_open();   /* timers still work while event delivery is unavailable */
		}
		if (stop_flag)
			break;
		int64_t wait = due - now_ms();
		struct pollfd pfd = { nl, POLLIN, 0 };
		int r = poll(&pfd, 1, wait > 0 ? (int)wait : 0);
		if (r < 0) {
			if (errno == EINTR)
				continue;
			break;
		}
		if (pfd.revents & (POLLIN | POLLERR)) {
			ft_nl_drain(nl);
			int64_t event_due = now_ms() + FT_DEBOUNCE_MS;
			/* Events can advance a healthy check, never postpone a deadline
			 * or defeat failure backoff. A storm cannot starve recovery. */
			if (!failed && event_due < due)
				due = event_due;
		}
		if (pfd.revents & (POLLHUP | POLLNVAL)) {
			close(nl);
			nl = -1;
		}
	}
	close(nl);
	close(instance);
	return 0;
}

static int usage(void)
{
	fprintf(stderr, "usage: ask-flowtable {apply|stop|resume|status|check|render|daemon|supervise|service-start|service-stop|service-restart|service-status} [--config PATH]\n");
	return 2;
}

int main(int argc, char **argv)
{
	const char *conf = FT_DEFAULT_CONF;
	const char *cmd = NULL;
	bool explicit_conf = false;
	int i;

	for (i = 1; i < argc; i++) {
		if (!strcmp(argv[i], "--config") && i + 1 < argc) {
			conf = argv[++i];
			explicit_conf = true;
		} else if (!cmd)
			cmd = argv[i];
		else
			return usage();
	}
	if (!cmd)
		return usage();
	if (!strcmp(cmd, "resume") && explicit_conf)
		return usage();   /* resume selects the running daemon's policy, not a candidate */

	struct ft_ctx ctx;
	memset(&ctx, 0, sizeof(ctx));

	/* nft can exit before we finish feeding its stdin (missing binary, early
	 * parse error): take a clean error from run(), not SIGPIPE death. */
	signal(SIGPIPE, SIG_IGN);

	if (!strcmp(cmd, "daemon"))
		return cmd_daemon(conf);
	if (!strcmp(cmd, "supervise"))
		return ft_supervise(conf, -1);
	if (!strncmp(cmd, "service-", 8))
		return ft_service(&ctx, cmd + 8, conf) ? (fprintf(stderr, "ask-flowtable: %s\n", ctx.err), 1) : 0;
	if (!strcmp(cmd, "status"))
		return cmd_status(&ctx) ? (fprintf(stderr, "ask-flowtable: %s\n", ctx.err), 1) : 0;
	if (!strcmp(cmd, "stop"))
		return ft_stop(&ctx, true) ? (fprintf(stderr, "ask-flowtable: %s\n", ctx.err), 1) : 0;
	if (!strcmp(cmd, "resume"))
		return cmd_resume(&ctx) ? (fprintf(stderr, "ask-flowtable: %s\n", ctx.err), 1) : 0;

	struct ft_policy p;
	if (ft_load_policy(&ctx, conf, &p)) {
		fprintf(stderr, "ask-flowtable: %s\n", ctx.err);
		return 1;
	}

	if (!strcmp(cmd, "check")) {
		char h[65]; ft_policy_hash(&p, h);
		printf("{\"valid\": true, \"policy_hash\": \"%s\"}\n", h);
		return 0;
	}
	if (!strcmp(cmd, "render")) {
		struct ft_backend st;
		char buf[FT_CONF_MAX * 2];
		uint32_t mask = 0;
		if (ft_backend_read(&ctx, &st) == 0 && st.present)
			mask = st.qos_mark_mask;
		if (p.enabled && p.devices_auto)
			ft_enumerate(&p);
		if (ft_render(&ctx, &p, mask, buf, sizeof(buf)) < 0) {
			fprintf(stderr, "ask-flowtable: %s\n", ctx.err);
			return 1;
		}
		fputs(buf, stdout);
		return 0;
	}
	if (!strcmp(cmd, "apply")) {
		if (ft_apply(&ctx, &p, true)) {
			fprintf(stderr, "ask-flowtable: %s\n", ctx.err);
			return 1;
		}
		return 0;
	}
	return usage();
}
