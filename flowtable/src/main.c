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

static bool same_devices(const struct ft_devices *installed, const struct ft_policy *p)
{
	int i;

	if (installed->n != p->ndevices)
		return false;
	for (i = 0; i < p->ndevices; i++)
		if (!ft_devices_has(installed, p->devices[i]))
			return false;
	return true;
}

/* Bring a healthy owned table's flowtable to the ports "devices auto" now
 * resolves to, in place. The policy is unchanged, so nothing is drained: the
 * devices that stay keep their bindings and their hardware flows, and the
 * adapter binds or unbinds only the devices named in the update. Verified as
 * strictly as a replacement. Returns 0, or -1 (ctx->err) for the caller to
 * fall back to the full transaction. */
static int follow_devices(struct ft_ctx *ctx, const struct ft_policy *p,
			  const struct ft_devices *installed, const char *hash, int lock)
{
	struct ft_devices now;
	struct ft_backend st;
	bool present, owned;
	char inhash[65], script[4096];
	int len = ft_render_membership(ctx, p, installed, script, sizeof(script));

	/* An empty update runs no nft; the verification below still decides. */
	if (len < 0 || (len && ft_nft_run(ctx, script, false, lock)) ||
	    ft_nft_inspect(ctx, &present, &owned, inhash, &now, lock) ||
	    ft_backend_read(ctx, &st))
		return -1;
	if (!(present && owned && !strcmp(inhash, hash) && same_devices(&now, p) &&
	      st.present && !st.observe &&
	      st.bindings == p->ndevices && !st.fatal && !st.invalidated && !st.quarantine)) {
		snprintf(ctx->err, sizeof(ctx->err), "updated devices did not acquire healthy backend bindings");
		return -1;
	}
	return 0;
}

/* Whether the daemon is holding a table whose ports fell below two, whether it
 * has an owned table whose devices it cannot read back, and whether another
 * flowtable is bound beside its own: each is logged once per episode rather
 * than on every check. */
static bool holding, unreadable, beside;

/* The apply transaction, mirroring the Python Runtime.apply(): drain the old
 * hardware before rebinding, never leave a foreign or half-applied table.
 * `multicast` is set when the policy asks for multicast acceleration on; the
 * caller switches it after the table, see apply_locked(). */
static int apply_table(struct ft_ctx *ctx, struct ft_policy *p, bool emit,
		       int lock, bool reconcile, bool *multicast)
{
	struct ft_backend st, drained;
	struct ft_devices installed;
	bool present, owned;
	char inhash[65], script[FT_RENDER_MAX + 1];
	char dj[512], bj[512], hash[65];
	int rc = -1, drain;
	memset(&drained, 0, sizeof(drained));

	if (ft_nft_inspect(ctx, &present, &owned, inhash, &installed, lock))
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
		if (!st.present || st.observe) {
			snprintf(ctx->err, sizeof(ctx->err), "an active flowtable provider is required");
			goto out;
		}
		if (st.fatal && st.fatal_terminal) {
			snprintf(ctx->err, sizeof(ctx->err), "hardware retirement failed; fresh boot required");
			goto out;
		}
		/* Left as it is: whatever the table needs once CDX has restarted
		 * the datapath, the next check sees it. */
		if (st.fatal) {
			snprintf(ctx->err, sizeof(ctx->err), "datapath restarting after an unproven deletion");
			rc = FT_RESTARTING;
			goto out;
		}
		*multicast = true;
		bool held = holding;

		holding = false;
		if (p->devices_auto)
			ft_enumerate(p);
		ft_policy_hash(p, hash);
		if (owned && installed.n < 0 && !unreadable) {
			fprintf(stderr, "ask-flowtable: cannot read the installed flowtable's devices; "
				"judging them by binding count\n");
			ft_log(LOG_WARNING, "cannot read the installed flowtable's devices; "
			       "judging them by binding count");
		}
		unreadable = owned && installed.n < 0;
		/* The adapter binds a second flowtable beside this one -- a
		 * consumer's own, or its offload probe mid-transaction -- and
		 * that shows only as more bindings than this table has devices.
		 * The other table is not ours to judge, and replacing ours would
		 * delete it and then wait on a drain the other one holds up:
		 * keep both as they are until it is gone. */
		if (owned && st.bindings > (installed.n >= 0 ? installed.n : p->ndevices)) {
			if (!beside) {
				fprintf(stderr, "ask-flowtable: another flowtable is bound beside this one; "
					"keeping both\n");
				ft_log(LOG_NOTICE, "another flowtable is bound beside this one; keeping both");
			}
			beside = true;
			if (reconcile)
				return 0;
			snprintf(ctx->err, sizeof(ctx->err),
				 "another flowtable is bound beside this one; not replacing it");
			goto out;
		}
		beside = false;
		if (reconcile && owned && !strcmp(inhash, hash) && !st.invalidated && !st.quarantine) {
			/* Only "devices auto" compares the listed devices with
			 * the policy's. An explicit list is covered by the hash,
			 * and nft lists a device named by an alternative name
			 * under its primary one, so comparing names would replace
			 * such a table on every check. A listing whose devices
			 * cannot be read back is judged by its binding count
			 * alone too: replacing the table on every check would be
			 * far worse than not following a port. */
			if (st.bindings == p->ndevices &&
			    (!p->devices_auto || installed.n < 0 || same_devices(&installed, p)))
				return 0;
			/* The same policy on other ports: follow them in place
			 * when the table is otherwise healthy. */
			if (p->devices_auto && installed.n >= 0 && st.bindings == installed.n) {
				/* Fewer than two up: keep the table as it stands.
				 * Two is the smallest set a policy may name, and
				 * following below it would leave a table no apply
				 * could have made. At zero the flowtable would
				 * lose its last binding, and the adapter refuses
				 * a first binding while the flowtable still holds
				 * flows, so the ports' return would force a full
				 * replacement. A port without carrier costs its
				 * binding nothing: nothing ingresses on it, and
				 * the adapter's link events have already retired
				 * the hardware flows through it. When the port
				 * returns the table is already right; when another
				 * one does, it is followed from here. */
				if (p->ndevices < 2) {
					if (!held) {
						fprintf(stderr, "ask-flowtable: fewer than two offload-capable "
							"ports are up; keeping the installed devices\n");
						ft_log(LOG_NOTICE, "fewer than two offload-capable ports are up; "
						       "keeping the installed devices");
					}
					holding = true;
					return 0;
				}
				if (!follow_devices(ctx, p, &installed, hash, lock)) {
					rc = 0;
					goto out;
				}
				fprintf(stderr, "ask-flowtable: device update failed: %s; replacing the table\n",
					ctx->err);
				ft_log(LOG_WARNING, "device update failed: %s; replacing the table", ctx->err);
			}
		}
		if (p->ndevices < 2) {
			snprintf(ctx->err, sizeof(ctx->err), "fewer than two offload-capable ports are up");
			goto out;
		}
		if (ft_render(ctx, p, st.qos_mark_mask, script, sizeof(script)) < 0)
			goto out;
	} else {
		/* Disabled is disabled for multicast as well: switched off
		 * first, so no group goes in while the rest drains, and drained
		 * with it below. Rewritten on every check, which is how a
		 * reloaded adapter, on again by default, is caught. */
		if (ft_backend_multicast(ctx, false))
			goto out;
		if (reconcile && !present &&
		    (!st.present || (!st.bindings && !st.entries && !st.handle_refs &&
				     !st.neighbour_refs && !st.quarantine && !st.fatal &&
				     !st.mcast_installed && !st.mroute_installed)))
			return 0;
	}

	/* Remove our previous table and let the hardware drain before rebinding;
	 * a disabled policy drains multicast too. */
	if (present && owned && ft_nft_delete(ctx, lock))
		goto out;
	drain = ft_backend_drain(ctx, 15000, !p->enabled);
	if (drain) {
		rc = drain;
		goto out;
	}
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
	drain = ft_backend_drain(ctx, 15000, false);
	if (drain) {
		rc = drain;
		goto out;
	}
	if (ft_nft_run(ctx, script, false, lock))
		goto out;

	/* Verify healthy bindings; roll back on any doubt. */
	if (ft_nft_inspect(ctx, &present, &owned, inhash, NULL, lock) || ft_backend_read(ctx, &st))
		goto rollback;
	ft_policy_hash(p, hash);
	if (!(present && owned && !strcmp(inhash, hash) &&
	      st.present && !st.observe &&
	      st.bindings == p->ndevices && !st.fatal && !st.invalidated && !st.quarantine)) {
		snprintf(ctx->err, sizeof(ctx->err), "new policy did not acquire healthy backend bindings");
		goto rollback;
	}
	/* Here rather than in the caller, so the result reports it. */
	*multicast = false;
	if (ft_backend_multicast(ctx, true) || (emit && ft_backend_read(ctx, &st)))
		goto out;
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
		if (ft_nft_delete(&tmp, lock) == 0 && ft_backend_drain(&tmp, 15000, false) == 0) {
			snprintf(ctx->err, sizeof(ctx->err), "apply failed, flowtable acceleration disabled: %.200s", why);
		} else {
			/* Left dirty: say so, mirroring the Python's compound error. */
			snprintf(ctx->err, sizeof(ctx->err),
				 "apply failed: %.110s; cleanup needs attention: %.90s", why, tmp.err);
		}
	}
out:
	return reconcile && !rc ? 1 : rc;
}

/* An enabled policy switches multicast acceleration on, whatever became of the
 * table: multicast follows no flowtable, and only a stop or a disabled policy
 * switches it off. After the table, though, never before it: installing the
 * table is a ruleset commit, which takes back every routed group's
 * confirmations, so groups carried ahead of it would go into hardware only to
 * come straight back out. */
static int apply_locked(struct ft_ctx *ctx, struct ft_policy *p, bool emit,
			int lock, bool reconcile)
{
	bool multicast = false;
	int rc = apply_table(ctx, p, emit, lock, reconcile, &multicast);

	if (multicast) {
		struct ft_ctx tmp;

		if (ft_backend_multicast(&tmp, true) && rc >= 0) {
			snprintf(ctx->err, sizeof(ctx->err), "%s", tmp.err);
			rc = -1;
		}
	}
	return rc;
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
	if (ft_nft_inspect(ctx, &present, &owned, inhash, NULL, lock))
		goto out;
	if (ft_backend_read(ctx, &st))
		goto out;
	if (!owned && st.present && st.bindings > 0) {
		snprintf(ctx->err, sizeof(ctx->err), "another flowtable owns the backend bindings");
		goto out;
	}
	/* Stop is global: multicast acceleration goes off before the table
	 * goes, and a successful stop has drained both learners' groups. */
	if (ft_backend_multicast(ctx, false))
		goto out;
	if (present && owned && ft_nft_delete(ctx, lock))
		goto out;
	if (ft_backend_drain(ctx, 15000, true))
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
	struct ft_devices installed;
	bool present, owned, paused;
	char inhash[65], devices[FT_MAX_DEVICES * (FT_IFNAME_MAX + 4) + 8];
	size_t o;
	int i, lock = ft_lock(ctx, 30000);
	if (lock < 0)
		return -1;
	if (paused_read(ctx, &paused) ||
	    ft_nft_inspect(ctx, &present, &owned, inhash, &installed, lock) ||
	    ft_backend_read(ctx, &st)) {
		close(lock);
		return -1;
	}
	close(lock);
	/* The ports the installed flowtable is bound to. Under "devices auto"
	 * the policy hash no longer says, so status does. */
	o = (size_t)snprintf(devices, sizeof(devices), "%s", installed.n < 0 ? "null" : "[");
	for (i = 0; i < installed.n; i++)
		o += (size_t)snprintf(devices + o, sizeof(devices) - o, "%s\"%s\"",
				      i ? ", " : "", installed.name[i]);
	if (installed.n >= 0)
		snprintf(devices + o, sizeof(devices) - o, "]");
	bool ready = owned && st.present &&
		     st.bindings > 0 && !st.fatal && !st.invalidated && !st.observe && !st.quarantine;
	printf("{\"policy_installed\": %s, \"policy_hash\": %s%s%s, \"devices\": %s, "
	       "\"reconciliation_paused\": %s, "
	       "\"admission_ready\": %s, \"backend\": {\"present\": %s, "
	       "\"bindings\": %ld, \"entries\": %ld, \"handle_refs\": %ld, \"neighbour_refs\": %ld, "
	       "\"quarantine\": %ld, \"fatal\": %ld, \"fatal_terminal\": %ld, \"restarts\": %ld, "
	       "\"resume_failures\": %ld, \"invalidated\": %ld, \"observe\": %ld, "
	       "\"mcast_enabled\": %ld, \"mcast_installed\": %ld, \"mroute_installed\": %ld}}\n",
	       owned ? "true" : "false",
	       owned ? "\"" : "null", owned ? inhash : "", owned ? "\"" : "",
	       devices,
	       paused ? "true" : "false",
	       ready ? "true" : "false",
	       st.present ? "true" : "false",
	       st.bindings, st.entries, st.handle_refs, st.neighbour_refs, st.quarantine,
	       st.fatal, st.fatal_terminal, st.restarts, st.resume_failures,
	       st.invalidated, st.observe,
	       st.mcast_enabled, st.mcast_installed, st.mroute_installed);
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
	int nl;
	int retry_ms = FT_RETRY_MIN_MS;
	int64_t due = 0;
	bool failed = false, restarting = false;

	if (!ft_cdx_present()) {
		fprintf(stderr, "ask-flowtable: cdx not loaded; idle\n");
		ft_log(LOG_NOTICE, "cdx not loaded; idle");
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
			if (rc == FT_RESTARTING) {
				/* Over in a second or two, so retried at the
				 * shortest interval rather than backed off, and
				 * said once per restart. */
				if (!restarting) {
					fprintf(stderr, "ask-flowtable: reconciliation deferred: %s\n", ctx.err);
					ft_log(LOG_NOTICE, "reconciliation deferred: %s", ctx.err);
				}
				due = now_ms() + FT_RETRY_MIN_MS;
			} else if (failed) {
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
			restarting = rc == FT_RESTARTING;
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
		char buf[FT_RENDER_MAX + 1];
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
