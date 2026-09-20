/* ask-flowtable: default-on hardware flow-offload service.
 *
 * A Python-free replacement for tools/ask_flowtable.py. One-shot verbs
 * (apply|stop|status|check|render) preserve the retired tool's CLI so the test
 * harness is unchanged; `daemon` adds the default-on behaviour — apply at boot
 * and re-apply when interfaces or Wi-Fi VAPs change.
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
		if (errno == ENOENT)
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
int ft_apply(struct ft_ctx *ctx, struct ft_policy *p, bool emit)
{
	struct ft_backend st, drained;
	bool present, owned;
	char inhash[65], script[FT_CONF_MAX * 2];
	char dj[512], bj[512], hash[65];
	int lock, rc = -1;
	memset(&drained, 0, sizeof(drained));

	lock = ft_lock(ctx, 30000);
	if (lock < 0)
		return -1;

	if (ft_nft_inspect(ctx, &present, &owned, inhash))
		goto out;
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
	}

	/* Remove our previous table and let the hardware drain before rebinding. */
	if (present && owned && ft_nft_delete(ctx, lock))
		goto out;
	if (ft_backend_drain(ctx, 15000))
		goto out;
	ft_backend_read(ctx, &drained);   /* the post-remove state the CLI reports */

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
	if (ft_nft_inspect(ctx, &present, &owned, inhash) || ft_backend_read(ctx, &st))
		goto rollback;
	ft_policy_hash(p, hash);
	if (!(present && owned && !strcmp(inhash, hash) &&
	      st.present && st.bindings == p->ndevices && !st.fatal && !st.invalidated)) {
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
		if (ft_nft_delete(&tmp, lock) == 0) {
			ft_backend_drain(&tmp, 15000);
			snprintf(ctx->err, sizeof(ctx->err), "apply failed, acceleration disabled: %.200s", why);
		} else {
			/* Left dirty: say so, mirroring the Python's compound error. */
			snprintf(ctx->err, sizeof(ctx->err),
				 "apply failed: %.110s; cleanup needs attention: %.90s", why, tmp.err);
		}
	}
out:
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
	if (ft_nft_inspect(ctx, &present, &owned, inhash))
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
	rc = 0;
	if (emit) {
		ft_backend_read(ctx, &drained);
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
	bool present, owned;
	char inhash[65];
	int lock = ft_lock(ctx, 30000);
	if (lock < 0)
		return -1;
	if (ft_nft_inspect(ctx, &present, &owned, inhash) || ft_backend_read(ctx, &st)) {
		close(lock);
		return -1;
	}
	close(lock);
	bool ready = owned && st.present && st.bindings > 0 && !st.fatal && !st.invalidated && !st.observe;
	printf("{\"policy_installed\": %s, \"policy_hash\": %s%s%s, "
	       "\"admission_ready\": %s, \"backend\": {\"present\": %s, \"owner\": \"%s\", "
	       "\"bindings\": %ld, \"entries\": %ld, \"handle_refs\": %ld, \"neighbour_refs\": %ld, "
	       "\"quarantine\": %ld, \"fatal\": %ld, \"invalidated\": %ld, \"observe\": %ld}}\n",
	       owned ? "true" : "false",
	       owned ? "\"" : "null", owned ? inhash : "", owned ? "\"" : "",
	       ready ? "true" : "false",
	       st.present ? "true" : "false", st.owner,
	       st.bindings, st.entries, st.handle_refs, st.neighbour_refs, st.quarantine,
	       st.fatal, st.invalidated, st.observe);
	return 0;
}

static volatile sig_atomic_t stop_flag;
static void on_signal(int s) { (void)s; stop_flag = 1; }

/* Resolve + render the current policy and return its hash, or "" if it cannot
 * be applied right now (e.g. fewer than two ports up). */
static void resolve_hash(const char *conf, char out[65])
{
	struct ft_ctx ctx;
	struct ft_policy p;
	out[0] = '\0';
	if (ft_load_policy(&ctx, conf, &p))
		return;
	if (p.enabled && p.devices_auto)
		ft_enumerate(&p);
	if (p.enabled && p.ndevices < 2)
		return;
	ft_policy_hash(&p, out);
}

static int cmd_daemon(const char *conf)
{
	struct ft_ctx ctx;
	char owner[16];
	int nl;
	char applied[65] = "";

	ft_offload_owner(owner);
	if (strcmp(owner, "flowtable")) {
		fprintf(stderr, "ask-flowtable: offload owner is '%s', not flowtable; idle\n",
			owner[0] ? owner : "none");
		return 0;   /* nothing to own; let the init system consider us done */
	}

	signal(SIGTERM, on_signal);
	signal(SIGINT, on_signal);
	signal(SIGPIPE, SIG_IGN);

	nl = ft_nl_open();
	if (nl < 0) {
		fprintf(stderr, "ask-flowtable: netlink open failed: %s\n", strerror(errno));
		return 1;
	}

	/* Boot apply (tolerate "not enough ports yet"; a netlink event will retry). */
	{
		struct ft_policy p;
		if (!ft_load_policy(&ctx, conf, &p)) {
			if (ft_apply(&ctx, &p, false) == 0)
				ft_policy_hash(&p, applied);
			else
				fprintf(stderr, "ask-flowtable: initial apply deferred: %s\n", ctx.err);
		} else {
			fprintf(stderr, "ask-flowtable: %s\n", ctx.err);
		}
	}

	while (!stop_flag) {
		struct pollfd pfd = { nl, POLLIN, 0 };
		int r = poll(&pfd, 1, -1);
		if (r < 0) {
			if (errno == EINTR)
				continue;
			break;
		}
		if (!(pfd.revents & POLLIN))
			continue;
		ft_nl_drain(nl);
		/* Debounce: absorb a burst of link/addr churn before acting. */
		for (;;) {
			struct pollfd d = { nl, POLLIN, 0 };
			if (poll(&d, 1, 500) > 0 && (d.revents & POLLIN))
				ft_nl_drain(nl);
			else
				break;
		}
		char want[65];
		resolve_hash(conf, want);
		if (!strcmp(want, applied))
			continue;   /* nothing material changed */
		struct ft_policy p;
		if (ft_load_policy(&ctx, conf, &p)) {
			fprintf(stderr, "ask-flowtable: reload failed: %s\n", ctx.err);
			continue;
		}
		if (ft_apply(&ctx, &p, false) == 0) {
			ft_policy_hash(&p, applied);
			fprintf(stderr, "ask-flowtable: re-applied for interface change\n");
		} else {
			applied[0] = '\0';   /* force a retry on the next event */
			fprintf(stderr, "ask-flowtable: re-apply deferred: %s\n", ctx.err);
		}
	}
	close(nl);
	return 0;
}

static int usage(void)
{
	fprintf(stderr, "usage: ask-flowtable {apply|stop|status|check|render|daemon} [--config PATH]\n");
	return 2;
}

int main(int argc, char **argv)
{
	const char *conf = FT_DEFAULT_CONF;
	const char *cmd = NULL;
	int i;

	for (i = 1; i < argc; i++) {
		if (!strcmp(argv[i], "--config") && i + 1 < argc)
			conf = argv[++i];
		else if (!cmd)
			cmd = argv[i];
		else
			return usage();
	}
	if (!cmd)
		return usage();

	struct ft_ctx ctx;
	memset(&ctx, 0, sizeof(ctx));

	/* nft can exit before we finish feeding its stdin (missing binary, early
	 * parse error): take a clean error from run(), not SIGPIPE death. */
	signal(SIGPIPE, SIG_IGN);

	if (!strcmp(cmd, "daemon"))
		return cmd_daemon(conf);
	if (!strcmp(cmd, "status"))
		return cmd_status(&ctx) ? (fprintf(stderr, "ask-flowtable: %s\n", ctx.err), 1) : 0;

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
	if (!strcmp(cmd, "stop")) {
		if (ft_stop(&ctx, true)) {
			fprintf(stderr, "ask-flowtable: %s\n", ctx.err);
			return 1;
		}
		return 0;
	}
	return usage();
}
