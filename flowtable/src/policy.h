/*
 * ASK hardware flow-offload service — policy model.
 *
 * A permanent, default-on replacement for the tools/ask_flowtable.py helper.
 * The policy model, its validation, and the rendered nftables output are a
 * faithful port of that engine; the file format is a native line-based conf
 * (/etc/ask/offload.conf) rather than JSON, so no interpreter or JSON library
 * is needed on the target.
 *
 * SPDX-License-Identifier: GPL-2.0+
 */
#ifndef ASK_FLOWTABLE_POLICY_H
#define ASK_FLOWTABLE_POLICY_H

#include <stdbool.h>
#include <stdint.h>
#include <stddef.h>

/* Mirrors CDX_FT_MAX_BINDINGS in cdx/cdx_flowtable_backend.h. Restated here so
 * an oversized policy is refused at check time, naming the limit, rather than
 * binding part of itself and rolling back. A host test fails if they diverge. */
#define FT_MAX_DEVICES   40
#define FT_MAX_RULES     256
#define FT_IFNAME_MAX    15
#define FT_NAME_MAX      64
#define FT_CONF_MAX      65536
/* The rendered table is larger than its conf (a port rule renders four
 * lines), so it has its own limit. ft_validate() measures the render against
 * it, which is what makes a policy that passes check always render at apply.
 * Buffers holding the script, or nft's listing of it, are sized from it. */
#define FT_RENDER_MAX    (FT_CONF_MAX * 2)

/* One selector set. Every field is optional; an empty match (in scope) means
 * "any". Presence is tracked by the has_* flags. An address is stored as a
 * canonical CIDR string exactly as it will appear in nft. */
struct ft_match {
	bool     has_proto;          /* meta l4proto {tcp,udp} */
	char     proto[4];           /* "tcp" | "udp" */

	/* ct <dir> ip <saddr|daddr>; index 0..3 = saddr,daddr,reply_saddr,reply_daddr */
	bool     has_addr[4];
	char     addr[4][44];        /* "a.b.c.d/nn" canonical */

	/* ports; index 0..3 = sport,dport,reply_sport,reply_dport */
	bool     has_port[4];
	char     portspec[4][12];    /* "N" or "lo-hi" */

	bool     has_port_any;       /* shorthand: match on any of the 4 port fields */
	char     port_any[12];

	bool     has_mark;
	uint32_t mark_value, mark_mask;

	char     name[FT_NAME_MAX + 1];
};

struct ft_policy {
	int              version;    /* must be 1 */
	bool             enabled;
	bool             devices_auto;              /* "devices auto" */
	int              ndevices;
	char             devices[FT_MAX_DEVICES][FT_IFNAME_MAX + 1];
	int              nscope;
	struct ft_match  scope[FT_MAX_RULES];
	int              nexclude;
	struct ft_match  exclude[FT_MAX_RULES];
};

/* The address/port field order, shared by conf parsing and rendering so the
 * two never disagree on what index means what. */
extern const char *const FT_ADDR_EXPR[4];   /* nft "ct ... ip saddr" etc. */
extern const char *const FT_ADDR_KEY[4];    /* conf tokens: saddr,daddr,... */
extern const char *const FT_PORT_EXPR[4];   /* nft "ct ... proto-src" etc. */
extern const char *const FT_PORT_KEY[4];    /* conf tokens: sport,dport,... */

/* Error reporting: on failure the parser/validator fills errbuf and returns
 * non-zero, exactly one message, mirroring the Python require() strings so the
 * host test can assert the same rejection surface. */
struct ft_ctx {
	char err[256];
};

/* Parse a conf buffer into policy. Returns 0 on success, -1 on error (ctx->err
 * set). Does NOT resolve "devices auto" — that is the daemon's job at apply. */
int ft_conf_parse(struct ft_ctx *ctx, const char *text, size_t len,
		  struct ft_policy *out);

/* Validate a fully-populated policy (post device resolution). Returns 0/-1. */
int ft_validate(struct ft_ctx *ctx, const struct ft_policy *p);

/* Render the nftables table text for an enabled, validated policy into buf.
 * qos_mark_mask is read from the live adapter (0 when unknown). Returns the
 * number of bytes written (excluding NUL), or -1 (ctx->err set) on overflow.
 * With buf NULL and buflen 0 it only measures, returning the length. */
int ft_render(struct ft_ctx *ctx, const struct ft_policy *p,
	      uint32_t qos_mark_mask, char *buf, size_t buflen);

/* The most an enabled policy can render at apply: its rules under the widest
 * mark guard, plus the longest device list "devices auto" may resolve to.
 * Returns -1 (ctx->err set) if it cannot be rendered at all. */
long ft_render_bound(struct ft_ctx *ctx, const struct ft_policy *p);

/* 64-hex fingerprint of the policy's canonical form, used as the nft table's
 * ownership marker. Stable across runs and independent of qos_mark_mask. */
void ft_policy_hash(const struct ft_policy *p, char out[65]);

/* The nft table name and the ownership-marker prefix. */
/* Ownership-marker recognition over `nft list table` text (pure; host-tested). */
int ft_marker_owned(const char *nft_output, char hash[65]);

#define FT_TABLE   "ask_flowtable"
#define FT_MARKER  "ask-flowtable/v1:"

#endif /* ASK_FLOWTABLE_POLICY_H */
