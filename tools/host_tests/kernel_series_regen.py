"""Regenerating a line's series rewrites a patch file only when its change did.

A patch file written against an earlier state of the series carries hunk
offsets, blob abbreviations and a commit id that regeneration renews by itself;
`git am` applies it all the same. Rewriting such a file would bury a fix's one
real patch change under every patch that merely sits later in the series.
"""

import kernel_series

PATCH = """\
From {commit} Mon Sep 17 00:00:00 2001
From: Tomaz Zaman <tomaz@mono.si>
Subject: [PATCH] netfilter: flowtable: an example

---
 net/netfilter/nf_flow_table_core.c | 2 ++

diff --git a/net/netfilter/nf_flow_table_core.c b/net/netfilter/nf_flow_table_core.c
index {index} 100644
--- a/net/netfilter/nf_flow_table_core.c
+++ b/net/netfilter/nf_flow_table_core.c
@@ -{old},6 +{new},8 @@ static bool nf_flow_custom_gc(struct nf_flowtable *flow_table,
 static void nf_flow_offload_gc_step(struct nf_flowtable *flow_table,
 				    struct flow_offload *flow, void *data)
 {{
+	{added}
+	bool teardown;
 	struct net *net = nf_ct_net(flow->ct);
"""


def patch(commit="0" * 40, index="933d60b206d6..2cf93b982f2f", old=580, new=580,
          added="bool retire = true;"):
    return PATCH.format(commit=commit, index=index, old=old, new=new, added=added)


def test_what_regeneration_renews_by_itself_is_no_change():
    written = patch(commit="c1894f0366a98b4c5486102d7bf3cf0431fc84cd")
    renewed = patch(index="0e6d442919b22..b48a4859dbbf6", old=610, new=610)
    assert kernel_series.normalized(written) == kernel_series.normalized(renewed)


def test_a_changed_line_is_a_change():
    assert kernel_series.normalized(patch()) != kernel_series.normalized(patch(added="bool retire;"))


def test_a_changed_hunk_length_is_a_change():
    assert kernel_series.normalized(patch()) != kernel_series.normalized(
        patch().replace("@@ -580,6 +580,8 @@", "@@ -580,6 +580,9 @@"))
