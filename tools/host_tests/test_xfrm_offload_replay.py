"""Where the patched kernel reads and writes a packet-offloaded state's replay
state, which moves in its device and reaches xfrm's copy only when the driver
publishes it (xdo_dev_state_update_stats()).

Every path that carries a state's sequence numbers on to another state asks
the driver first -- XFRM_MSG_GETSA already did, XFRM_MSG_GETAE and the clone
xfrm_state_migrate() makes now do -- and the one path that writes them,
XFRM_MSG_NEWAE, refuses to for such a state: no driver hears of it.
"""

import os
from pathlib import Path
import re

from _host_qos_lifecycle import (function)

ROOT = Path(__file__).resolve().parents[2]
KERNEL = Path(os.environ.get("ASK_KERNEL_SOURCE", ROOT /
    "meta-ask/build/tmp/work-shared/ask-ls1046a/kernel-source"))
REFRESH = "xfrm_dev_state_update_stats(x);"


def user():
    return (KERNEL / "net/xfrm/xfrm_user.c").read_text()


def test_getae_publishes_before_it_reads():
    """GETAE asks the driver under x->lock, where the state timer asks, and
    before it builds the reply from the state's copy."""
    body = function(user(), "xfrm_get_ae")
    lock = body.index("spin_lock_bh(&x->lock);")
    assert body.count(REFRESH) == 1, body
    assert lock < body.index(REFRESH) < body.index("err = build_aevent(r_skb, x, &c);"), body
    assert body.index("spin_unlock_bh(&x->lock);") > body.index("err = build_aevent("), body


def test_getsa_publishes_before_it_reads():
    """GETSA's copy of the state, upstream's own call site of the op, reads the
    replay state only after it."""
    body = function(user(), "copy_to_user_state_extra")
    state = function(user(), "copy_to_user_state")
    assert "xfrm_dev_state_update_stats(x);" in state, state
    assert body.index("copy_to_user_state(x, p);") < body.index("XFRMA_REPLAY_ESN_VAL"), body


def test_migrate_publishes_before_it_clones():
    """The clone takes the replay state as xfrm has it, so the driver
    publishes first, under x->lock."""
    source = (KERNEL / "net/xfrm/xfrm_state.c").read_text()
    body = function(source, "xfrm_state_migrate")
    clone = body.index("xc = xfrm_state_clone(x, encap);")
    refresh = body.index(REFRESH)
    assert body.index("spin_lock_bh(&x->lock);") < refresh < body.index("spin_unlock_bh(&x->lock);") < clone, body
    # And the clone copies exactly the two shapes xfrm keeps it in.
    clone_body = function(source, "xfrm_state_clone")
    assert "x->replay = orig->replay;" in clone_body and "xfrm_replay_clone(x, orig)" in clone_body


def test_newae_leaves_an_offloaded_replay_state_alone():
    """NEWAE refuses a replay state for a packet-offloaded SA, with the
    reason, before anything is written; the lifetime and thresholds it may
    still set are xfrm's own."""
    body = function(user(), "xfrm_new_ae")
    refusal = re.search(r"if \(\(rp \|\| re\) && x->xso\.type == XFRM_DEV_OFFLOAD_PACKET\) \{\s*"
                        r"NL_SET_ERR_MSG\(extack, \"([^\"]+)\"\);\s*err = -EOPNOTSUPP;\s*goto out;", body)
    assert refusal, body
    assert "packet-offloaded" in refusal.group(1)
    assert body.index("x = xfrm_state_lookup(") < refusal.start() < body.index("xfrm_update_ae_params(x, attrs, 1);"), body
    # Nothing else in it narrows what an update may carry.
    assert body.count("-EOPNOTSUPP") == 1, body
