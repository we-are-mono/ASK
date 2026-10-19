"""Check cdx classifies every gateway-dk port by its FMan port, not its link.

cdx_pcd_ports.c is compiled unmodified against the board model in
cdx_pcd_ports_board.c. A 10G MAC that the firmware runs at 1000base-x is still
bound to the FMan's 10G RX port: cdx must class it 10G, give it the logical id
the 10G port carries, and resolve it to that same wrapper port. The expected
ids are the ones mono-1.0.7's cdx_cfg.xml fixed for this board.
"""

import os
import shutil
import subprocess
from pathlib import Path

import pytest

from cdx_pcd_build import SHIMS, sdk_tree

ROOT = Path(__file__).resolve().parents[2]

PORT_SHIMS = {
    "linux/netdevice.h": """#pragma once
#include <linux/types.h>
#define SPEED_1000 1000
#define SPEED_10000 10000
struct device_node;
struct device { struct device *parent; struct device_node *of_node; };
struct net_device { char name[16]; struct device dev; void *priv; };
struct net { int unused; };
extern struct net init_net;
extern struct net_device *harness_netdevs[];
extern unsigned int harness_num_netdevs;
static inline void *netdev_priv(const struct net_device *dev) { return dev->priv; }
#define for_each_netdev(net, d) \\
	for (unsigned int _i = ((void)(net), 0); \\
	     _i < harness_num_netdevs && ((d) = harness_netdevs[_i], 1); _i++)
""",
    "linux/of.h": """#pragma once
#include <errno.h>
#include <string.h>
#include <linux/types.h>
struct device_node {
	const char *full_name;
	const char *compatible;
	bool has_portid;
	u32 portid;
};
extern struct device_node *harness_nodes[];
extern unsigned int harness_num_nodes;
static inline int of_device_is_compatible(const struct device_node *n, const char *c)
{ return n && n->compatible && !strcmp(n->compatible, c); }
static inline int of_property_read_u32(const struct device_node *n, const char *p, u32 *v)
{
	if (!n || !n->has_portid || strcmp(p, "mono,cdx-logical-portid"))
		return -EINVAL;
	*v = n->portid;
	return 0;
}
static inline void of_node_put(struct device_node *n) { (void)n; }
static inline const char *kbasename(const char *p)
{ const char *t = strrchr(p, '/'); return t ? t + 1 : p; }
#define for_each_compatible_node(dn, type, compat) \\
	for (unsigned int _n = 0; \\
	     ((dn) = _n < harness_num_nodes ? harness_nodes[_n] : NULL) != NULL; _n++) \\
		if (of_device_is_compatible((dn), (compat)))
""",
    "linux/rtnetlink.h": "#pragma once\n#define ASSERT_RTNL() do { } while (0)\n",
    "linux/sort.h": """#pragma once
#include <stdlib.h>
static inline void sort(void *base, size_t num, size_t size,
			int (*cmp)(const void *, const void *), void *swap)
{ (void)swap; qsort(base, num, size, cmp); }
""",
    "linux/fsl_oh_port.h": """#pragma once
#include <stdint.h>
#define MAX_OFFLINE_PORTS 4
struct fman_offline_port_info {
	char port_name[32];
	uint32_t channel_id;
	uint32_t err_fqid;
	uint32_t default_fqid;
};
int oh_port_driver_get_port_info(struct fman_offline_port_info *info);
""",
    "mac.h": """#pragma once
#include <linux/netdevice.h>
struct mac_device {
	struct device *dev;
	void *fm_dev;
	uint8_t cell_index;
	int max_speed;
	void *port_dev[2];
};
""",
    "dpaa_eth.h": """#pragma once
#include "mac.h"
enum port_type { RX, TX };
struct dpa_priv_s { struct mac_device *mac_dev; };
""",
    "dpaa_eth_common.h": """#pragma once
#include <stdio.h>
#define strscpy(dst, src, size) snprintf((dst), (size), "%s", (src))
""",
    "portdefs.h": "#pragma once\n",
    # The wrapper port carries the type and id sdk_fman's port probe gave it.
    "lnxwrp_fm.h": """#pragma once
#include "fm_ext.h"
#include "fm_port_ext.h"
typedef struct { t_FmPortParams param; } t_WrpFmPortDevSettings;
typedef struct {
	uint8_t id;
	bool active;
	t_Handle h_Dev;
	t_WrpFmPortDevSettings settings;
} t_LnxWrpFmPortDev;
typedef struct {
	uint8_t id;
	t_Handle h_Dev;
	t_Handle h_PcdDev;
	t_LnxWrpFmPortDev opPorts[FM_MAX_NUM_OF_OH_PORTS - 1];
	t_LnxWrpFmPortDev rxPorts[FM_MAX_NUM_OF_RX_PORTS];
} t_LnxWrpFmDev;
""",
}

# name, class, number, logical id, cdx_port_info type, resolved wrapper port
EXPECTED = [
    "eth0 1G 1 1 1 own",
    "eth1 1G 4 4 1 own",
    "eth2 1G 5 5 1 own",
    "eth3 10G 0 6 10 own",
    "eth4 10G 1 7 10 own",
    "dpa-fman0-oh@2 OH 1 9 0 -",
    "dpa-fman0-oh@3 OH 2 10 0 -",
    "dpa-fman0-oh@4 OH 3 11 0 -",
]


@pytest.fixture(scope="module")
def harness(tmp_path_factory):
    tmp = tmp_path_factory.mktemp("cdx_pcd_ports")
    sdk = sdk_tree()
    for name, body in {**SHIMS, **PORT_SHIMS}.items():
        target = tmp / name
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(body)
    shutil.copyfile(Path(__file__).with_name("sdk_types_linux.h"), tmp / "types_linux.h")
    # A copy beside the shims, so its quoted includes find them before cdx/'s.
    shutil.copyfile(ROOT / "cdx/cdx_pcd_ports.c", tmp / "cdx_pcd_ports.c")

    binary = tmp / "cdx_pcd_ports"
    command = [os.environ.get("HOSTCC", "cc"), "-std=gnu11", "-g", "-O1",
               "-fsanitize=address,undefined", "-fno-omit-frame-pointer",
               "-Werror=implicit-function-declaration", "-D__CORE_EXT_H",
               "-include", "errno.h",
               "-include", str(sdk / "ls1043_dflags.h"),
               "-I", str(tmp), "-I", str(ROOT / "cdx")]
    for inc in ["inc", "inc/etc", "inc/Peripherals", "inc/flib",
                "inc/integrations/LS1043"]:
        command += ["-I", str(sdk / inc)]
    command += [str(tmp / "cdx_pcd_ports.c"),
                str(Path(__file__).with_name("cdx_pcd_ports_board.c")),
                "-o", str(binary)]
    subprocess.run(command, check=True)
    return binary


@pytest.mark.parametrize("board", ["dut", "router"])
def test_cdx_pcd_ports_follow_fman_port(harness, board):
    out = subprocess.run([str(harness), board], check=True, capture_output=True,
                         text=True)
    assert out.stdout.splitlines() == [f"count {len(EXPECTED)}", *EXPECTED], out.stderr
