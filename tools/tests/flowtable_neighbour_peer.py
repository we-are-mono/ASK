"""LAN-side neighbour controls shared by UDP and persistent TCP tests.

This file is staged as source with lan_run_python or prepended to the TCP peer.
Nothing changes until configure_neighbour is explicitly called by the test.
"""


def configure_neighbour(iface, address, mac=None, arp_ignore=None, restore_after=None):
    import pathlib
    import subprocess
    import threading
    import time

    interface = pathlib.Path("/sys/class/net") / iface
    ignore = pathlib.Path("/proc/sys/net/ipv4/conf") / iface / "arp_ignore"
    assert interface.is_dir() and ignore.is_file()
    if restore_after is not None:
        assert arp_ignore == 8 and 0 < restore_after <= 15
    if arp_ignore is not None:
        assert arp_ignore in {0, 8}
        old = ignore.read_text()
        ignore.write_text(str(arp_ignore))
        if restore_after is not None:
            # A TCP control connection cannot restore ARP over a path whose
            # resolution has deliberately failed. Bound the fault locally;
            # the fixture also restores the original value after peer exit.
            timer = threading.Timer(restore_after, ignore.write_text, args=(old,))
            timer.daemon = True
            timer.start()
    else:
        assert restore_after is None
    if mac is not None:
        from scapy.all import ARP, Ether, sendp
        subprocess.run(["ip", "link", "set", "dev", iface, "address", mac], check=True)
        # Announce the actual new receive address using ARP, never an
        # administrative replacement of the DUT's neighbour entry.
        sendp(Ether(src=mac, dst="ff:ff:ff:ff:ff:ff") /
              ARP(op=1, hwsrc=mac, psrc=address,
                  hwdst="00:00:00:00:00:00", pdst=address),
              iface=iface, count=2, inter=0.05, verbose=False)
    return {"op": "neighbour", "mac": (interface / "address").read_text().strip(),
            "arp_ignore": int(ignore.read_text()), "time": time.time(),
            "restore_after": restore_after}
