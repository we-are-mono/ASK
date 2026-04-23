"""askd-agent — on-node HTTP API for the ASK test harness.

Runs on the DUT (Yocto-delivered), the LAN host (rsync), and the WAN
host (local install). Exposes a small aiohttp JSON API the orchestrator
uses to drive tests.
"""

__version__ = "0.1.0"
