"""ask_orch — orchestrator library for the ASK test harness.

Runs on the WAN-side host (the one physically reachable from the DUT's
WAN interface). Imported by pytest tests under tools/tests/; they drive
scenarios against the target's HTTP agent and the LAN-side traffic
generator (currently over UART, eventually also HTTP).
"""

__version__ = "0.1.0"
