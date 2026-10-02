"""Native multicast recovery with live unicast and multicast controls."""
from __future__ import annotations

from _flowtable_service_multicast import (STOPS, acceleration_stopped, recover)


import pytest



@pytest.mark.parametrize('fault', ['withdrawal', 'install-failslab', 'add-event-failslab', 'delete-event-failslab', 'group-failslab'])
async def test_flowtable_service_multicast_recovery(multicast_service, fault):
    await recover(multicast_service, fault)


@pytest.mark.parametrize('how', STOPS)
async def test_flowtable_service_multicast_stops_with_acceleration(multicast_service, how):
    await acceleration_stopped(multicast_service, how)
