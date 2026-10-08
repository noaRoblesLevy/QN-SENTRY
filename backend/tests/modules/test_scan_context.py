"""Which addresses may get a port scan (#81)."""

from qnsentry.modules.base import ScanContext

LIVE_HOSTS = [
    {"name": "badsecurityinc.be", "ips": ["76.76.21.21"]},
    {"name": "dev.badsecurityinc.be", "ips": ["192.0.2.10", "2001:db8::10"]},
    {"name": "test.badsecurityinc.be", "ips": ["192.0.2.10"]},
]


def test_nothing_is_a_target_without_an_approval():
    context = ScanContext(domain="badsecurityinc.be", live_hosts=LIVE_HOSTS)

    assert context.port_scan_targets() == {}


def test_an_approved_address_found_in_this_scan_is_a_target_with_its_hosts():
    context = ScanContext(domain="badsecurityinc.be", live_hosts=LIVE_HOSTS, port_scan_ips=["192.0.2.10"])

    assert context.port_scan_targets() == {"192.0.2.10": ["dev.badsecurityinc.be", "test.badsecurityinc.be"]}


def test_an_approved_address_the_hosts_no_longer_resolve_to_is_not_a_target():
    # dev moved: the old address may belong to someone else by now
    context = ScanContext(domain="badsecurityinc.be", live_hosts=LIVE_HOSTS, port_scan_ips=["198.51.100.7"])

    assert context.port_scan_targets() == {}
