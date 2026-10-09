"""Port scans only on addresses the user confirmed (#81)."""

import json

from sqlalchemy import text

from qnsentry.db.session import engine
from test_domain_permission import add_client, add_domain, fake_dns

LIVE_HOSTS = [
    {"name": "badsecurityinc.be", "ips": ["76.76.21.21"]},
    {"name": "www.badsecurityinc.be", "ips": ["76.76.21.21"]},
    {"name": "dev.badsecurityinc.be", "ips": ["192.0.2.10", "2001:db8::10"]},
]


def verified_domain(api, monkeypatch) -> dict:
    domain = add_domain(api, add_client(api), permission_confirmed=True).json()
    fake_dns(monkeypatch, records=[domain["verification_record"]])
    api.post(f"/api/domains/{domain['id']}/verify")
    return domain


def scan_with_hosts(domain_id: int, live_hosts=LIVE_HOSTS, status: str = "completed") -> None:
    """A scan whose Attack Surface module found these hosts (#4)."""
    with engine.begin() as connection:
        connection.execute(
            text("INSERT INTO scans (domain_id, status, context) VALUES (:d, :s, CAST(:c AS JSONB))"),
            {"d": domain_id, "s": status, "c": json.dumps({"domain": "badsecurityinc.be", "live_hosts": live_hosts})},
        )


def test_addresses_of_the_latest_scan_start_unapproved(api, monkeypatch):
    domain = verified_domain(api, monkeypatch)
    scan_with_hosts(domain["id"])

    addresses = api.get(f"/api/domains/{domain['id']}/addresses").json()

    assert addresses == [
        {"ip": "76.76.21.21", "hosts": ["badsecurityinc.be", "www.badsecurityinc.be"], "approved": False},
        {"ip": "192.0.2.10", "hosts": ["dev.badsecurityinc.be"], "approved": False},
        {"ip": "2001:db8::10", "hosts": ["dev.badsecurityinc.be"], "approved": False},
    ]


def test_a_domain_without_a_scan_has_no_addresses(api, monkeypatch):
    domain = verified_domain(api, monkeypatch)

    assert api.get(f"/api/domains/{domain['id']}/addresses").json() == []


def test_approving_an_address(api, monkeypatch):
    domain = verified_domain(api, monkeypatch)
    scan_with_hosts(domain["id"])

    response = api.put(f"/api/domains/{domain['id']}/port-scan", json={"ips": ["192.0.2.10"]})

    assert response.status_code == 200
    assert [a["ip"] for a in response.json() if a["approved"]] == ["192.0.2.10"]
    [listed] = api.get(f"/api/clients/{domain['id']}").json()["domains"]
    assert listed["port_scan_ips"] == ["192.0.2.10"]


def test_an_unverified_domain_cannot_approve_addresses(api):
    domain = add_domain(api, add_client(api), permission_confirmed=True).json()
    scan_with_hosts(domain["id"])

    response = api.put(f"/api/domains/{domain['id']}/port-scan", json={"ips": ["192.0.2.10"]})

    assert response.status_code == 403
    assert "Verify that you control badsecurityinc.be" in response.json()["detail"]


def test_an_address_the_scan_did_not_find_cannot_be_approved(api, monkeypatch):
    # The approval is for the domain's own hosts: an arbitrary address cannot be added through it
    domain = verified_domain(api, monkeypatch)
    scan_with_hosts(domain["id"])

    response = api.put(f"/api/domains/{domain['id']}/port-scan", json={"ips": ["198.51.100.7"]})

    assert response.status_code == 422
    assert response.json()["detail"] == "198.51.100.7 was not found for badsecurityinc.be in the latest scan."


def test_an_invalid_address_is_refused(api, monkeypatch):
    domain = verified_domain(api, monkeypatch)
    scan_with_hosts(domain["id"])

    response = api.put(f"/api/domains/{domain['id']}/port-scan", json={"ips": ["dev.badsecurityinc.be"]})

    assert response.status_code == 422
    assert response.json()["detail"] == "dev.badsecurityinc.be is not a valid IP address."


def test_ipv6_addresses_are_normalised(api, monkeypatch):
    domain = verified_domain(api, monkeypatch)
    scan_with_hosts(domain["id"])

    response = api.put(f"/api/domains/{domain['id']}/port-scan", json={"ips": ["2001:DB8:0::10"]})

    assert [a["ip"] for a in response.json() if a["approved"]] == ["2001:db8::10"]


def test_the_list_replaces_the_approvals_and_an_empty_list_clears_them(api, monkeypatch):
    domain = verified_domain(api, monkeypatch)
    scan_with_hosts(domain["id"])
    url = f"/api/domains/{domain['id']}/port-scan"

    api.put(url, json={"ips": ["192.0.2.10", "2001:db8::10"]})
    replaced = api.put(url, json={"ips": ["2001:db8::10"]}).json()
    cleared = api.put(url, json={"ips": []}).json()

    assert [a["ip"] for a in replaced if a["approved"]] == ["2001:db8::10"]
    assert not any(a["approved"] for a in cleared)


def test_an_approved_address_the_latest_scan_did_not_find_stays_visible(api, monkeypatch):
    # So the user can still see and withdraw the approval
    domain = verified_domain(api, monkeypatch)
    scan_with_hosts(domain["id"])
    api.put(f"/api/domains/{domain['id']}/port-scan", json={"ips": ["192.0.2.10"]})
    scan_with_hosts(domain["id"], live_hosts=[{"name": "badsecurityinc.be", "ips": ["76.76.21.21"]}])

    addresses = api.get(f"/api/domains/{domain['id']}/addresses").json()

    assert {"ip": "192.0.2.10", "hosts": [], "approved": True} in addresses


def test_an_approved_address_the_latest_scan_did_not_find_can_be_kept(api, monkeypatch):
    # The dashboard sends back every checked address, also one the latest scan did not see anymore
    domain = verified_domain(api, monkeypatch)
    scan_with_hosts(domain["id"])
    url = f"/api/domains/{domain['id']}/port-scan"
    api.put(url, json={"ips": ["192.0.2.10"]})
    scan_with_hosts(domain["id"], live_hosts=[{"name": "badsecurityinc.be", "ips": ["76.76.21.21"]}])

    response = api.put(url, json={"ips": ["192.0.2.10", "76.76.21.21"]})

    assert response.status_code == 200
    assert [a["ip"] for a in response.json() if a["approved"]] == ["76.76.21.21", "192.0.2.10"]


def test_only_the_latest_finished_scan_counts(api, monkeypatch):
    # An older scan's address may no longer belong to the domain, and a running scan has no hosts yet
    domain = verified_domain(api, monkeypatch)
    scan_with_hosts(domain["id"])
    scan_with_hosts(domain["id"], live_hosts=[{"name": "badsecurityinc.be", "ips": ["76.76.21.21"]}])
    scan_with_hosts(domain["id"], live_hosts=[], status="running")

    addresses = api.get(f"/api/domains/{domain['id']}/addresses").json()
    response = api.put(f"/api/domains/{domain['id']}/port-scan", json={"ips": ["192.0.2.10"]})

    assert [a["ip"] for a in addresses] == ["76.76.21.21"]
    assert response.status_code == 422


def test_unknown_domain_is_404(api):
    assert api.get("/api/domains/999/addresses").status_code == 404
    assert api.put("/api/domains/999/port-scan", json={"ips": []}).status_code == 404
