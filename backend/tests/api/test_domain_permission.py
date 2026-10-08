"""A scan only starts for a domain with confirmed permission (#3) and verified ownership (#48)."""

import pytest
from sqlalchemy import text

from qnsentry import verification
from qnsentry.db.session import engine


def add_client(api, name="BadSecurityInc") -> int:
    return api.post("/api/clients", json={"name": name}).json()["id"]


def add_domain(api, client_id, name="badsecurityinc.be", **extra):
    return api.post(f"/api/clients/{client_id}/domains", json={"name": name, **extra})


def fake_dns(monkeypatch, records=None, error=None):
    def lookup(domain):
        if error:
            raise error
        return records or []

    monkeypatch.setattr(verification, "txt_records", lookup)


# ---------- #3: permission ----------


def test_a_domain_cannot_be_added_without_confirming_permission(api):
    response = add_domain(api, add_client(api))

    assert response.status_code == 422
    assert response.json()["detail"] == "Confirm that you own this domain or have written permission to scan it."


def test_a_confirmed_domain_is_added_but_not_yet_verified(api):
    response = add_domain(api, add_client(api), permission_confirmed=True)

    assert response.status_code == 201
    body = response.json()
    assert body["permission_confirmed"] is True
    assert body["verified"] is False
    assert body["verification_record"].startswith("qn-sentry-verify=")


def test_a_domain_without_confirmation_cannot_be_scanned(api, queued):
    # A domain from before migration 0003 has no confirmation; set it up directly in the database
    client_id = add_client(api)
    with engine.begin() as connection:
        domain_id = connection.execute(
            text("INSERT INTO domains (client_id, name) VALUES (:c, 'old.example') RETURNING id"), {"c": client_id}
        ).scalar_one()

    response = api.post(f"/api/domains/{domain_id}/scans")

    assert response.status_code == 403
    assert "Confirm that you own this domain" in response.json()["detail"]
    assert queued == []


def test_permission_can_be_confirmed_for_an_existing_domain(api):
    client_id = add_client(api)
    with engine.begin() as connection:
        domain_id = connection.execute(
            text("INSERT INTO domains (client_id, name) VALUES (:c, 'old.example') RETURNING id"), {"c": client_id}
        ).scalar_one()

    response = api.post(f"/api/domains/{domain_id}/permission")

    assert response.status_code == 200
    assert response.json()["permission_confirmed"] is True


# ---------- #48: ownership ----------


def test_an_unverified_domain_cannot_be_scanned_and_the_message_says_how(api, queued):
    domain = add_domain(api, add_client(api), permission_confirmed=True).json()

    response = api.post(f"/api/domains/{domain['id']}/scans")

    assert response.status_code == 403
    assert domain["verification_record"] in response.json()["detail"]
    assert queued == []


def test_verify_fails_clearly_when_the_record_is_missing(api, monkeypatch):
    domain = add_domain(api, add_client(api), permission_confirmed=True).json()
    fake_dns(monkeypatch, records=["v=spf1 +all"])

    response = api.post(f"/api/domains/{domain['id']}/verify")

    assert response.status_code == 409
    assert domain["verification_record"] in response.json()["detail"]


def test_a_dns_failure_is_reported_as_temporary(api, monkeypatch):
    domain = add_domain(api, add_client(api), permission_confirmed=True).json()
    fake_dns(monkeypatch, error=verification.VerificationLookupFailed("badsecurityinc.be: Timeout"))

    response = api.post(f"/api/domains/{domain['id']}/verify")

    assert response.status_code == 503
    assert "Try again" in response.json()["detail"]


def test_verified_domain_can_be_scanned(api, monkeypatch, queued):
    domain = add_domain(api, add_client(api), permission_confirmed=True).json()
    fake_dns(monkeypatch, records=["v=spf1 +all", f'"{domain["verification_record"]}"'])

    verified = api.post(f"/api/domains/{domain['id']}/verify")
    scan = api.post(f"/api/domains/{domain['id']}/scans")

    assert verified.status_code == 200 and verified.json()["verified"] is True
    assert scan.status_code == 201
    assert queued == [scan.json()["id"]]


def test_verification_is_kept_and_not_looked_up_again(api, monkeypatch):
    domain = add_domain(api, add_client(api), permission_confirmed=True).json()
    fake_dns(monkeypatch, records=[domain["verification_record"]])
    api.post(f"/api/domains/{domain['id']}/verify")
    fake_dns(monkeypatch, error=AssertionError("no second lookup expected"))

    assert api.post(f"/api/domains/{domain['id']}/verify").json()["verified"] is True


def test_client_page_shows_status_and_record_per_domain(api):
    client_id = add_client(api)
    add_domain(api, client_id, permission_confirmed=True)

    [domain] = api.get(f"/api/clients/{client_id}").json()["domains"]

    assert {"permission_confirmed", "verified", "verification_record"} <= set(domain)


@pytest.mark.parametrize("path", ["permission", "verify"])
def test_unknown_domain_is_404(api, path):
    assert api.post(f"/api/domains/999/{path}").status_code == 404


# ---------- Review of #72 ----------


def verified_domain(api, monkeypatch):
    domain = add_domain(api, add_client(api), permission_confirmed=True).json()
    fake_dns(monkeypatch, records=[domain["verification_record"]])
    api.post(f"/api/domains/{domain['id']}/verify")
    return domain


def test_a_removed_record_withdraws_the_permission(api, monkeypatch, queued):
    # The client removes the TXT record: from then on its domain is not scanned anymore
    domain = verified_domain(api, monkeypatch)
    fake_dns(monkeypatch, records=["v=spf1 +all"])

    response = api.post(f"/api/domains/{domain['id']}/scans")

    assert response.status_code == 403
    assert "is no longer on badsecurityinc.be" in response.json()["detail"]
    assert queued == []
    # The dashboard shows the verification step again
    [listed] = api.get(f"/api/clients/{domain['id']}").json()["domains"]
    assert listed["verified"] is False


def test_a_failed_lookup_at_scan_time_starts_no_scan(api, monkeypatch, queued):
    domain = verified_domain(api, monkeypatch)
    fake_dns(monkeypatch, error=verification.VerificationLookupFailed("badsecurityinc.be: Timeout"))

    response = api.post(f"/api/domains/{domain['id']}/scans")

    assert response.status_code == 503
    assert queued == []
    # A DNS problem is not a withdrawn permission: the domain stays verified
    [listed] = api.get(f"/api/clients/{domain['id']}").json()["domains"]
    assert listed["verified"] is True


@pytest.mark.parametrize("value", ["yes", 1, "true"])
def test_only_the_json_value_true_confirms_permission(api, value):
    assert add_domain(api, add_client(api), permission_confirmed=value).status_code == 422
