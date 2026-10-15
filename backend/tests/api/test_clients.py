"""Managing several clients (#16): rename, delete with everything they have, and the overview."""

from sqlalchemy import text

from qnsentry.db.session import engine
from test_domain_permission import add_client, add_domain

TABLES = ["clients", "domains", "scans", "module_runs", "findings", "port_scan_approvals"]


def add_scan(domain_id: int, status: str = "completed", hours_ago: int = 0) -> int:
    """A scan with one module run, one finding and an approved address."""
    with engine.begin() as connection:
        scan_id = connection.execute(
            text(
                "INSERT INTO scans (domain_id, status, context, created_at)"
                " VALUES (:d, :s, '{}'::jsonb, now() - make_interval(hours => :h)) RETURNING id"
            ),
            {"d": domain_id, "s": status, "h": hours_ago},
        ).scalar_one()
        connection.execute(
            text("INSERT INTO module_runs (scan_id, module, status, finding_count) VALUES (:id, 'phishing', 'completed', 1)"),
            {"id": scan_id},
        )
        connection.execute(
            text(
                "INSERT INTO findings (scan_id, module, type, title, description, severity, asset, details)"
                " VALUES (:id, 'phishing', 't', 'x', 'd', 'high', 'a', '{}'::jsonb)"
            ),
            {"id": scan_id},
        )
        connection.execute(
            text("INSERT INTO port_scan_approvals (domain_id, ip) VALUES (:d, :ip) ON CONFLICT DO NOTHING"),
            {"d": domain_id, "ip": "192.0.2.10"},
        )
    return scan_id


def rows() -> dict[str, int]:
    with engine.connect() as connection:
        return {table: connection.execute(text(f"SELECT count(*) FROM {table}")).scalar_one() for table in TABLES}


def client_with_domains(api, name="BadSecurityInc", *domains) -> tuple[int, list[int]]:
    client_id = add_client(api, name)
    return client_id, [add_domain(api, client_id, domain, permission_confirmed=True).json()["id"] for domain in domains]


# ---------- Rename ----------


def test_a_client_can_be_renamed(api):
    client_id = add_client(api)

    response = api.patch(f"/api/clients/{client_id}", json={"name": "  Bad Security Inc  "})

    assert response.status_code == 200
    assert response.json()["name"] == "Bad Security Inc"
    assert api.get(f"/api/clients/{client_id}").json()["name"] == "Bad Security Inc"


def test_a_client_name_cannot_be_empty(api):
    client_id = add_client(api)

    assert api.patch(f"/api/clients/{client_id}", json={"name": "   "}).status_code == 422
    assert api.get(f"/api/clients/{client_id}").json()["name"] == "BadSecurityInc"


# ---------- Delete ----------


def test_deleting_a_client_deletes_everything_it_has(api):
    client_id, [first, second] = client_with_domains(api, "BadSecurityInc", "badsecurityinc.be", "badsecurity.eu")
    add_scan(first)
    add_scan(second)
    other_id, [other_domain] = client_with_domains(api, "Other", "other.be")
    add_scan(other_domain)

    response = api.delete(f"/api/clients/{client_id}")

    assert response.status_code == 204
    assert api.get(f"/api/clients/{client_id}").status_code == 404
    # Only the other client and its data are left
    assert rows() == {table: 1 for table in TABLES}
    assert [client["id"] for client in api.get("/api/clients").json()] == [other_id]


def test_deleting_a_domain_keeps_the_client_and_its_other_domains(api):
    client_id, [first, second] = client_with_domains(api, "BadSecurityInc", "badsecurityinc.be", "badsecurity.eu")
    add_scan(first)
    kept_scan = add_scan(second)

    response = api.delete(f"/api/domains/{first}")

    assert response.status_code == 204
    [domain] = api.get(f"/api/clients/{client_id}").json()["domains"]
    assert domain["id"] == second
    assert [scan["id"] for scan in domain["scans"]] == [kept_scan]
    assert rows() == {table: 1 for table in TABLES}


def test_a_deleted_domain_can_be_added_again(api):
    # The name is unique across clients: after deleting it, another client may add it
    _, [domain_id] = client_with_domains(api, "BadSecurityInc", "badsecurityinc.be")
    api.delete(f"/api/domains/{domain_id}")

    response = add_domain(api, add_client(api, "Other"), "badsecurityinc.be", permission_confirmed=True)

    assert response.status_code == 201
    # A fresh start: not verified, no approved addresses
    assert (response.json()["verified"], response.json()["port_scan_ips"]) == (False, [])


def test_nothing_is_deleted_while_a_scan_runs(api):
    client_id, [domain_id] = client_with_domains(api, "BadSecurityInc", "badsecurityinc.be")
    add_scan(domain_id, status="running")
    before = rows()

    client = api.delete(f"/api/clients/{client_id}")
    domain = api.delete(f"/api/domains/{domain_id}")

    assert client.status_code == domain.status_code == 409
    assert client.json()["detail"] == "A scan of badsecurityinc.be is still running. Wait until it has finished."
    assert rows() == before


def test_a_queued_scan_also_blocks_deleting(api):
    _, [domain_id] = client_with_domains(api, "BadSecurityInc", "badsecurityinc.be")
    add_scan(domain_id, status="queued")

    assert api.delete(f"/api/domains/{domain_id}").status_code == 409


def test_a_stuck_scan_does_not_block_deleting(api):
    # Older than the scan timeout (120 minutes): it will not finish anymore, as in start_scan
    client_id, [domain_id] = client_with_domains(api, "BadSecurityInc", "badsecurityinc.be")
    add_scan(domain_id, status="running", hours_ago=3)

    assert api.delete(f"/api/clients/{client_id}").status_code == 204
    assert rows()["scans"] == 0


def test_unknown_client_or_domain_is_404(api):
    assert api.patch("/api/clients/999", json={"name": "x"}).status_code == 404
    assert api.delete("/api/clients/999").status_code == 404
    assert api.delete("/api/domains/999").status_code == 404


# ---------- Overview ----------


def test_the_overview_shows_the_newest_scan_of_any_domain(api):
    _, [first, second] = client_with_domains(api, "BadSecurityInc", "badsecurityinc.be", "badsecurity.eu")
    add_scan(first)
    newest = add_scan(second, status="running")
    add_client(api, "Not scanned yet")

    clients = {client["name"]: client for client in api.get("/api/clients").json()}

    last = clients["BadSecurityInc"]["last_scan"]
    # Also a running scan: the overview shows that something is happening
    assert (last["id"], last["domain_id"], last["status"], last["finished_at"]) == (newest, second, "running", None)
    assert clients["Not scanned yet"]["last_scan"] is None
