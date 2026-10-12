"""The risk score is stored per scan (#59): reading it never loads the findings."""

import json

from alembic import command
from sqlalchemy import event, text

from qnsentry.db.migrate import alembic_config
from qnsentry.db.session import engine
from qnsentry.risk import METHOD
from test_domain_permission import add_client, add_domain


def add_domain_id(api) -> tuple[int, int]:
    client_id = add_client(api)
    return client_id, add_domain(api, client_id, permission_confirmed=True).json()["id"]


def insert_scan(connection, domain_id: int, status: str, score: int | None = None) -> int:
    """A scan row; with `score` it looks like one the worker of #59 finished."""
    return connection.execute(
        text(
            "INSERT INTO scans (domain_id, status, context, risk_score, risk_level, risk_complete, risk_points, risk_method)"
            " VALUES (:d, :s, '{}'::jsonb, :score, :level, :complete, :points, :method) RETURNING id"
        ),
        {
            "d": domain_id, "s": status, "score": score,
            "level": "high" if score else None, "complete": True if score else None,
            "points": 10 if score else None, "method": METHOD if score else None,
        },
    ).scalar_one()


def insert_findings(connection, scan_id: int, *severities: str, kind: str = "t") -> None:
    for severity in severities:
        connection.execute(
            text(
                "INSERT INTO findings (scan_id, module, type, title, description, severity, asset, details)"
                " VALUES (:id, 'phishing', :type, 'x', 'd', :sev, 'a', '{}'::jsonb)"
            ),
            {"id": scan_id, "sev": severity, "type": kind},
        )


def insert_module_run(connection, scan_id: int, warnings: list[str]) -> None:
    connection.execute(
        text(
            "INSERT INTO module_runs (scan_id, module, status, finding_count, warnings)"
            " VALUES (:id, 'phishing', 'completed', 0, CAST(:w AS JSONB))"
        ),
        {"id": scan_id, "w": json.dumps(warnings)},
    )


def queries_on_findings(call) -> list[str]:
    seen = []

    def record(conn, cursor, statement, parameters, context, executemany):
        if "FROM findings" in statement:
            seen.append(statement)

    event.listen(engine, "before_cursor_execute", record)
    try:
        call()
    finally:
        event.remove(engine, "before_cursor_execute", record)
    return seen


def test_the_client_pages_do_not_load_findings(api):
    client_id, domain_id = add_domain_id(api)
    with engine.begin() as connection:
        scan_id = insert_scan(connection, domain_id, "completed", score=50)
        insert_findings(connection, scan_id, "high")

    assert queries_on_findings(lambda: api.get("/api/clients")) == []
    assert queries_on_findings(lambda: api.get(f"/api/clients/{client_id}")) == []
    assert api.get("/api/clients").json()[0]["risk_score"] == 50


def test_the_scan_shows_the_method_of_its_score(api):
    client_id, domain_id = add_domain_id(api)
    with engine.begin() as connection:
        scan_id = insert_scan(connection, domain_id, "completed", score=50)

    assert api.get(f"/api/scans/{scan_id}").json()["risk_method"] == METHOD
    assert api.get(f"/api/clients/{client_id}").json()["domains"][0]["scans"][0]["risk_method"] == METHOD


def test_the_migration_scores_existing_scans(api):
    _, domain_id = add_domain_id(api)
    config = alembic_config()
    command.downgrade(config, "0004")
    try:
        with engine.begin() as connection:
            scans = {}
            for name, status in [
                ("completed", "completed"), ("partial", "partial"), ("warned", "completed"),
                ("placeholder", "completed"), ("failed", "failed"),
            ]:
                scans[name] = connection.execute(
                    text("INSERT INTO scans (domain_id, status, context) VALUES (:d, :s, '{}'::jsonb) RETURNING id"),
                    {"d": domain_id, "s": status},
                ).scalar_one()
            insert_findings(connection, scans["completed"], "high", "medium")
            insert_findings(connection, scans["partial"], "high")
            insert_findings(connection, scans["warned"], "high")
            insert_module_run(connection, scans["warned"], ["1 lookup failed"])
            insert_findings(connection, scans["placeholder"], "high")
            insert_findings(connection, scans["placeholder"], "info", kind="placeholder")
            insert_findings(connection, scans["failed"], "critical")
    finally:
        command.upgrade(config, "head")

    with engine.connect() as connection:
        rows = {
            row.id: (row.risk_score, row.risk_level, row.risk_complete, row.risk_points, row.risk_method)
            for row in connection.execute(
                text("SELECT id, risk_score, risk_level, risk_complete, risk_points, risk_method FROM scans")
            )
        }
    assert rows[scans["completed"]] == (50, "high", True, 14, METHOD)
    # Partial, with warnings or with a placeholder: the same score, marked incomplete
    for name in ("partial", "warned", "placeholder"):
        assert rows[scans[name]] == (50, "high", False, 10, METHOD)
    assert rows[scans["failed"]] == (None, None, None, None, None)
