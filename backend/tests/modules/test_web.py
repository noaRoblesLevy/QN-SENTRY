"""Attack Surface: web services and technologies of the live hosts (issue #6)."""

import json

import pytest

from qnsentry.db.models import Severity
from qnsentry.modules.attack_surface import AttackSurfaceModule, web, web_findings
from qnsentry.modules.attack_surface.subdomains import RESOLVERS, Host
from qnsentry.modules.attack_surface.web import WebService, outdated_software, parse_httpx_output
from qnsentry.modules.base import ScanContext

DOMAIN = "badsecurityinc.be"
LIVE_HOSTS = [
    {"name": "www.badsecurityinc.be", "ips": ["76.76.21.21"], "cdn": None},
    {"name": "dev.badsecurityinc.be", "ips": ["192.0.2.10"], "cdn": None},
]
LOGIN_PAGE = """<form method="post" action="/login">
  <label for="password">Password</label>
  <input id="password" name="password" type="password" />
</form>"""
# Captured from the worker image: httpx against the decoy of testenv/vm (the host name replaced)
DECOY = {
    "port": "80", "url": "http://dev.badsecurityinc.be", "input": "dev.badsecurityinc.be",
    "title": "BadSecurityInc – Staging admin", "scheme": "http", "webserver": "nginx/1.18.0",
    "content_type": "text/html", "method": "GET", "host": "dev.badsecurityinc.be", "host_ip": "192.0.2.10",
    "path": "/", "a": ["192.0.2.10"], "tech": ["Nginx:1.18.0", "PHP:7.4.3"], "words": 369, "lines": 39,
    "status_code": 200, "content_length": 1910, "failed": False, "body": LOGIN_PAGE,
}
VERCEL = {
    "url": "https://www.badsecurityinc.be", "input": "www.badsecurityinc.be", "status_code": 200,
    "title": "BadSecurityInc | Office IT for Belgian SMEs", "webserver": "Vercel", "tech": ["HSTS", "Vercel"],
    "failed": False, "body": "<html><body>Welcome</body></html>",
}


# ---------- Parsing the output ----------


def test_httpx_output_gives_the_web_service_with_login_page_and_outdated_software():
    [service] = parse_httpx_output(json.dumps(DECOY))

    assert service == WebService(
        url="http://dev.badsecurityinc.be",
        host="dev.badsecurityinc.be",
        status=200,
        title="BadSecurityInc – Staging admin",
        server="nginx/1.18.0",
        technologies=["Nginx:1.18.0", "PHP:7.4.3"],
        login_page=True,
        outdated=["nginx 1.18", "PHP 7.4"],
    )


def test_a_current_website_has_no_login_page_and_nothing_outdated():
    [service] = parse_httpx_output(json.dumps(VERCEL))

    assert (service.login_page, service.outdated) == (False, [])


def test_failed_probes_and_garbage_are_skipped():
    output = "\n".join([json.dumps({"url": "https://x.be", "status_code": 0, "failed": True}), "not json", "{}", ""])

    assert parse_httpx_output(output) == []


@pytest.mark.parametrize(
    "body",
    [
        '<INPUT TYPE="PASSWORD">',
        "<input name=p type=password>",
        "<input class='a' type = 'password' />",
    ],
)
def test_a_password_field_is_found_however_it_is_written(body):
    [service] = parse_httpx_output(json.dumps({**VERCEL, "body": body}))

    assert service.login_page


@pytest.mark.parametrize("body", ["Forgot your password?", '<input type="text" name="password">'])
def test_the_word_password_alone_is_no_login_page(body):
    [service] = parse_httpx_output(json.dumps({**VERCEL, "body": body}))

    assert not service.login_page


@pytest.mark.parametrize(
    ("names", "expected"),
    [
        (["nginx/1.18.0"], ["nginx 1.18"]),
        (["nginx/1.26.2"], []),
        (["PHP:7.4.3"], ["PHP 7.4"]),
        (["PHP:8.1.2"], ["PHP 8.1"]),
        (["PHP:8.2.0"], []),
        (["Apache/2.2.34"], ["apache 2.2"]),
        (["Apache HTTP Server:2.4.58"], []),
        # The Server header and the detected technology name the same software: reported once
        (["nginx/1.18.0", "Nginx:1.18.0"], ["nginx 1.18"]),
        # Without a version nothing can be said
        (["nginx", "Vercel", "PHP"], []),
        ([""], []),
    ],
)
def test_outdated_software(names, expected):
    assert outdated_software(names) == expected


# ---------- The command ----------


def capture(monkeypatch, stdout=""):
    commands = []

    def run(command, **kwargs):
        commands.append((command, kwargs.get("input")))
        return web.subprocess.CompletedProcess(command, 0, stdout, "")

    monkeypatch.setattr(web.shutil, "which", lambda name: f"/usr/local/bin/{name}")
    monkeypatch.setattr(web.subprocess, "run", run)
    return commands


def test_httpx_only_visits_the_given_hosts_and_stays_on_them(monkeypatch):
    commands = capture(monkeypatch)

    web.probe(["www.badsecurityinc.be", "dev.badsecurityinc.be"])

    [(command, stdin)] = commands
    assert stdin == "www.badsecurityinc.be\ndev.badsecurityinc.be"
    # Redirects to another host are never followed (#66)
    assert "-follow-host-redirects" in command and "-follow-redirects" not in command
    # The default web ports and the start page only: no port list, no guessed paths
    assert not {"-p", "-ports", "-path", "-pa"} & set(command)
    assert "-duc" in command
    assert command[command.index("-rate-limit") + 1] == str(web.RATE_LIMIT)
    assert command[command.index("-r") + 1] == RESOLVERS


def test_missing_httpx_is_a_clear_error(monkeypatch):
    monkeypatch.setattr(web.shutil, "which", lambda name: None)

    with pytest.raises(RuntimeError, match="httpx is not installed"):
        web.probe(["www.badsecurityinc.be"])


def test_a_failing_httpx_is_a_clear_error(monkeypatch):
    monkeypatch.setattr(web.shutil, "which", lambda name: "/usr/local/bin/httpx")
    monkeypatch.setattr(
        web.subprocess, "run", lambda command, **kwargs: web.subprocess.CompletedProcess(command, 1, "", "boom\n")
    )

    with pytest.raises(RuntimeError, match="httpx failed: boom"):
        web.probe(["www.badsecurityinc.be"])


# ---------- The findings ----------


def fake_probe(monkeypatch, services=(), error=None):
    asked = []

    def probe(hosts):
        asked.extend(hosts)
        if error:
            raise error
        return list(services)

    monkeypatch.setattr(web, "probe", probe)
    return asked


def test_each_web_service_is_a_finding_with_title_status_and_technologies(monkeypatch):
    fake_probe(monkeypatch, parse_httpx_output(json.dumps(VERCEL)))
    context = ScanContext(domain=DOMAIN, live_hosts=LIVE_HOSTS)

    [finding] = web_findings(context)

    assert (finding.type, finding.asset, finding.severity) == (
        "web_service", "https://www.badsecurityinc.be", Severity.INFO,
    )
    assert finding.title == "Web service https://www.badsecurityinc.be (200): HSTS, Vercel"
    assert finding.details == {
        "host": "www.badsecurityinc.be",
        "status": 200,
        "page_title": "BadSecurityInc | Office IT for Belgian SMEs",
        "server": "Vercel",
        "technologies": ["HSTS", "Vercel"],
    }
    assert context.warnings == []


def test_the_decoy_gives_a_login_and_an_outdated_finding_next_to_the_web_service(monkeypatch):
    # One finding per entry of the ground truth: as-admin-login and as-outdated-server (#47)
    fake_probe(monkeypatch, parse_httpx_output(json.dumps(DECOY)))

    service, login, outdated = web_findings(ScanContext(domain=DOMAIN, live_hosts=LIVE_HOSTS))

    assert (service.severity, login.severity, outdated.severity) == (Severity.INFO, Severity.MEDIUM, Severity.MEDIUM)
    assert login.details["login_page"] is True and "outdated" not in login.details
    assert outdated.details["outdated"] is True and "login_page" not in outdated.details
    assert outdated.details["software"] == ["nginx 1.18", "PHP 7.4"]
    assert outdated.title == "Outdated software on http://dev.badsecurityinc.be: nginx 1.18, PHP 7.4"
    assert {f.asset for f in (service, login, outdated)} == {"http://dev.badsecurityinc.be"}


def test_the_page_itself_is_not_stored(monkeypatch):
    fake_probe(monkeypatch, parse_httpx_output(json.dumps(DECOY)))

    for finding in web_findings(ScanContext(domain=DOMAIN, live_hosts=LIVE_HOSTS)):
        assert LOGIN_PAGE not in json.dumps(finding.details)


def test_all_live_hosts_are_probed_also_those_without_a_port_scan_approval(monkeypatch):
    # A normal visit of the client's own host names, unlike the port scan of #81
    asked = fake_probe(monkeypatch)

    web_findings(ScanContext(domain=DOMAIN, live_hosts=LIVE_HOSTS))

    assert asked == ["www.badsecurityinc.be", "dev.badsecurityinc.be"]


def test_no_web_service_at_all_is_a_warning(monkeypatch):
    # httpx exits with 0 and prints nothing without network, captured in the worker image
    fake_probe(monkeypatch)
    context = ScanContext(domain=DOMAIN, live_hosts=LIVE_HOSTS)

    assert web_findings(context) == []
    assert context.warnings == [
        "No web service answered on 2 host(s): either they run no website, or the network "
        "QN-Sentry runs on blocks outgoing connections"
    ]


def test_a_failing_httpx_is_a_warning(monkeypatch):
    fake_probe(monkeypatch, error=RuntimeError("httpx did not finish within 600 s"))
    context = ScanContext(domain=DOMAIN, live_hosts=LIVE_HOSTS)

    assert web_findings(context) == []
    assert context.warnings == ["Web services could not be checked: httpx did not finish within 600 s"]


def test_no_hosts_is_no_probe_and_no_warning(monkeypatch):
    asked = fake_probe(monkeypatch)
    context = ScanContext(domain=DOMAIN)

    assert web_findings(context) == [] and asked == [] and context.warnings == []


def test_the_module_probes_its_own_live_hosts(monkeypatch):
    monkeypatch.setattr(
        "qnsentry.modules.attack_surface.discover", lambda domain, warn: [Host("www.badsecurityinc.be", ["76.76.21.21"])]
    )
    asked = fake_probe(monkeypatch, parse_httpx_output(json.dumps(VERCEL)))
    context = ScanContext(domain=DOMAIN)

    findings = AttackSurfaceModule().run(context)

    assert asked == ["www.badsecurityinc.be"]
    assert [f.type for f in findings] == ["subdomain", "web_service"]
    # The "not checked yet" warning is gone: the module is complete since #6
    assert context.warnings == ["1 address(es) were not port-scanned because they were not confirmed"]
