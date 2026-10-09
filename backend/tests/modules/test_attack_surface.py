"""Attack Surface: subdomains from passive sources, resolved to IP addresses (issue #4)."""

import json

import pytest

from qnsentry.db.models import Severity
from qnsentry.modules import MODULES, MODULES_BY_NAME
from qnsentry.modules.attack_surface import AttackSurfaceModule, subdomains
from qnsentry.modules.attack_surface.subdomains import Host, discover, parse_dnsx_output, parse_subfinder_output
from qnsentry.modules.base import ScanContext

DOMAIN = "badsecurityinc.be"


def dnsx_line(host, a=(), aaaa=(), cname=(), status="NOERROR"):
    return json.dumps({"host": host, "a": list(a), "aaaa": list(aaaa), "cname": list(cname), "status_code": status})


# ---------- Parsing the tools' output ----------


def test_subfinder_output_keeps_names_of_the_domain_with_their_sources():
    output = "\n".join(
        [
            json.dumps({"host": "WWW.badsecurityinc.be", "sources": ["crtname", "shodanct"]}),
            json.dumps({"host": "www.badsecurityinc.be", "source": "scanmalware"}),
            json.dumps({"host": "dev.badsecurityinc.be.", "sources": ["crtsh"]}),
            json.dumps({"host": "*.badsecurityinc.be", "sources": ["crtsh"]}),  # a wildcard certificate name
            json.dumps({"host": "badsecurityinc.be.evil.example", "sources": ["x"]}),  # not under the domain
            json.dumps({"host": "notbadsecurityinc.be", "sources": ["x"]}),
            "not json",
            "",
        ]
    )

    assert parse_subfinder_output(output, DOMAIN) == {
        "www.badsecurityinc.be": ["crtname", "shodanct", "scanmalware"],
        "dev.badsecurityinc.be": ["crtsh"],
    }


def test_dnsx_output_gives_addresses_and_cnames_of_names_that_resolve():
    output = "\n".join(
        [
            dnsx_line("www.badsecurityinc.be", a=["76.76.21.21"], cname=["cname.vercel-dns.com."]),
            dnsx_line("dev.badsecurityinc.be", a=["192.0.2.10"], aaaa=["2001:db8::10"]),
            dnsx_line("gone.badsecurityinc.be", status="NXDOMAIN"),
            dnsx_line("dangling.badsecurityinc.be", cname=["old-service.example."]),  # reaches no server
            "garbage",
        ]
    )

    hosts = parse_dnsx_output(output)

    assert set(hosts) == {"www.badsecurityinc.be", "dev.badsecurityinc.be"}
    assert hosts["www.badsecurityinc.be"].cname == ["cname.vercel-dns.com"]
    assert hosts["dev.badsecurityinc.be"].ips == ["192.0.2.10", "2001:db8::10"]


# ---------- Discovery ----------


def fake_tools(monkeypatch, passive=None, resolved=None, passive_error=None, failed_sources=(), failed_lookups=0):
    """passive: {name: sources}; resolved: {name: [ips]}; returns the names given to dnsx."""
    asked = []

    def fake_passive(domain):
        if passive_error:
            raise passive_error
        return dict(passive or {}), list(failed_sources)

    def fake_resolve(names):
        asked.extend(names)
        resolved_ips = resolved or {}
        def ips_for(name):
            if name in resolved_ips:
                return resolved_ips[name]
            # The wildcard probe: a random name under the domain
            return resolved_ips.get("*")
        hosts = {name: Host(name, list(ips_for(name))) for name in names if ips_for(name)}
        return hosts, failed_lookups

    monkeypatch.setattr(subdomains, "passive_subdomains", fake_passive)
    monkeypatch.setattr(subdomains, "resolve", fake_resolve)
    return asked


def test_the_domain_and_www_are_always_checked(monkeypatch):
    asked = fake_tools(monkeypatch, passive={"dev.badsecurityinc.be": ["crtsh"]})

    discover(DOMAIN)

    assert asked[:3] == ["badsecurityinc.be", "www.badsecurityinc.be", "dev.badsecurityinc.be"]
    # The last name is the random wildcard probe
    assert asked[3].startswith("qnsentry-wildcard-") and asked[3].endswith(f".{DOMAIN}")


def test_only_names_that_resolve_are_live_hosts_with_their_sources(monkeypatch):
    fake_tools(
        monkeypatch,
        passive={"www.badsecurityinc.be": ["crtname"], "old.badsecurityinc.be": ["crtsh"]},
        resolved={"badsecurityinc.be": ["76.76.21.21"], "www.badsecurityinc.be": ["76.76.21.21"]},
    )

    hosts = discover(DOMAIN)

    assert [h.name for h in hosts] == ["badsecurityinc.be", "www.badsecurityinc.be"]
    assert hosts[1].sources == ["crtname"]


def test_names_that_only_resolve_through_a_wildcard_are_left_out(monkeypatch):
    # *.example.be makes every name resolve: a name pointing to the same address is no real host
    fake_tools(
        monkeypatch,
        passive={"stale.badsecurityinc.be": ["shodanct"], "dev.badsecurityinc.be": ["crtsh"]},
        resolved={"*": ["198.51.100.1"], "badsecurityinc.be": ["198.51.100.1"], "dev.badsecurityinc.be": ["192.0.2.10"]},
    )
    warnings = []

    hosts = discover(DOMAIN, warn=warnings.append)

    # The domain itself is kept; dev points elsewhere, so it is a real host
    assert [h.name for h in hosts] == ["badsecurityinc.be", "dev.badsecurityinc.be"]
    assert warnings == [
        "badsecurityinc.be has a wildcard DNS record: 2 name(s) that only resolve through it were left out"
    ]


def test_failing_passive_sources_still_check_the_domain_and_www(monkeypatch):
    fake_tools(
        monkeypatch,
        passive_error=RuntimeError("subfinder did not finish within 180 s"),
        resolved={"badsecurityinc.be": ["76.76.21.21"], "www.badsecurityinc.be": ["76.76.21.21"]},
    )
    warnings = []

    hosts = discover(DOMAIN, warn=warnings.append)

    assert [h.name for h in hosts] == ["badsecurityinc.be", "www.badsecurityinc.be"]
    assert warnings == ["Passive sources could not be searched for subdomains: subfinder did not finish within 180 s"]


def test_too_many_subdomains_is_a_warning(monkeypatch):
    many = {f"h{i}.badsecurityinc.be": ["crtsh"] for i in range(subdomains.MAX_SUBDOMAINS + 5)}
    asked = fake_tools(monkeypatch, passive=many)
    warnings = []

    discover(DOMAIN, warn=warnings.append)

    # The domain, www, the first MAX_SUBDOMAINS names (sorted, so stable between scans) and the probe
    assert len(asked) == subdomains.MAX_SUBDOMAINS + 3
    assert asked[2:-1] == sorted(many)[: subdomains.MAX_SUBDOMAINS]
    assert warnings == [
        f"Only the first {subdomains.MAX_SUBDOMAINS} of {subdomains.MAX_SUBDOMAINS + 5} subdomains from passive sources were checked"
    ]


def test_failing_resolution_fails_the_module(monkeypatch):
    # Without DNS nothing was checked: reporting "no subdomains" would look like a clean result
    monkeypatch.setattr(subdomains, "passive_subdomains", lambda domain: ({}, []))

    def broken(names):
        raise RuntimeError("dnsx failed: no resolvers reachable")

    monkeypatch.setattr(subdomains, "resolve", broken)

    with pytest.raises(RuntimeError, match="dnsx failed"):
        AttackSurfaceModule().run(ScanContext(domain=DOMAIN))


# ---------- The commands ----------


def capture(monkeypatch, stdout=""):
    commands = []

    def run(command, **kwargs):
        commands.append((command, kwargs.get("input")))
        return subdomains.subprocess.CompletedProcess(command, 0, stdout, "")

    monkeypatch.setattr(subdomains.shutil, "which", lambda name: f"/usr/local/bin/{name}")
    monkeypatch.setattr(subdomains.subprocess, "run", run)
    return commands


def test_subfinder_is_passive_and_never_checks_for_updates(monkeypatch):
    commands = capture(monkeypatch)

    subdomains.passive_subdomains(DOMAIN)

    [(command, _)] = commands
    assert command[:3] == ["subfinder", "-d", DOMAIN]
    assert "-duc" in command
    # Verbose, because only then subfinder logs the sources that failed
    assert "-v" in command and "-silent" not in command
    # No active techniques: no brute force wordlist, no recursion into found names
    assert not {"-w", "-wordlist", "-recursive", "-active"} & set(command)


def test_dnsx_uses_public_resolvers_and_reads_names_from_stdin(monkeypatch):
    commands = capture(monkeypatch)

    subdomains.resolve(["badsecurityinc.be", "www.badsecurityinc.be"])

    [(command, stdin)] = commands
    assert command[command.index("-r") + 1] == subdomains.RESOLVERS
    assert "-duc" in command
    assert "-cdn" in command  # from address ranges, for the port scan (#5)
    assert stdin == "badsecurityinc.be\nwww.badsecurityinc.be"


@pytest.mark.parametrize("tool", ["subfinder", "dnsx"])
def test_missing_tool_is_a_clear_error(monkeypatch, tool):
    monkeypatch.setattr(subdomains.shutil, "which", lambda name: None)
    function = subdomains.passive_subdomains if tool == "subfinder" else subdomains.resolve

    with pytest.raises(RuntimeError, match=f"{tool} is not installed"):
        function(DOMAIN if tool == "subfinder" else [DOMAIN])


# ---------- The module ----------


def test_module_reports_subdomains_and_fills_the_context(monkeypatch):
    fake_tools(
        monkeypatch,
        passive={"www.badsecurityinc.be": ["crtname"]},
        resolved={"badsecurityinc.be": ["76.76.21.21"], "www.badsecurityinc.be": ["76.76.21.21"]},
    )
    context = ScanContext(domain=DOMAIN)

    findings = AttackSurfaceModule().run(context)

    # The domain itself is the scanned domain, not a discovered subdomain
    [finding] = findings
    assert (finding.type, finding.asset, finding.severity) == ("subdomain", "www.badsecurityinc.be", Severity.INFO)
    assert finding.title == "Subdomain www.badsecurityinc.be resolves to 76.76.21.21"
    assert finding.details == {"ips": ["76.76.21.21"], "cname": [], "sources": ["crtname"], "cdn": None}
    assert context.live_hosts == [
        {"name": "badsecurityinc.be", "ips": ["76.76.21.21"], "cdn": None},
        {"name": "www.badsecurityinc.be", "ips": ["76.76.21.21"], "cdn": None},
    ]
    # Nothing approved, so no port scan (#5, #81); until #6 the module says it is not complete
    assert context.warnings == [
        "1 address(es) were not port-scanned because they were not confirmed",
        "Web services are not checked yet in this version of QN-Sentry",
    ]


def test_many_addresses_are_shortened_in_the_title(monkeypatch):
    ips = [f"192.0.2.{i}" for i in range(1, 6)]
    fake_tools(monkeypatch, passive={"cdn.badsecurityinc.be": ["crtsh"]}, resolved={"cdn.badsecurityinc.be": ips})

    [finding] = AttackSurfaceModule().run(ScanContext(domain=DOMAIN))

    assert finding.title == "Subdomain cdn.badsecurityinc.be resolves to 192.0.2.1, 192.0.2.2, 192.0.2.3 and 2 more"


def test_attack_surface_module_replaces_the_placeholder():
    assert isinstance(MODULES_BY_NAME["attack_surface"], AttackSurfaceModule)
    assert MODULES[0].name == "attack_surface"  # first: later modules can use its hosts


# ---------- Failures the tools only report on stderr (review of #79) ----------

# Captured from the worker image in a container without network (--network none)
DNSX_OFFLINE = "[WRN] 3 domains failed to resolve (consider increasing -retry or reducing -threads)\n"
SUBFINDER_OFFLINE = "\n".join(
    f"[WRN] Encountered an error with source {source}: dial tcp: lookup failed"
    for source in ["crtsh", "crtname", "scanmalware", "crtsh", "hackertarget"]
)


def test_the_failure_lines_are_read_from_stderr():
    assert subdomains.failed_lookups(DNSX_OFFLINE) == 3
    assert subdomains.failed_lookups("[WRN] 1 domain failed to resolve") == 1
    assert subdomains.failed_lookups("") == 0
    assert subdomains.failed_sources(SUBFINDER_OFFLINE) == ["crtname", "crtsh", "hackertarget", "scanmalware"]


def test_no_dns_fails_the_module_instead_of_reporting_no_hosts(monkeypatch):
    # Reviewer's probe: without network both tools exit with 0 and find nothing
    fake_tools(monkeypatch, failed_sources=["crtsh", "crtname"], failed_lookups=3)

    with pytest.raises(RuntimeError, match="could not be looked up: 3 DNS lookup"):
        AttackSurfaceModule().run(ScanContext(domain=DOMAIN))


def test_some_failed_lookups_are_a_warning(monkeypatch):
    fake_tools(
        monkeypatch,
        passive={"www.badsecurityinc.be": ["crtname"]},
        resolved={"badsecurityinc.be": ["76.76.21.21"]},
        failed_lookups=1,
    )
    warnings = []

    hosts = discover(DOMAIN, warn=warnings.append)

    assert [h.name for h in hosts] == ["badsecurityinc.be"]
    assert warnings == ["1 DNS lookup(s) failed, so hosts of badsecurityinc.be may be missing"]


def test_nothing_found_while_sources_failed_is_a_warning(monkeypatch):
    fake_tools(monkeypatch, resolved={"badsecurityinc.be": ["76.76.21.21"]}, failed_sources=["crtsh", "leakix"])
    warnings = []

    discover(DOMAIN, warn=warnings.append)

    assert warnings == [
        "No subdomains were found in passive sources, and 2 source(s) could not be searched "
        "(crtsh, leakix), so subdomains may be missing"
    ]


def test_a_few_failing_sources_are_normal_when_names_were_found(monkeypatch):
    # Online, some sources always fail (an API down or wanting a key): no warning then
    fake_tools(
        monkeypatch,
        passive={"www.badsecurityinc.be": ["crtname"]},
        resolved={"badsecurityinc.be": ["76.76.21.21"], "www.badsecurityinc.be": ["76.76.21.21"]},
        failed_sources=["crtsh", "digitorus", "driftnet", "leakix", "reconeer", "submd"],
    )
    warnings = []

    discover(DOMAIN, warn=warnings.append)

    assert warnings == []
