"""Published email addresses and the naming convention (issue #8)."""

import threading
from http.server import BaseHTTPRequestHandler, HTTPServer

import pytest

from qnsentry.db.models import Severity
from qnsentry.modules import metadata
from qnsentry.modules.base import ScanContext
from qnsentry.modules.metadata import MetadataModule, emails
from qnsentry.modules.metadata.emails import collect_emails, detect_convention, extract_emails, page_urls
from qnsentry.modules.names import JOINED, SEPARATED

DOMAIN = "badsecurityinc.be"
SITE = "https://www.badsecurityinc.be"

# The test website (testenv/website): the team page and the document authors
PUBLISHED = [
    "jan.peeters@badsecurityinc.be",
    "sofie.maes@badsecurityinc.be",
    "lars.janssens@badsecurityinc.be",
    "emma.claes@badsecurityinc.be",
    "tom.wouters@badsecurityinc.be",
    "lotte.vandenbroeck@badsecurityinc.be",
    "gerard.dubois@badsecurityinc.be",
    "info@badsecurityinc.be",
    "sales@badsecurityinc.be",
    "jobs@badsecurityinc.be",
    "helpdesk@badsecurityinc.be",
]
AUTHORS = ["Lotte Van den Broeck", "Gérard Dubois", "Lars Janssens", "Emma Claes", "Tom Wouters", "Pieter Mertens", "Sofie Maes"]


# ---------- Extracting addresses ----------


def test_addresses_from_mailto_links_and_text():
    page = """
        <a href="mailto:sofie.maes@badsecurityinc.be?subject=Hello">Sofie</a>
        <p>Questions? Mail Info@BadSecurityInc.be.</p>
        <a href="mailto:sofie.maes@badsecurityinc.be">again</a>
    """

    assert extract_emails(page, DOMAIN) == ["sofie.maes@badsecurityinc.be", "info@badsecurityinc.be"]


def test_html_entities_and_url_encoding_are_decoded():
    page = '<a href="mailto:jan.peeters%40badsecurityinc.be">jan.peeters&#64;badsecurityinc.be</a>'

    assert extract_emails(page, DOMAIN) == ["jan.peeters@badsecurityinc.be"]


def test_only_addresses_of_the_clients_domain_are_kept():
    page = "privacy@vercel.com, someone@notbadsecurityinc.be, it@mail.badsecurityinc.be, a@badsecurityinc.be"

    # A subdomain belongs to the client; a domain that only ends in the same letters does not
    assert extract_emails(page, DOMAIN) == ["it@mail.badsecurityinc.be", "a@badsecurityinc.be"]


def test_only_pages_of_the_site_are_fetched_each_once():
    urls = [
        f"{SITE}/team.html",
        "https://badsecurityinc.be/team.html",  # the same page on the other host
        f"{SITE}/",
        f"{SITE}",
        f"{SITE}/style.css",
        f"{SITE}/logo.png",
        f"{SITE}/files/budget-2026.xlsx",
        "https://cdn.example.net/page.html",
    ]

    assert page_urls(urls, {DOMAIN, f"www.{DOMAIN}"}) == [f"{SITE}/team.html", f"{SITE}/"]


# ---------- Detecting the convention ----------


def test_the_test_website_follows_first_last_with_joined_last_names():
    convention = detect_convention(AUTHORS, PUBLISHED, DOMAIN)

    assert convention.convention == "first.last"
    assert convention.last_name_style == JOINED
    # 6 of the 7 authors have a published address; Pieter Mertens is left for #12
    assert [name for name, _ in convention.evidence] == [
        "Lotte Van den Broeck", "Gérard Dubois", "Lars Janssens", "Emma Claes", "Tom Wouters", "Sofie Maes",
    ]
    assert ("Gérard Dubois", "gerard.dubois@badsecurityinc.be") in convention.evidence


def test_a_separated_last_name_is_learned():
    published = ["lotte.van.den.broeck@x.be", "jan.peeters@x.be"]

    convention = detect_convention(["Lotte Van den Broeck", "Jan Peeters"], published, "x.be")

    assert (convention.convention, convention.last_name_style) == ("first.last", SEPARATED)


def test_without_a_last_name_of_several_words_the_style_is_unknown():
    convention = detect_convention(["Jan Peeters", "Sofie Maes"], ["jan.peeters@x.be", "sofie.maes@x.be"], "x.be")

    assert convention.last_name_style is None


@pytest.mark.parametrize(
    ("published", "expected"),
    [
        (["jpeeters@x.be", "smaes@x.be"], "flast"),
        (["peeters.jan@x.be", "maes.sofie@x.be"], "last.first"),
        (["jan@x.be", "sofie@x.be"], "first"),
        (["jan_peeters@x.be", "sofie_maes@x.be"], "first_last"),
    ],
)
def test_other_conventions(published, expected):
    assert detect_convention(["Jan Peeters", "Sofie Maes"], published, "x.be").convention == expected


def test_one_match_is_not_enough():
    # One name that happens to match could be chance (contract 10.4.3: at least two)
    assert detect_convention(["Jan Peeters", "Sofie Maes"], ["jan.peeters@x.be", "info@x.be"], "x.be") is None


def test_no_names_or_no_addresses_give_no_convention():
    assert detect_convention([], PUBLISHED, DOMAIN) is None
    assert detect_convention(AUTHORS, [], DOMAIN) is None


def test_addresses_of_another_domain_do_not_count():
    assert detect_convention(["Jan Peeters", "Sofie Maes"], ["jan.peeters@other.be", "sofie.maes@other.be"], "x.be") is None


def test_the_most_matching_convention_wins():
    published = ["jan.peeters@x.be", "sofie.maes@x.be", "lars.janssens@x.be", "tom@x.be", "emma@x.be"]

    names = ["Jan Peeters", "Sofie Maes", "Lars Janssens", "Tom Wouters", "Emma Claes"]

    assert detect_convention(names, published, "x.be").convention == "first.last"


# ---------- Fetching pages ----------


@pytest.fixture
def site():
    """The client on 127.0.0.1 and a third party on localhost (see test_metadata_redirects.py)."""
    third_party_requests = []

    class ThirdParty(BaseHTTPRequestHandler):
        def do_GET(self):
            third_party_requests.append(self.path)
            self.send_response(200)
            self.send_header("Content-Type", "text/html")
            self.end_headers()
            self.wfile.write(b"stolen@badsecurityinc.be")

        def log_message(self, *args):
            pass

    third_party = HTTPServer(("127.0.0.1", 0), ThirdParty)
    other = f"http://localhost:{third_party.server_port}"

    class Client(BaseHTTPRequestHandler):
        def do_GET(self):
            if self.path == "/away.html":
                self.send_response(302)
                self.send_header("Location", f"{other}/page.html")
                self.end_headers()
                return
            if self.path == "/broken.html":
                self.send_response(500)
                self.end_headers()
                return
            self.send_response(200)
            if self.path == "/api/data":
                self.send_header("Content-Type", "application/json")
                self.end_headers()
                self.wfile.write(b'{"mail": "api@badsecurityinc.be"}')
                return
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.end_headers()
            self.wfile.write(b'<a href="mailto:jan.peeters@badsecurityinc.be">Jan</a> info@badsecurityinc.be')

        def log_message(self, *args):
            pass

    client = HTTPServer(("127.0.0.1", 0), Client)
    for server in (client, third_party):
        threading.Thread(target=server.serve_forever, daemon=True).start()
    yield f"http://127.0.0.1:{client.server_port}", third_party_requests
    for server in (client, third_party):
        server.shutdown()
        server.server_close()


def test_addresses_are_collected_with_their_pages(site, monkeypatch):
    base, third_party_requests = site
    monkeypatch.setattr(emails, "SECONDS_BETWEEN_PAGES", 0)
    warnings = []

    found = collect_emails(
        [f"{base}/team.html", f"{base}/contact.html", f"{base}/away.html", f"{base}/api/data", f"{base}/broken.html"],
        {"127.0.0.1"},
        DOMAIN,
        warn=warnings.append,
    )

    assert found == {
        "jan.peeters@badsecurityinc.be": [f"{base}/team.html", f"{base}/contact.html"],
        "info@badsecurityinc.be": [f"{base}/team.html", f"{base}/contact.html"],
    }
    # A redirect to another host is refused before it is followed (#66); /api/data answers JSON, not HTML
    assert third_party_requests == []
    assert warnings == ["1 of 5 page(s) could not be loaded, so email addresses on them may have been missed"]


def test_the_page_limit_is_a_warning(monkeypatch):
    monkeypatch.setattr(emails, "fetch_page", lambda url, hosts: "")
    monkeypatch.setattr(emails, "SECONDS_BETWEEN_PAGES", 0)
    warnings = []

    collect_emails([f"{SITE}/{i}.html" for i in range(emails.MAX_PAGES + 3)], {f"www.{DOMAIN}"}, DOMAIN, warn=warnings.append)

    assert warnings == [f"Only the first {emails.MAX_PAGES} of {emails.MAX_PAGES + 3} pages were checked for email addresses"]


# ---------- The module ----------


def test_module_fills_the_context_and_reports_addresses_and_convention(monkeypatch):
    def fake_analysis(urls, folder, hosts, warn):
        return {}

    monkeypatch.setattr(metadata, "crawl", lambda urls, warn: [f"{SITE}/team.html"])
    monkeypatch.setattr(metadata, "download_documents", fake_analysis)
    monkeypatch.setattr(metadata, "read_metadata", lambda paths: {})
    monkeypatch.setattr(metadata, "collect_emails", lambda urls, hosts, domain, warn: {a: [f"{SITE}/team.html"] for a in PUBLISHED})
    # The authors come from the documents; here they are already in the context
    context = ScanContext(domain=DOMAIN, person_names=list(AUTHORS))

    findings = MetadataModule().run(context)

    assert context.emails == PUBLISHED
    assert (context.email_convention, context.last_name_style) == ("first.last", JOINED)
    by_type = {f.type: f for f in findings}
    assert by_type["email_address"].severity == Severity.INFO
    assert by_type["email_address"].title == "11 email addresses of badsecurityinc.be are published on the website"
    assert by_type["email_convention"].severity == Severity.LOW
    assert by_type["email_convention"].title == "Email addresses of badsecurityinc.be follow the pattern first.last"
    assert by_type["email_convention"].details["names_checked"] == 7


def test_no_addresses_give_no_findings_and_no_convention(monkeypatch):
    monkeypatch.setattr(metadata, "crawl", lambda urls, warn: [f"{SITE}/index.html"])
    monkeypatch.setattr(metadata, "download_documents", lambda urls, folder, hosts, warn: {})
    monkeypatch.setattr(metadata, "read_metadata", lambda paths: {})
    monkeypatch.setattr(metadata, "collect_emails", lambda urls, hosts, domain, warn: {})
    context = ScanContext(domain=DOMAIN, person_names=list(AUTHORS))

    assert MetadataModule().run(context) == []
    assert context.email_convention is None
