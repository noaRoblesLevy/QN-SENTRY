"""Redirects never make the Metadata module contact another host (issue #66).

The legal framework (5.2) promises that only the client's own website is contacted.
These tests use two local HTTP servers: "the client" on 127.0.0.1 and "a third party" on
localhost. They are the same machine but different host names, which is all the
host check looks at, so no network or second address is needed.
"""

import json
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer

import pytest

from qnsentry.modules.metadata import crawler, documents


@pytest.fixture
def servers():
    """A client site and a third party; returns their base URLs and the third party's requests."""
    third_party_requests = []

    class ThirdParty(BaseHTTPRequestHandler):
        def do_GET(self):
            third_party_requests.append(self.path)
            self.send_response(200)
            self.end_headers()
            self.wfile.write(b"%PDF-1.4 third party")

        def log_message(self, *args):
            pass

    third_party = HTTPServer(("127.0.0.1", 0), ThirdParty)
    other = f"http://localhost:{third_party.server_port}"

    class Client(BaseHTTPRequestHandler):
        def do_GET(self):
            redirects = {"/moved.pdf": f"{other}/moved.pdf", "/old.pdf": "/new.pdf"}
            if self.path in redirects:
                self.send_response(302)
                self.send_header("Location", redirects[self.path])
                self.end_headers()
                return
            self.send_response(200)
            self.end_headers()
            self.wfile.write(b"%PDF-1.4 " + self.path.encode())

        def log_message(self, *args):
            pass

    client = HTTPServer(("127.0.0.1", 0), Client)
    for server in (client, third_party):
        threading.Thread(target=server.serve_forever, daemon=True).start()
    yield f"http://127.0.0.1:{client.server_port}", third_party_requests
    for server in (client, third_party):
        server.shutdown()
        server.server_close()


def test_redirect_to_another_host_is_refused_before_it_is_followed(servers, tmp_path):
    site, third_party_requests = servers

    reason = documents.download(f"{site}/moved.pdf", tmp_path / "moved.pdf", {"127.0.0.1"})

    assert reason == documents.OFF_HOST_REASON
    assert third_party_requests == []
    assert not (tmp_path / "moved.pdf").exists()


def test_redirect_within_the_site_is_followed(servers, tmp_path):
    site, third_party_requests = servers

    assert documents.download(f"{site}/old.pdf", tmp_path / "old.pdf", {"127.0.0.1"}) is None
    assert (tmp_path / "old.pdf").read_bytes() == b"%PDF-1.4 /new.pdf"
    assert third_party_requests == []


def test_off_host_redirect_is_counted_as_a_warning(servers, tmp_path):
    site, third_party_requests = servers
    warnings = []

    downloaded = documents.download_documents(
        [f"{site}/moved.pdf", f"{site}/old.pdf"], tmp_path, {"127.0.0.1"}, warn=warnings.append
    )

    assert list(downloaded) == [f"{site}/old.pdf"]
    assert warnings == ["1 of 2 document(s) were skipped because they redirect to another website"]
    assert third_party_requests == []


# ---------- The crawler: katana never follows redirects, same-host ones are crawled next ----------

SITE = "https://www.badsecurityinc.be"


def entry(endpoint, status=200, location=None):
    headers = {"Location": location} if location else {}
    return json.dumps({"request": {"endpoint": endpoint}, "response": {"status_code": status, "headers": headers}})


def fake_katana(monkeypatch, pages):
    """katana that answers with pages[start URLs]; returns the start URLs of every run."""
    runs = []

    def run(command, **kwargs):
        urls = command[command.index("-u") + 1]
        runs.append(urls)
        return crawler.subprocess.CompletedProcess(command, 0, "\n".join(pages.get(urls, [])), "")

    monkeypatch.setattr(crawler.shutil, "which", lambda name: "/usr/local/bin/katana")
    monkeypatch.setattr(crawler.subprocess, "run", run)
    return runs


def test_katana_never_follows_redirects_and_reports_all_of_them(monkeypatch):
    commands = []

    def run(command, **kwargs):
        commands.append(command)
        return crawler.subprocess.CompletedProcess(command, 0, entry(SITE), "")

    monkeypatch.setattr(crawler.shutil, "which", lambda name: "/usr/local/bin/katana")
    monkeypatch.setattr(crawler.subprocess, "run", run)

    crawler.crawl([SITE])

    assert "-disable-redirects" in commands[0]
    # Without it katana drops redirects with the same (empty) body: only one would be reported
    assert "-disable-unique-filter" in commands[0]


def test_a_redirect_within_the_site_is_crawled_in_a_next_round(monkeypatch):
    runs = fake_katana(
        monkeypatch,
        {
            SITE: [entry(SITE, 302, "/nl/")],
            f"{SITE}/nl/": [entry(f"{SITE}/nl/"), entry(f"{SITE}/nl/files/budget-2026.xlsx")],
        },
    )

    found = crawler.crawl([SITE])

    assert runs == [SITE, f"{SITE}/nl/"]
    assert f"{SITE}/nl/files/budget-2026.xlsx" in found


def test_a_redirect_to_another_host_is_never_crawled(monkeypatch):
    runs = fake_katana(
        monkeypatch,
        {SITE: [entry(SITE), entry(f"{SITE}/shop", 301, "https://shop.example.com/"), entry(f"{SITE}/a.pdf", 302, "https://cdn.example.net/a.pdf")]},
    )

    found = crawler.crawl([SITE])

    assert runs == [SITE]
    # The redirecting document is kept: the downloader refuses its redirect before following it
    assert f"{SITE}/a.pdf" in crawler.document_urls(found, {"www.badsecurityinc.be"})


def test_a_document_behind_a_redirect_is_left_to_the_downloader(monkeypatch):
    runs = fake_katana(monkeypatch, {SITE: [entry(SITE), entry(f"{SITE}/old.pdf", 302, "/new.pdf")]})

    found = crawler.crawl([SITE])

    assert runs == [SITE]
    assert f"{SITE}/old.pdf" in found


def test_redirect_rounds_are_limited(monkeypatch):
    # Every page redirects to the next one: the crawl stops after MAX_REDIRECT_ROUNDS extra rounds
    pages = {f"{SITE}/{i}": [entry(f"{SITE}/{i}", 302, f"/{i + 1}")] for i in range(10)}
    runs = fake_katana(monkeypatch, pages)

    crawler.crawl([f"{SITE}/0"])

    assert len(runs) == 1 + crawler.MAX_REDIRECT_ROUNDS


def test_a_redirect_loop_is_crawled_once(monkeypatch):
    runs = fake_katana(
        monkeypatch,
        {SITE: [entry(SITE, 302, "/nl/")], f"{SITE}/nl/": [entry(f"{SITE}/nl/", 302, SITE)]},
    )

    crawler.crawl([SITE])

    assert runs == [SITE, f"{SITE}/nl/"]


def test_redirect_targets_are_made_absolute():
    output = "\n".join(
        [
            entry(SITE),
            entry(f"{SITE}/docs", 301, "/docs/"),
            entry(f"{SITE}/a/b", 302, "../c"),
            json.dumps({"request": {"endpoint": f"{SITE}/x"}, "response": {"status_code": 307, "headers": {"location": "/y"}}}),
            "not json",
        ]
    )

    assert crawler.redirect_targets(output) == [f"{SITE}/docs/", f"{SITE}/c", f"{SITE}/y"]


def test_the_same_document_on_both_hosts_is_downloaded_once():
    # Without katana's content filter both badsecurityinc.be and www. are crawled fully
    urls = [
        "https://badsecurityinc.be/files/budget-2026.xlsx",
        "https://www.badsecurityinc.be/files/budget-2026.xlsx",
        "https://www.badsecurityinc.be/files/budget-2026.xlsx?v=2",
        "https://www.badsecurityinc.be/files/other.pdf",
    ]

    assert crawler.document_urls(urls, {"badsecurityinc.be", "www.badsecurityinc.be"}) == [
        "https://badsecurityinc.be/files/budget-2026.xlsx",
        "https://www.badsecurityinc.be/files/budget-2026.xlsx?v=2",
        "https://www.badsecurityinc.be/files/other.pdf",
    ]
