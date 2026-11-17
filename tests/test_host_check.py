"""The server answers only to the names it is reached by on this machine.

DNS rebinding: a page on rebind.evil.example is loaded from the attacker's
server, then the name is made to resolve to 127.0.0.1. The browser keeps
treating the page and every request it sends to rebind.evil.example:8000 as one
origin, so it says `Sec-Fetch-Site: same-origin`, sets `Origin` equal to `Host`,
and reads the answers. The server never looked at `Host`: the write guard passed
and the watchlist — the software installed and its versions — was served.
Found by the bug hunt of 2026-11-17 against origin/main at ad348ad.

The ASGI scope's `server` is the address the connection arrived on: uvicorn
fills it from the socket, httpx's ASGITransport from the URL, so a base URL of
http://localhost:8000 is a server bound on port 8000.
"""
import re
from pathlib import Path

import pytest
from httpx import ASGITransport, AsyncClient

from patchradar.api import main as api
from patchradar.db import database

FOREIGN = "rebind.evil.example:8000"
# The setting, by the name the documentation gives it.
ALLOWED_HOSTS_ENV = "PATCHRADAR_ALLOWED_HOSTS"


async def _request(method: str, path: str, headers: dict | None = None,
                   base_url: str = "http://localhost:8000"):
    async with AsyncClient(transport=ASGITransport(app=api.app), base_url=base_url) as ac:
        return await ac.request(method, path, headers=headers or {})


@pytest.fixture(autouse=True)
def no_configured_hosts(monkeypatch):
    monkeypatch.delenv(ALLOWED_HOSTS_ENV, raising=False)


# ─── A name the server does not answer to ────────────────────────────────────

@pytest.mark.asyncio
@pytest.mark.parametrize("path", [
    "/api/watchlist", "/api/cves", "/api/stats", "/api/cves/CVE-2026-0001",
    "/", "/static/app.js", "/health",
])
async def test_a_read_for_a_foreign_host_is_refused(path):
    await database.add_to_watchlist("secretapp")
    r = await _request("GET", path, {"Host": FOREIGN})
    assert r.status_code == 421
    assert "secretapp" not in r.text


@pytest.mark.asyncio
@pytest.mark.parametrize("method, path", [
    ("POST", "/api/watchlist/rebound"),
    ("POST", "/api/scan"),
    ("DELETE", "/api/watchlist/nginx"),
])
async def test_a_write_for_a_foreign_host_is_refused_even_when_it_says_same_origin(
        unreachable_network, method, path):
    await database.add_to_watchlist("nginx")
    r = await _request(method, path, {"Host": FOREIGN, "Sec-Fetch-Site": "same-origin"})
    assert r.status_code == 421
    assert await database.get_watchlist() == ["nginx"]


@pytest.mark.asyncio
async def test_an_origin_equal_to_a_foreign_host_is_refused():
    """A browser without Fetch Metadata: Origin was compared with the request's own Host."""
    r = await _request("POST", "/api/watchlist/rebound",
                       {"Host": FOREIGN, "Origin": f"http://{FOREIGN}"})
    assert r.status_code == 421
    assert await database.get_watchlist() == []


@pytest.mark.asyncio
async def test_a_loopback_name_on_another_port_is_refused():
    """The browser puts the port it connected to in Host; another one arrived
    through something in between, which has to be named."""
    r = await _request("GET", "/api/watchlist", {"Host": "localhost:9000"})
    assert r.status_code == 421


@pytest.mark.asyncio
@pytest.mark.parametrize("host", [
    "", "localhost:99999", "localhost:80@evil.example", "evil.example/x",
    # brackets around what is not an IPv6 address: urlsplit raises on them
    "[1.2]", "[1.2.3.4]:8000", "[:::]",
])
async def test_a_host_that_is_not_one_is_a_bad_request(host):
    async with AsyncClient(transport=ASGITransport(app=api.app, raise_app_exceptions=False),
                           base_url="http://localhost:8000") as ac:
        r = await ac.get("/api/watchlist", headers={"Host": host})
    assert r.status_code == 400


@pytest.mark.asyncio
async def test_a_request_without_host_is_a_bad_request():
    """HTTP/1.1 requires Host (RFC 9112, 3.2). Sent straight to the ASGI app,
    since an HTTP client always adds one."""
    sent: list[dict] = []

    async def receive():
        return {"type": "http.request", "body": b"", "more_body": False}

    async def send(message):
        sent.append(message)

    scope = {"type": "http", "asgi": {"version": "3.0"}, "http_version": "1.1", "method": "GET",
             "scheme": "http", "path": "/api/watchlist", "raw_path": b"/api/watchlist",
             "root_path": "", "query_string": b"", "headers": [],
             "server": ("127.0.0.1", 8000), "client": ("127.0.0.1", 50000)}
    await api.app(scope, receive, send)
    assert sent[0]["status"] == 400


# ─── The names it does answer to ─────────────────────────────────────────────

@pytest.mark.asyncio
@pytest.mark.parametrize("host", [
    "localhost", "localhost:8000", "LOCALHOST:8000",
    "127.0.0.1", "127.0.0.1:8000", "[::1]", "[::1]:8000",
])
async def test_the_loopback_names_are_served(host):
    await database.add_to_watchlist("nginx")
    r = await _request("GET", "/api/watchlist", {"Host": host})
    assert r.status_code == 200
    assert r.json()["watchlist"] == ["nginx"]


@pytest.mark.asyncio
@pytest.mark.parametrize("host", ["localhost:8000", "127.0.0.1:8000", "[::1]:8000"])
async def test_the_ui_writes_through_each_loopback_name(unreachable_network, host):
    """What the bundled UI sends: same-origin, Origin equal to the address bar."""
    r = await _request("POST", "/api/watchlist/nginx",
                       {"Host": host, "Origin": f"http://{host}", "Sec-Fetch-Site": "same-origin"})
    assert r.status_code == 200
    assert await database.get_watchlist() == ["nginx"]


@pytest.mark.asyncio
async def test_the_address_the_connection_arrived_on_is_served():
    """`patchradar serve --host 0.0.0.0` opened from another machine as
    http://192.168.1.10:8000: an address, which no DNS answer can rebind."""
    r = await _request("GET", "/api/watchlist", {"Host": "192.168.1.10:8000"},
                       base_url="http://192.168.1.10:8000")
    assert r.status_code == 200


@pytest.mark.asyncio
async def test_a_name_is_not_trusted_because_the_connection_was_made_to_it():
    """httpx's ASGITransport fills `server` from the URL, so here it holds the
    foreign name; uvicorn always gives an address there. A name is never taken
    from it."""
    r = await _request("GET", "/api/watchlist", base_url=f"http://{FOREIGN}")
    assert r.status_code == 421


# ─── Names the operator adds ─────────────────────────────────────────────────

@pytest.mark.asyncio
@pytest.mark.parametrize("host", ["patchradar.lan", "patchradar.lan:8000", "PatchRadar.LAN:9999",
                                  "proxy.example:8443"])
async def test_a_configured_host_is_served(monkeypatch, host):
    monkeypatch.setenv(ALLOWED_HOSTS_ENV, " patchradar.lan , proxy.example:8443,")
    r = await _request("GET", "/api/watchlist", {"Host": host})
    assert r.status_code == 200


@pytest.mark.asyncio
@pytest.mark.parametrize("host", ["proxy.example:9", "proxy.example", "other.lan:8000"])
async def test_a_configured_port_is_the_only_one(monkeypatch, host):
    monkeypatch.setenv(ALLOWED_HOSTS_ENV, "proxy.example:8443,patchradar.lan")
    r = await _request("GET", "/api/watchlist", {"Host": host})
    assert r.status_code == 421


@pytest.mark.asyncio
async def test_a_remapped_port_is_served_once_named(monkeypatch):
    """`docker run -p 127.0.0.1:9000:8000`: the browser says localhost:9000 to a
    server bound on 8000."""
    monkeypatch.setenv(ALLOWED_HOSTS_ENV, "localhost:9000")
    r = await _request("GET", "/api/watchlist", {"Host": "localhost:9000"})
    assert r.status_code == 200


@pytest.mark.asyncio
async def test_a_malformed_configured_entry_is_ignored(monkeypatch):
    monkeypatch.setenv(ALLOWED_HOSTS_ENV, "*,http://x/,patchradar.lan")
    assert (await _request("GET", "/api/watchlist", {"Host": "anything.example"})).status_code == 421
    assert (await _request("GET", "/api/watchlist", {"Host": "patchradar.lan"})).status_code == 200


# ─── The Origin check names the hosts, not the request's Host ────────────────

@pytest.mark.asyncio
async def test_a_proxy_that_rewrites_host_keeps_the_configured_origin(monkeypatch, unreachable_network):
    """A proxy forwarding https://patchradar.example.com to 127.0.0.1:8000 with
    Host rewritten, and a browser without Fetch Metadata: the Origin is the
    configured name, not the Host."""
    monkeypatch.setenv(ALLOWED_HOSTS_ENV, "patchradar.example.com")
    r = await _request("POST", "/api/watchlist/nginx",
                       {"Host": "127.0.0.1:8000", "Origin": "https://patchradar.example.com"})
    assert r.status_code == 200


@pytest.mark.asyncio
@pytest.mark.parametrize("origin", [
    "http://localhost:3000",          # another program on this machine
    "http://localhost",               # port 80: another origin too
    f"http://{FOREIGN}",
    "null",
    "http://localhost:8000@evil.example",
    "http://localhost:8000/path",
    "http://[1.2]:8000",              # urlsplit raises on it: a 500 on ad348ad
])
async def test_an_origin_the_server_does_not_answer_to_is_refused(origin):
    async with AsyncClient(transport=ASGITransport(app=api.app, raise_app_exceptions=False),
                           base_url="http://localhost:8000") as ac:
        r = await ac.post("/api/watchlist/nginx", headers={"Origin": origin})
    assert r.status_code == 403
    assert await database.get_watchlist() == []


# ─── At startup ──────────────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_startup_names_the_configured_entries_it_ignores(monkeypatch, caplog):
    """`*` would read as "any host" elsewhere; here it is not a host, and the
    operator is told rather than left to wonder why nothing matches."""
    monkeypatch.setenv(ALLOWED_HOSTS_ENV, "*, patchradar.lan, http://x/")
    with caplog.at_level("WARNING", logger="patchradar"):
        async with api.lifespan(api.app):
            pass
    ignored = [r.getMessage() for r in caplog.records if ALLOWED_HOSTS_ENV in r.getMessage()]
    assert ignored == [f"{ALLOWED_HOSTS_ENV}: ignoring ['*', 'http://x/'], which are not host or host:port"]


@pytest.mark.asyncio
async def test_the_host_check_lets_the_lifespan_through():
    """Startup and shutdown carry no Host: the check is for HTTP requests only,
    or uvicorn would never start the app. Driven through the ASGI app, as
    uvicorn drives it."""
    incoming = iter([{"type": "lifespan.startup"}, {"type": "lifespan.shutdown"}])
    sent: list[str] = []

    async def receive():
        return next(incoming)

    async def send(message):
        sent.append(message["type"])

    await api.app({"type": "lifespan", "asgi": {"version": "3.0"}, "state": {}}, receive, send)
    assert sent == ["lifespan.startup.complete", "lifespan.shutdown.complete"]


@pytest.mark.asyncio
async def test_startup_is_quiet_about_valid_entries(monkeypatch, caplog):
    monkeypatch.setenv(ALLOWED_HOSTS_ENV, "patchradar.lan,localhost:9000")
    with caplog.at_level("WARNING", logger="patchradar"):
        async with api.lifespan(api.app):
            pass
    assert not [r for r in caplog.records if ALLOWED_HOSTS_ENV in r.getMessage()]


# ─── The page itself ─────────────────────────────────────────────────────────

def test_the_page_script_calls_the_api_by_path():
    """The UI keeps working under any name the server answers to only if it
    never names a host itself."""
    script = (Path(api.__file__).parent / "static" / "app.js").read_text(encoding="utf-8")
    calls = re.findall(r"\bapi\(\s*([`'\"])(.*?)\1", script)
    assert calls
    for _, path in calls:
        assert path.startswith("/api/"), path
    assert re.findall(r"\bfetch\(\s*([^,)]+)", script) == ["path"]
