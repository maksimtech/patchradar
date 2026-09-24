"""
PatchRadar — Content-Security-Policy without 'unsafe-inline' (W6)

script-src allowed 'unsafe-inline' because the page used inline event handler
attributes (onclick=, onkeydown=, oninput=, onchange=) and one inline <script>
block. With 'unsafe-inline' the CSP stops nothing: any markup injection that
slipped past escaping could run script through an on*= attribute.

The fix moves the script to /static/app.js and binds every handler with
addEventListener, so script-src can be plain 'self'.

The wiring tests run the real page script in Node (tests/js/ui_harness.js):
the harness never executes on*= attributes — exactly like a browser under the
strict CSP — so a control is only live if the script bound it.
"""
import json
import re
import shutil
import subprocess
from html.parser import HTMLParser
from pathlib import Path

import pytest
from httpx import ASGITransport, AsyncClient

import patchradar.api.main as api

REPO = Path(__file__).resolve().parents[1]
HTML = REPO / "src" / "patchradar" / "api" / "templates" / "index.html"
STATIC = REPO / "src" / "patchradar" / "api" / "static"
HARNESS = REPO / "tests" / "js" / "ui_harness.js"

needs_node = pytest.mark.skipif(shutil.which("node") is None, reason="node not installed")


@pytest.fixture
async def client():
    async with AsyncClient(transport=ASGITransport(app=api.app), base_url="http://test") as ac:
        yield ac


def csp_directives(header: str) -> dict[str, list[str]]:
    out = {}
    for part in header.split(";"):
        tokens = part.split()
        if tokens:
            out[tokens[0]] = tokens[1:]
    return out


class _Collector(HTMLParser):
    def __init__(self):
        super().__init__()
        self.handlers, self.scripts, self.js_urls = [], [], []
        self._in_script = None

    def handle_starttag(self, tag, attrs):
        for name, value in attrs:
            if name.lower().startswith("on"):
                self.handlers.append(f"<{tag} {name}={value!r}>")
            if name.lower() in ("href", "src", "action") and (value or "").strip().lower().startswith("javascript:"):
                self.js_urls.append(f"<{tag} {name}={value!r}>")
        if tag == "script":
            self._in_script = {"src": dict(attrs).get("src"), "body": ""}
            self.scripts.append(self._in_script)

    def handle_data(self, data):
        if self._in_script is not None:
            self._in_script["body"] += data

    def handle_endtag(self, tag):
        if tag == "script":
            self._in_script = None


def parse_template() -> _Collector:
    c = _Collector()
    c.feed(HTML.read_text(encoding="utf-8"))
    return c


# ─── the policy itself ───────────────────────────────────────────────────────

@pytest.mark.asyncio
@pytest.mark.parametrize("path", ["/", "/api/stats"])
async def test_script_src_forbids_inline_and_eval(client, path):
    r = await client.get(path)
    directives = csp_directives(r.headers["content-security-policy"])
    script_src = directives.get("script-src", directives.get("default-src"))
    assert "'unsafe-inline'" not in script_src
    assert "'unsafe-eval'" not in script_src
    assert script_src == ["'self'"]


@pytest.mark.asyncio
async def test_policy_keeps_the_other_protections(client):
    r = await client.get("/")
    d = csp_directives(r.headers["content-security-policy"])
    assert d["default-src"] == ["'self'"]
    assert d["frame-ancestors"] == ["'none'"]
    assert d["connect-src"] == ["'self'"]
    assert d.get("object-src") == ["'none'"]
    assert d.get("base-uri") == ["'none'"]


# ─── the page must be able to live under that policy ────────────────────────

def test_template_has_no_inline_event_handlers():
    handlers = parse_template().handlers
    assert handlers == [], "blocked by script-src 'self':\n" + "\n".join(handlers)


def test_template_has_no_javascript_urls():
    assert parse_template().js_urls == []


def test_template_has_no_inline_script_bodies():
    scripts = parse_template().scripts
    assert scripts, "the page loads no script at all"
    inline = [s for s in scripts if s["body"].strip()]
    assert inline == [], "inline <script> blocks do not run under script-src 'self'"
    assert all(s["src"] and s["src"].startswith("/static/") for s in scripts)


def test_static_script_does_not_generate_inline_handlers():
    """Markup built in JS (innerHTML) is parsed by the browser just the same."""
    for js in STATIC.glob("*.js"):
        src = js.read_text(encoding="utf-8")
        assert not re.search(r"""\son[a-z]+\s*=\s*['"\\]""", src), f"{js.name} builds an on*= attribute"
        assert "setAttribute('on" not in src and 'setAttribute("on' not in src
        assert "javascript:" not in src
        assert not re.search(r"\beval\s*\(|new Function\s*\(", src), f"{js.name} needs 'unsafe-eval'"


@pytest.mark.asyncio
async def test_page_script_is_served_same_origin(client):
    page = await client.get("/")
    for s in parse_template().scripts:
        r = await client.get(s["src"])
        assert r.status_code == 200, s["src"]
        assert "javascript" in r.headers["content-type"]
        assert "function init" in r.text
        # the script response carries the same hardening headers
        assert r.headers["x-content-type-options"] == "nosniff"
    assert page.status_code == 200


@pytest.mark.asyncio
@pytest.mark.parametrize("path", ["/static/../main.py", "/static/%2e%2e/main.py", "/static/nope.js"])
async def test_static_route_does_not_escape_its_directory(client, path):
    r = await client.get(path)
    assert r.status_code == 404
    assert "SCAN_TIMEOUT" not in r.text


# ─── every control still works without inline handlers ──────────────────────

OK_ROUTES = {
    "/api/cves/": {"status": 200, "json": {"id": "CVE-1", "cvss_score": 5.0,
                                           "severity": "MEDIUM", "software": "nginx"}},
    "/api/cves": {"status": 200, "json": {"cves": [
        {"id": "CVE-1", "software": "nginx", "severity": "CRITICAL", "cvss_score": 9.8},
        {"id": "CVE-2", "software": "redis", "severity": "LOW", "cvss_score": 2.0},
    ], "total": 2}},
    "/api/watchlist/import": {"status": 200, "json": {"added": ["redis"], "skipped": ["nginx"],
                                                      "rejected": []}},
    "/api/watchlist/": {"status": 200, "json": {"added": True, "removed": True}},
    "/api/watchlist": {"status": 200, "json": {"watchlist": ["nginx"]}},
    "/api/stats": {"status": 200, "json": {"total_cves": 2, "watched": 1,
                                           "by_severity": {}, "by_software": {}}},
    "/api/scan": {"status": 200, "json": {"total": 0, "scanned": 1, "watched": 1,
                                          "timed_out": False, "errors": []}},
}


def run_page(tmp_path, actions, inputs=None):
    spec = tmp_path / "scenario.json"
    spec.write_text(json.dumps({"routes": OK_ROUTES, "actions": actions, "inputs": inputs or {}}), encoding="utf-8")
    out = subprocess.run(["node", str(HARNESS), str(HTML), str(spec)],
                         capture_output=True, text=True, timeout=30, encoding="utf-8", errors="replace")
    assert out.returncode == 0, out.stderr
    result = json.loads(out.stdout)
    assert result["errors"] == [], "\n".join(result["errors"])
    return result


def calls(result, method):
    return [r["path"] for r in result["requests"] if r["method"] == method]


@needs_node
def test_add_button_adds(tmp_path):
    r = run_page(tmp_path, ['await fire("#add-btn", "click")'], {"add-input": "redis"})
    assert calls(r, "POST") == ["/api/watchlist/redis"]


@needs_node
def test_enter_in_add_input_adds(tmp_path):
    r = run_page(tmp_path, ['await fire("#add-input", "keydown", {key: "Enter"})'],
                 {"add-input": "redis"})
    assert calls(r, "POST") == ["/api/watchlist/redis"]


@needs_node
def test_other_keys_in_add_input_do_not_add(tmp_path):
    r = run_page(tmp_path, ['await fire("#add-input", "keydown", {key: "a"})'],
                 {"add-input": "redis"})
    assert calls(r, "POST") == []


@needs_node
def test_scan_button_scans(tmp_path):
    r = run_page(tmp_path, ['await fire("#scan-btn", "click")'])
    assert calls(r, "POST") == ["/api/scan?days=30"]


@needs_node
def test_import_button_opens_file_picker(tmp_path):
    r = run_page(tmp_path, ['await fire("#import-btn", "click")'])
    assert "import-file" in r["clicked"]


@needs_node
def test_file_input_change_imports(tmp_path):
    action = ('const f = document.getElementById("import-file");'
              'f.files = [{text: async () => "nginx\\nredis\\n"}];'
              'await fire("#import-file", "change");')
    r = run_page(tmp_path, [action])
    assert calls(r, "POST") == ["/api/watchlist/import"]


@needs_node
@pytest.mark.parametrize("severity", ["CRITICAL", "LOW", "ALL"])
def test_filter_buttons_filter(tmp_path, severity):
    r = run_page(tmp_path, [f'await fire(\'[data-filter="{severity}"]\', "click")'])
    assert [k for k, active in r["filters"].items() if active] == [severity]
    table = r["elements"]["cve-table-wrap"]["text"]
    if severity == "CRITICAL":
        assert "CVE-1" in table and "CVE-2" not in table
    elif severity == "LOW":
        assert "CVE-2" in table and "CVE-1" not in table
    else:
        assert "CVE-1" in table and "CVE-2" in table


@needs_node
def test_search_input_filters(tmp_path):
    action = ('document.getElementById("search-input").value = "redis";'
              'await fire("#search-input", "input");')
    r = run_page(tmp_path, [action])
    table = r["elements"]["cve-table-wrap"]["text"]
    assert "CVE-2" in table and "CVE-1" not in table


@needs_node
def test_enter_in_search_is_swallowed(tmp_path):
    action = ('const e = await fire("#search-input", "keydown", {key: "Enter"});'
              'if (!e.defaultPrevented) throw new Error("Enter not prevented");')
    run_page(tmp_path, [action])


OPEN_MODAL = 'await openCveDetail("CVE-1");'
MODAL_OPEN = ('if (!document.getElementById("cve-modal").classList.contains("active"))'
              ' throw new Error("modal did not open");')
MODAL_CLOSED = ('if (document.getElementById("cve-modal").classList.contains("active"))'
                ' throw new Error("modal still open");')


@needs_node
def test_close_button_closes_modal(tmp_path):
    run_page(tmp_path, [OPEN_MODAL + MODAL_OPEN + 'await fire("#modal-close", "click");' + MODAL_CLOSED])


@needs_node
def test_click_on_backdrop_closes_modal(tmp_path):
    run_page(tmp_path, [OPEN_MODAL + 'await fire("#cve-modal", "click");' + MODAL_CLOSED])


@needs_node
def test_click_inside_modal_keeps_it_open(tmp_path):
    action = (OPEN_MODAL + 'const m = document.getElementById("cve-modal");'
              'await fire("#cve-modal", "click", {target: {}});' + MODAL_OPEN)
    run_page(tmp_path, [action])
