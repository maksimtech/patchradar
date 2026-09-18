"""
PatchRadar — web UI behaviour on API failure (W7) and zero scores (W3, UI side)

api() reported an error with a toast and then returned `{}`, and almost every
caller dereferenced the result unconditionally:

* loadWatchlist: `data.watchlist.length` -> TypeError, init() aborted
* loadCves:      `allCves = data.cves` -> undefined -> renderTable() TypeError
* loadStats:     wrote the string "undefined" into the stat cards
* addSoftware:   after a failure, toasted "<name> already in watchlist",
                 overwriting the real error
* removeSoftware: toasted "Removed <name>" whether or not it was removed
* openCveDetail: opened an empty modal on a 404
* api():         `return r.json()` was not awaited inside the try, so a 200
                 with a non-JSON body escaped as an unhandled rejection

W3 on the UI side: `cvss_score ? toFixed(1) : 'N/A'` showed a real 0.0 as N/A.

These tests execute the page's actual <script> in Node (tests/js/ui_harness.js)
rather than pattern-matching the source.
"""
import json
import shutil
import subprocess
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[1]
HTML = REPO / "src" / "patchradar" / "api" / "templates" / "index.html"
HARNESS = REPO / "tests" / "js" / "ui_harness.js"

pytestmark = pytest.mark.skipif(shutil.which("node") is None, reason="node not installed")

OK_ROUTES = {
    "/api/watchlist": {"status": 200, "json": {"watchlist": ["nginx"]}},
    "/api/stats": {"status": 200, "json": {"total_cves": 3, "watched": 1,
                                           "by_severity": {"HIGH": 2, "LOW": 1},
                                           "by_software": {"nginx": 3}}},
    "/api/cves/": {"status": 200, "json": {"id": "CVE-1", "cvss_score": 0.0,
                                           "severity": "LOW", "software": "nginx"}},
    "/api/cves": {"status": 200, "json": {"cves": [], "total": 0}},
}
ALL_500 = {"status": 500, "json": {"detail": "boom"}}


def run_page(tmp_path, **scenario):
    spec = tmp_path / "scenario.json"
    spec.write_text(json.dumps(scenario))
    out = subprocess.run(["node", str(HARNESS), str(HTML), str(spec)],
                         capture_output=True, text=True, timeout=30)
    assert out.returncode == 0, out.stderr
    return json.loads(out.stdout)


def ordered(routes):
    """Longest prefix first, so /api/cves/ wins over /api/cves."""
    return dict(sorted(routes.items(), key=lambda kv: -len(kv[0])))


# ─── harness sanity ──────────────────────────────────────────────────────────

def test_happy_path_renders_without_errors(tmp_path):
    result = run_page(tmp_path, routes=ordered(OK_ROUTES))
    assert result["errors"] == []
    assert "nginx" in result["elements"]["watchlist-items"]["text"]
    assert result["elements"]["stat-total"]["text"] == "3"


# ─── W7: failures must not crash the page ────────────────────────────────────

@pytest.mark.parametrize("failure", [
    pytest.param(ALL_500, id="http-500"),
    pytest.param({"status": 429, "json": {"detail": "slow down"}}, id="http-429"),
    pytest.param({"networkError": True}, id="network-error"),
    pytest.param({"status": 200, "rawBody": "<html>proxy error</html>"}, id="200-non-json"),
])
def test_initial_load_survives_api_failure(tmp_path, failure):
    result = run_page(tmp_path, fallback=failure)
    assert result["errors"] == [], "\n".join(result["errors"])


@pytest.mark.parametrize("failure", [
    pytest.param(ALL_500, id="http-500"),
    pytest.param({"networkError": True}, id="network-error"),
])
def test_stat_cards_never_show_undefined(tmp_path, failure):
    result = run_page(tmp_path, fallback=failure)
    for card in ("stat-total", "stat-watched", "stat-critical", "stat-high"):
        assert "undefined" not in result["elements"].get(card, {}).get("text", ""), card


def test_a_failed_load_is_reported_to_the_user(tmp_path):
    result = run_page(tmp_path, fallback=ALL_500)
    assert any("500" in t for t in result["toasts"])


def test_failed_add_is_not_reported_as_duplicate(tmp_path):
    """The error toast used to be overwritten by '<name> already in watchlist'."""
    result = run_page(tmp_path, routes=ordered(OK_ROUTES),
                      routesAfterInit={"/api/watchlist/": ALL_500, **ordered(OK_ROUTES)},
                      inputs={"add-input": "redis"},
                      actions=["await addSoftware()"])
    assert result["errors"] == []
    assert not any("already in watchlist" in t for t in result["toasts"]), result["toasts"]
    assert "500" in result["toasts"][-1]


def test_failed_remove_is_not_reported_as_removed(tmp_path):
    result = run_page(tmp_path, routes=ordered(OK_ROUTES),
                      routesAfterInit={"/api/watchlist/": ALL_500, **ordered(OK_ROUTES)},
                      actions=["await removeSoftware('nginx')"])
    assert result["errors"] == []
    assert not any(t.startswith("Removed") for t in result["toasts"]), result["toasts"]


def test_successful_remove_is_still_reported(tmp_path):
    routes = {"/api/watchlist/": {"status": 200, "json": {"removed": True, "software": "nginx"}},
              **OK_ROUTES}
    result = run_page(tmp_path, routes=ordered(routes),
                      actions=["await removeSoftware('nginx')"])
    assert any(t.startswith("Removed") for t in result["toasts"])


def test_failed_cve_detail_does_not_open_an_empty_modal(tmp_path):
    # scenario route last: dict merge keeps the right-most value for a key
    routes = {**OK_ROUTES, "/api/cves/": {"status": 404, "json": {"detail": "CVE not found"}}}
    result = run_page(tmp_path, routes=ordered(routes),
                      actions=["await openCveDetail('CVE-404')"])
    assert result["errors"] == []
    assert result["elements"].get("cve-modal", {}).get("active") is not True


# ─── W3: zero is a score ─────────────────────────────────────────────────────

def cve_row(score):
    return {"id": "CVE-1", "software": "nginx", "cvss_score": score,
            "severity": "LOW", "description": "d", "source": "NVD",
            "published_at": "2026-01-01"}


@pytest.mark.parametrize("score, shown", [(0.0, "0.0"), (0, "0.0"), (7.5, "7.5"), (None, "N/A")])
def test_table_score_cell(tmp_path, score, shown):
    routes = {"/api/cves": {"status": 200, "json": {"cves": [cve_row(score)], "total": 1}},
              **{k: v for k, v in OK_ROUTES.items() if k != "/api/cves"}}
    result = run_page(tmp_path, routes=ordered(routes))
    text = result["elements"]["cve-table-wrap"]["text"]
    # header cells come first: CVE ID, Software, Score, ...; row: CVE-1, nginx, <score>
    assert f"nginx{shown}" in text, text


@pytest.mark.parametrize("score, shown", [(0.0, "0.0"), (None, "")])
def test_modal_score(tmp_path, score, shown):
    routes = {**OK_ROUTES, "/api/cves/": {"status": 200, "json": {"id": "CVE-1", "cvss_score": score,
                                                                  "severity": "LOW"}}}
    result = run_page(tmp_path, routes=ordered(routes), actions=["await openCveDetail('CVE-1')"])
    assert result["elements"]["modal-score"]["text"] == shown


# ─── W10: an incomplete scan must not read as a clean one ────────────────────

def test_scan_with_failed_sources_warns(tmp_path):
    scan = {"status": 200, "json": {"total": 0, "by_software": {"nginx": 0}, "timed_out": False,
                                     "scanned": 1, "watched": 1,
                                     "errors": [{"software": "nginx", "source": "NVD",
                                                 "reason": "rate_limited", "status": 429}]}}
    result = run_page(tmp_path, routes=ordered({**OK_ROUTES, "/api/scan": scan}),
                      actions=["await scanAll()"])
    assert result["errors"] == []
    last = result["toasts"][-1]
    assert "NVD" in last and "incomplete" in last.lower(), result["toasts"]
    assert not last.startswith("Found"), "an incomplete scan was toasted as a normal result"


def test_clean_scan_still_reports_the_count(tmp_path):
    scan = {"status": 200, "json": {"total": 4, "by_software": {"nginx": 4}, "timed_out": False,
                                     "scanned": 1, "watched": 1, "errors": []}}
    result = run_page(tmp_path, routes=ordered({**OK_ROUTES, "/api/scan": scan}),
                      actions=["await scanAll()"])
    assert result["toasts"][-1] == "Found 4 CVEs"
