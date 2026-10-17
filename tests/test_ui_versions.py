"""
PatchRadar — the web UI shows what is installed and the verdict (docs/DESIGN.md §5.4, §5.6)

The command line and the API learnt the installed version, the verdict on each
CVE and the priority stored with it (#58–#61); the dashboard still listed every
CVE found by name, ranked as if each were a job, with no way to say what is
installed. Now:

- the watchlist shows the version beside the name, and the add form takes a
  version and a CPE, sent to `POST /api/watchlist/{name}` like the CLI's;
- the table has a Verdict and a Priority column, and hides the CVEs that do
  not affect the installed version — counted, one click away — as `scan`
  does without `--all`;
- a scan's toast gives the split per judged product.

Runs the page's real script in Node against scripted API answers
(tests/js/ui_harness.js), as tests/test_ui_errors.py does.
"""
from __future__ import annotations

import json
import shutil
import subprocess
from pathlib import Path
from urllib.parse import quote

import pytest

REPO = Path(__file__).resolve().parents[1]
HTML = REPO / "src" / "patchradar" / "api" / "templates" / "index.html"
HARNESS = REPO / "tests" / "js" / "ui_harness.js"

pytestmark = pytest.mark.skipif(shutil.which("node") is None, reason="node not installed")

NOTEPADPP = "cpe:2.3:a:notepad-plus-plus:notepad\\+\\+"


def _cve(cve_id, verdict, priority="scored", software="notepad"):
    return {"id": cve_id, "software": software, "cvss_score": 7.8, "severity": "HIGH",
            "description": cve_id, "source": "NVD", "published_at": "2026-06-26T00:00:00Z",
            "verdict": verdict, "verdict_reason": f"reason of {cve_id}" if verdict else None,
            "priority": priority, "priority_reason": f"why {cve_id}"}


CVES = [
    _cve("CVE-2026-0001", "affected", priority="ransomware"),
    _cve("CVE-2026-0002", "not evaluable"),
    _cve("CVE-2026-0003", "not affected"),
    _cve("CVE-2026-0004", None, software="nginx"),
]

ROUTES = {
    "/api/watchlist": {"status": 200, "json": {
        "watchlist": ["nginx", "notepad"],
        "entries": [{"name": "nginx", "installed_version": None, "cpe": None},
                    {"name": "notepad", "installed_version": "8.5.0", "cpe": NOTEPADPP}]}},
    "/api/stats": {"status": 200, "json": {"total_cves": 4, "watched": 2,
                                           "by_severity": {"HIGH": 4}, "by_software": {"notepad": 3}}},
    "/api/cves": {"status": 200, "json": {"cves": CVES, "total": 4}},
}


def run_page(tmp_path, actions=(), inputs=None, routes_after_init=None):
    scenario = {"routes": ROUTES, "actions": list(actions), "inputs": inputs or {}}
    if routes_after_init:
        # The harness takes the first route that is a prefix of the path, so the
        # specific ones go first: "/api/watchlist/notepad" before "/api/watchlist".
        merged = {**ROUTES, **routes_after_init}
        scenario["routesAfterInit"] = dict(sorted(merged.items(), key=lambda kv: -len(kv[0])))
    spec = tmp_path / "scenario.json"
    spec.write_text(json.dumps(scenario), encoding="utf-8")
    out = subprocess.run(["node", str(HARNESS), str(HTML), str(spec)],
                         capture_output=True, text=True, timeout=30, encoding="utf-8", errors="replace")
    assert out.returncode == 0, out.stderr
    result = json.loads(out.stdout)
    assert result["errors"] == [], "\n".join(result["errors"])
    return result


def table(result) -> str:
    return result["elements"]["cve-table-wrap"]["text"]


# ─── the watchlist ───────────────────────────────────────────────────────────

def test_the_watchlist_shows_the_installed_version(tmp_path):
    text = run_page(tmp_path)["elements"]["watchlist-items"]["text"]

    assert "notepad" in text and "8.5.0" in text
    assert "nginx" in text


def test_the_add_form_sends_the_version_and_the_cpe(tmp_path):
    result = run_page(tmp_path, ['await fire("#add-btn", "click")'],
                      {"add-input": "notepad", "add-version": "8.5.0", "add-cpe": NOTEPADPP})

    posts = [r["path"] for r in result["requests"] if r["method"] == "POST"]
    assert posts == [f"/api/watchlist/notepad?version=8.5.0&cpe={quote(NOTEPADPP, safe='-_.!~*()')}"]


def test_without_a_version_the_add_form_sends_the_name_alone(tmp_path):
    result = run_page(tmp_path, ['await fire("#add-btn", "click")'], {"add-input": "redis"})

    assert [r["path"] for r in result["requests"] if r["method"] == "POST"] == ["/api/watchlist/redis"]


def test_a_refused_cpe_shows_the_form_nvd_wants(tmp_path):
    refusal = {"status": 422, "json": {"detail": "the product 'notepad++' has characters NVD writes "
                                                 "escaped; NVD's form is 'notepad\\+\\+'"}}
    result = run_page(tmp_path, ['await fire("#add-btn", "click")'],
                      {"add-input": "notepad", "add-version": "8.5.0",
                       "add-cpe": "cpe:2.3:a:notepad-plus-plus:notepad++"},
                      routes_after_init={"/api/watchlist/notepad": refusal})

    assert any("notepad\\+\\+" in toast for toast in result["toasts"])


# ─── the table ───────────────────────────────────────────────────────────────

def test_the_table_has_a_verdict_and_a_priority_column(tmp_path):
    text = table(run_page(tmp_path))

    assert "Verdict" in text and "Priority" in text
    assert "ransomware" in text
    assert "not evaluable" in text


def test_what_does_not_affect_the_installed_version_is_hidden_and_counted(tmp_path):
    result = run_page(tmp_path)

    text = table(result)
    assert "CVE-2026-0001" in text and "CVE-2026-0002" in text and "CVE-2026-0004" in text
    assert "CVE-2026-0003" not in text
    assert "1 not affected" in result["elements"]["toggle-unaffected"]["text"]


def test_one_click_shows_them_and_another_hides_them(tmp_path):
    shown = run_page(tmp_path, ['await fire("#toggle-unaffected", "click")'])
    hidden = run_page(tmp_path, ['await fire("#toggle-unaffected", "click")',
                                 'await fire("#toggle-unaffected", "click")'])

    assert "CVE-2026-0003" in table(shown)
    assert "CVE-2026-0003" not in table(hidden)


def test_a_cve_matched_by_name_says_its_version_was_not_checked(tmp_path):
    """nginx has no version: its CVE is listed, and the verdict cell does not
    leave the reader to guess why it is empty."""
    assert "not checked" in table(run_page(tmp_path))


# ─── a scan ──────────────────────────────────────────────────────────────────

def test_a_scan_says_the_split_for_each_judged_product(tmp_path):
    scan = {"status": 200, "json": {"total": 21, "scanned": 1, "watched": 1, "timed_out": False,
                                    "errors": [], "by_software": {"notepad": 21},
                                    "verdicts": {"notepad": {"affected": 10, "not evaluable": 0,
                                                             "not affected": 11}}}}
    result = run_page(tmp_path, ['await fire("#scan-btn", "click")'], routes_after_init={"/api/scan": scan})

    assert any("Found 21 CVEs" in t and "notepad: 10 affected, 0 not evaluable, 11 not affected" in t
               for t in result["toasts"]), result["toasts"]


def test_with_nothing_hidden_there_is_no_button_to_show_it(tmp_path, monkeypatch):
    only_affected = {"/api/cves": {"status": 200, "json": {"cves": [CVES[0]], "total": 1}}}
    monkeypatch.setitem(ROUTES, "/api/cves", only_affected["/api/cves"])

    assert run_page(tmp_path)["elements"]["toggle-unaffected"]["text"] == ""
