"""
PatchRadar — `scripts/import-winget.ps1` against a server that has a key

Run on 2026-10-09 on a Windows 11 machine against the published image, started
with `docker compose` and `PATCHRADAR_API_KEY` set, the way README says to run it
anywhere but on the same machine:

    PatchRadar - Winget Import
    Connecting to: http://127.0.0.1:8000
    Reading installed software from winget...
    Found 109 installed packages
    ERROR: Failed to import to PatchRadar: {"detail":"There was an error parsing the body"}

Two defects, and the second hid the first. The script sent the body in the
console's code page — Windows PowerShell 5.1 posts a string as cp1252 — and one
of the 109 names was "hwinfo® 64", whose ® is not valid UTF-8 in that encoding,
so the server refused the body before it read anything else. Sent as UTF-8 the
same list imports (the ® name is then rejected by the name rule, by itself). And
the script sent no `X-API-Key` at all, so against that server it could only
ever have ended in 401.

The script takes `-ApiKey` now, `$env:PATCHRADAR_API_KEY` by default, and posts
UTF-8 bytes. It also takes `-InputFile`, one name per line, which is how a list
taken on another machine gets in — and how this file can run the real script
against a real HTTP server without `winget` and without a mock: the server below
is Python's own, in a thread, and it writes down the bytes and headers it got.
"""
from __future__ import annotations

import http.server
import json
import pathlib
import shutil
import subprocess
import threading

import pytest

SCRIPT = pathlib.Path(__file__).resolve().parents[1] / "scripts" / "import-winget.ps1"
POWERSHELL = shutil.which("powershell") or shutil.which("pwsh")


@pytest.fixture
def script() -> str:
    return SCRIPT.read_text(encoding="utf-8")


# ── the contract, read off the script ───────────────────────────────────────

def test_the_script_sends_the_api_key_header(script):
    assert "X-API-Key" in script


def test_the_key_comes_from_the_environment_by_default(script):
    assert "$env:PATCHRADAR_API_KEY" in script


def test_the_body_is_posted_as_utf8_bytes(script):
    """Invoke-RestMethod encodes a string body in the console's code page on
    Windows PowerShell 5.1; bytes travel as they are."""
    assert "[System.Text.Encoding]::UTF8.GetBytes" in script


# ── the real script against a real server ───────────────────────────────────

class _Recorder(http.server.BaseHTTPRequestHandler):
    received: list[dict] = []

    def do_GET(self):  # noqa: N802 - the handler API
        self._answer({"status": "ok", "version": "test", "database": "ok"})

    def do_POST(self):  # noqa: N802
        length = int(self.headers.get("Content-Length") or 0)
        body = self.rfile.read(length)
        _Recorder.received.append({"path": self.path, "headers": dict(self.headers), "body": body})
        names = json.loads(body.decode("utf-8"))["software"]
        self._answer({"added": names, "skipped": [], "rejected": [], "total": len(names)})

    def _answer(self, payload: dict) -> None:
        data = json.dumps(payload).encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def log_message(self, *args):  # quiet
        return


@pytest.fixture
def recording_server():
    _Recorder.received = []
    server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), _Recorder)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield f"http://127.0.0.1:{server.server_address[1]}"
    finally:
        server.shutdown()
        server.server_close()


@pytest.mark.skipif(POWERSHELL is None, reason="PowerShell not installed")
def test_the_script_posts_utf8_with_the_key_it_was_given(recording_server, tmp_path):
    names = tmp_path / "names.txt"
    # The name that broke the real run, and one with a plain accent.
    names.write_text("hwinfo® 64\ncaffè latte\n7-zip\n", encoding="utf-8")

    run = subprocess.run(
        [POWERSHELL, "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass",
         "-File", str(SCRIPT), "-Url", recording_server, "-ApiKey", "k-123", "-InputFile", str(names)],
        capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=120,
    )
    assert run.returncode == 0, run.stdout + run.stderr

    [post] = _Recorder.received
    assert post["path"] == "/api/watchlist/import"
    assert post["headers"].get("X-API-Key") == "k-123"
    body = json.loads(post["body"].decode("utf-8"))      # raises on cp1252 bytes
    assert body["software"] == ["hwinfo® 64", "caffè latte", "7-zip"]
    assert "Added: 3" in run.stdout


@pytest.mark.skipif(POWERSHELL is None, reason="PowerShell not installed")
def test_the_key_is_read_from_the_environment(recording_server, tmp_path, monkeypatch):
    names = tmp_path / "names.txt"
    names.write_text("nginx\n", encoding="utf-8")
    monkeypatch.setenv("PATCHRADAR_API_KEY", "from-env")

    run = subprocess.run(
        [POWERSHELL, "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass",
         "-File", str(SCRIPT), "-Url", recording_server, "-InputFile", str(names)],
        capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=120,
    )
    assert run.returncode == 0, run.stdout + run.stderr
    [post] = _Recorder.received
    assert post["headers"].get("X-API-Key") == "from-env"
    assert json.loads(post["body"].decode("utf-8")) == {"software": ["nginx"]}


@pytest.mark.skipif(POWERSHELL is None, reason="PowerShell not installed")
def test_a_single_name_is_still_a_list(recording_server, tmp_path):
    """ConvertTo-Json unwraps a one-element array into a string unless told not
    to, and {"software": "nginx"} is a 400 at the server."""
    names = tmp_path / "names.txt"
    names.write_text("nginx\n", encoding="utf-8")
    subprocess.run(
        [POWERSHELL, "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass",
         "-File", str(SCRIPT), "-Url", recording_server, "-InputFile", str(names)],
        capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=120, check=True,
    )
    [post] = _Recorder.received
    assert isinstance(json.loads(post["body"].decode("utf-8"))["software"], list)
