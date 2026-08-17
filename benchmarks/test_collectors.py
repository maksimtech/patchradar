"""Benchmarks for the CVE collectors.

The HTTP layer is replaced by ``httpx.MockTransport`` so that the measurement
covers what PatchRadar actually spends CPU time on: JSON decoding, keyword
filtering, CVSS extraction and record normalization.
"""

import httpx
import pytest

from patchradar.collectors import msrc, nvd


@pytest.fixture
def mock_http(monkeypatch):
    """Serve every outgoing request from a static payload."""

    def _install(payload: dict, status_code: int = 200):
        def handler(request: httpx.Request) -> httpx.Response:
            return httpx.Response(status_code, json=payload)

        transport = httpx.MockTransport(handler)
        real_client = httpx.AsyncClient

        def factory(*args, **kwargs):
            kwargs["transport"] = transport
            return real_client(*args, **kwargs)

        monkeypatch.setattr(httpx, "AsyncClient", factory)

    return _install


def test_nvd_fetch_cves(benchmark, loop, mock_http, nvd_payload):
    """Full NVD collection path over a 50 CVE page."""
    mock_http(nvd_payload)

    result = benchmark(lambda: loop.run_until_complete(nvd.fetch_cves("proxmox", 30)))

    assert len(result) == 50


def test_msrc_fetch_cves(benchmark, loop, mock_http, msrc_payload):
    """MSRC collection path, including keyword filtering over 200 advisories."""
    mock_http(msrc_payload)

    result = benchmark(
        lambda: loop.run_until_complete(msrc.fetch_cves("windows 10", 30))
    )

    assert result


def test_msrc_score_to_severity(benchmark):
    """CVSS score to severity mapping, called once per advisory."""
    scores = [None, 0.0, 3.9, 4.0, 6.9, 7.0, 8.9, 9.0, 10.0]

    def run():
        return [msrc._score_to_severity(score) for score in scores * 100]

    result = benchmark(run)

    assert len(result) == 900
