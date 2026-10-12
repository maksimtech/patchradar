"""
PatchRadar — VulDB collector

VulDB adds exploit pricing intelligence and faster indexing than NVD for some
entries. The API is a single POST endpoint; authentication is mandatory and via
the ``X-VulDB-ApiKey`` header.

All tests mock the network: a test that reaches vuldb.com would consume real
credits, and a scan test that exercises VulDB without mocking it would do the
same silently.
"""
from urllib.parse import parse_qs, urlsplit

import httpx
import pytest
import respx

from patchradar.collectors import vuldb
from patchradar.collectors.errors import CollectorError

# ── fixture data ────────────────────────────────────────────────────────────

_ENTRY_APACHE = {
    "source": {"cve": "CVE-2024-38476"},
    "advisory": {"id": "271234", "date": "2024-07-01", "title": "Apache HTTP Server mod_proxy Weakness"},
    "vulnerability": {"title": "Apache HTTP Server mod_proxy Weakness"},
    "cvss3": {"base_score": "9.8"},
}

_ENTRY_APACHE_NO_CVE = {
    "source": {},
    "advisory": {"id": "271999", "date": "2024-07-05", "title": "Apache Tomcat DoS"},
    "vulnerability": {"title": "Apache Tomcat DoS"},
    "cvss3": {"base_score": "5.3"},
}

_ENTRY_OPENSSL = {
    "source": {"cve": "CVE-2024-5535"},
    "advisory": {"id": "270001", "date": "2024-06-27", "title": "OpenSSL SSL_select_next_proto Buffer Overread"},
    "vulnerability": {"title": "OpenSSL SSL_select_next_proto Buffer Overread"},
    "cvss3": {"base_score": "7.5"},
}

_ENTRY_CVSS2_ONLY = {
    "source": {"cve": "CVE-2010-1234"},
    "advisory": {"id": "100001", "date": "2010-03-15", "title": "Apache Legacy Flaw"},
    "vulnerability": {"title": "Apache Legacy Flaw"},
    "cvss2": {"base_score": "6.5"},
}

_ENTRY_NO_SCORE = {
    "source": {"cve": "CVE-2024-99999"},
    "advisory": {"id": "271500", "date": "2024-07-10", "title": "Apache Pending Analysis"},
    "vulnerability": {"title": "Apache Pending Analysis"},
}


def _vuldb_response(result: list | None = None, remaining: int = 100) -> dict:
    """Build a well-formed VulDB API response."""
    return {
        "request": {"type": "search", "keyword": "apache"},
        "response": {"remaining": remaining, "total": len(result or [])},
        "result": result if result is not None else [],
    }


def _mock(payload=None, status=200, *, key="test-vuldb-key"):
    """Mock the VulDB POST endpoint."""
    if payload is None:
        payload = _vuldb_response([_ENTRY_APACHE])
    return respx.post(vuldb.VULDB_API).mock(
        return_value=httpx.Response(status, json=payload)
    )


@pytest.fixture(autouse=True)
def _set_api_key(monkeypatch):
    """Every test gets an API key and the real fetch_cves back.

    The session-wide ``vuldb_offline_by_default`` fixture replaces
    ``fetch_cves`` with a no-op.  This file's tests need the real one.
    """
    monkeypatch.setattr(vuldb, "fetch_cves", vuldb._real_fetch_cves)
    monkeypatch.setenv(vuldb.API_KEY_ENV, "test-vuldb-key")


# ── API key ─────────────────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_missing_api_key_raises(monkeypatch):
    monkeypatch.delenv(vuldb.API_KEY_ENV, raising=False)
    with pytest.raises(CollectorError) as exc_info:
        await vuldb.fetch_cves("apache")
    assert exc_info.value.reason == "no_api_key"
    assert vuldb.API_KEY_ENV in exc_info.value.detail


@pytest.mark.asyncio
async def test_empty_api_key_raises(monkeypatch):
    monkeypatch.setenv(vuldb.API_KEY_ENV, "   ")
    with pytest.raises(CollectorError) as exc_info:
        await vuldb.fetch_cves("apache")
    assert exc_info.value.reason == "no_api_key"


# ── basic search ────────────────────────────────────────────────────────────

@pytest.mark.asyncio
@respx.mock
async def test_search_returns_matching_cves():
    _mock(_vuldb_response([_ENTRY_APACHE]))
    results = await vuldb.fetch_cves("apache")
    assert len(results) == 1
    assert results[0]["id"] == "CVE-2024-38476"
    assert results[0]["software"] == "apache"
    assert results[0]["source"] == "VulDB"


@pytest.mark.asyncio
@respx.mock
async def test_search_sends_correct_request():
    route = _mock(_vuldb_response([]))
    await vuldb.fetch_cves("apache")
    request = route.calls[0].request
    assert request.method == "POST"
    assert request.url == vuldb.VULDB_API
    assert request.headers["X-VulDB-ApiKey"] == "test-vuldb-key"
    body = request.content.decode()
    assert "search=apache" in body
    assert "details=1" in body


@pytest.mark.asyncio
@respx.mock
async def test_empty_result_returns_empty_list():
    _mock(_vuldb_response([]))
    results = await vuldb.fetch_cves("nonexistent-software-xyz")
    assert results == []


@pytest.mark.asyncio
@respx.mock
async def test_null_result_returns_empty_list():
    _mock(_vuldb_response(None))
    results = await vuldb.fetch_cves("apache")
    assert results == []


# ── record parsing ──────────────────────────────────────────────────────────

@pytest.mark.asyncio
@respx.mock
async def test_record_fields_are_populated():
    _mock(_vuldb_response([_ENTRY_APACHE]))
    results = await vuldb.fetch_cves("apache")
    record = results[0]
    assert record["id"] == "CVE-2024-38476"
    assert record["software"] == "apache"
    assert record["description"] == "Apache HTTP Server mod_proxy Weakness"
    assert record["cvss_score"] == 9.8
    assert record["cvss_version"] == "3.1"
    assert record["severity"] == "CRITICAL"
    assert record["published_at"] == "2024-07-01"
    assert record["source"] == "VulDB"
    # The host, not a substring: CodeQL flagged the substring test (alert #59,
    # py/incomplete-url-substring-sanitization) and failed Security Posture on main.
    assert urlsplit(record["url"]).hostname == "vuldb.com"


@pytest.mark.asyncio
@respx.mock
async def test_entry_without_cve_gets_vdb_prefix():
    _mock(_vuldb_response([_ENTRY_APACHE_NO_CVE]))
    results = await vuldb.fetch_cves("apache")
    assert len(results) == 1
    assert results[0]["id"] == "VDB-271999"


@pytest.mark.asyncio
@respx.mock
async def test_cvss2_only_entry():
    _mock(_vuldb_response([_ENTRY_CVSS2_ONLY]))
    results = await vuldb.fetch_cves("apache")
    assert len(results) == 1
    assert results[0]["cvss_score"] == 6.5
    assert results[0]["cvss_version"] == "2.0"


@pytest.mark.asyncio
@respx.mock
async def test_entry_without_cvss_has_unknown_severity():
    _mock(_vuldb_response([_ENTRY_NO_SCORE]))
    results = await vuldb.fetch_cves("apache")
    assert len(results) == 1
    assert results[0]["cvss_score"] is None
    assert results[0]["severity"] == "UNKNOWN"


@pytest.mark.asyncio
@respx.mock
async def test_multiple_entries_returned():
    _mock(_vuldb_response([_ENTRY_APACHE, _ENTRY_OPENSSL]))
    results = await vuldb.fetch_cves("apache")
    # OpenSSL entry should still be returned — post-filtering is by the search keyword
    # in title. Apache matches; OpenSSL doesn't match "apache".
    ids = {r["id"] for r in results}
    assert "CVE-2024-38476" in ids


# ── error handling ──────────────────────────────────────────────────────────

@pytest.mark.asyncio
@respx.mock
async def test_http_error_raises_collector_error():
    respx.post(vuldb.VULDB_API).mock(return_value=httpx.Response(500))
    with pytest.raises(CollectorError) as exc_info:
        await vuldb.fetch_cves("apache")
    assert exc_info.value.source == "VulDB"
    assert exc_info.value.status == 500


@pytest.mark.asyncio
@respx.mock
async def test_rate_limited_raises_collector_error():
    respx.post(vuldb.VULDB_API).mock(return_value=httpx.Response(429))
    with pytest.raises(CollectorError) as exc_info:
        await vuldb.fetch_cves("apache")
    assert exc_info.value.reason == "rate_limited"


@pytest.mark.asyncio
@respx.mock
async def test_bad_json_raises_collector_error():
    respx.post(vuldb.VULDB_API).mock(
        return_value=httpx.Response(200, content=b"not json")
    )
    with pytest.raises(CollectorError) as exc_info:
        await vuldb.fetch_cves("apache")
    assert exc_info.value.reason == "bad_payload"


@pytest.mark.asyncio
@respx.mock
async def test_non_dict_response_raises_collector_error():
    respx.post(vuldb.VULDB_API).mock(
        return_value=httpx.Response(200, json=[1, 2, 3])
    )
    with pytest.raises(CollectorError) as exc_info:
        await vuldb.fetch_cves("apache")
    assert exc_info.value.reason == "bad_payload"


@pytest.mark.asyncio
@respx.mock
async def test_network_error_raises_collector_error():
    respx.post(vuldb.VULDB_API).mock(side_effect=httpx.ConnectError("connection refused"))
    with pytest.raises(CollectorError) as exc_info:
        await vuldb.fetch_cves("apache")
    assert exc_info.value.reason == "network"


# ── credits warning ─────────────────────────────────────────────────────────

@pytest.mark.asyncio
@respx.mock
async def test_low_credits_logs_warning(caplog):
    _mock(_vuldb_response([], remaining=5))
    with caplog.at_level("WARNING"):
        await vuldb.fetch_cves("apache")
    assert any("credits low" in r.message.lower() for r in caplog.records)


@pytest.mark.asyncio
@respx.mock
async def test_adequate_credits_no_warning(caplog):
    _mock(_vuldb_response([], remaining=100))
    with caplog.at_level("WARNING"):
        await vuldb.fetch_cves("apache")
    assert not any("credits" in r.message.lower() for r in caplog.records)


# ── malformed entries ───────────────────────────────────────────────────────

@pytest.mark.asyncio
@respx.mock
async def test_non_dict_entry_is_skipped():
    _mock(_vuldb_response(["not a dict", _ENTRY_APACHE]))
    results = await vuldb.fetch_cves("apache")
    assert len(results) == 1
    assert results[0]["id"] == "CVE-2024-38476"


@pytest.mark.asyncio
@respx.mock
async def test_entry_without_id_is_skipped():
    no_id = {"source": {}, "advisory": {}, "vulnerability": {"title": "Apache Bug"}}
    _mock(_vuldb_response([no_id, _ENTRY_APACHE]))
    results = await vuldb.fetch_cves("apache")
    assert len(results) == 1


# ── signature compatibility ─────────────────────────────────────────────────

@pytest.mark.asyncio
@respx.mock
async def test_days_back_is_accepted():
    """days_back is part of the collector interface, even though VulDB ignores it."""
    _mock(_vuldb_response([_ENTRY_APACHE]))
    results = await vuldb.fetch_cves("apache", days_back=90)
    assert len(results) == 1


# ── api_key helper ──────────────────────────────────────────────────────────

def test_api_key_returns_key_when_set(monkeypatch):
    monkeypatch.setenv(vuldb.API_KEY_ENV, "my-key")
    assert vuldb.api_key() == "my-key"


def test_api_key_returns_none_when_unset(monkeypatch):
    monkeypatch.delenv(vuldb.API_KEY_ENV, raising=False)
    assert vuldb.api_key() is None


def test_api_key_returns_none_for_blank(monkeypatch):
    monkeypatch.setenv(vuldb.API_KEY_ENV, "   ")
    assert vuldb.api_key() is None


def test_the_keyword_reaches_vuldb_as_one_form_field():
    """The body was built as f"search={keyword}&details=1": a software name with
    `&`, `=` or a space was cut or added parameters to the request. It is
    form-encoded now, so whatever the watchlist holds arrives as one value."""
    for keyword in ("AT&T Connect", "foo&details=0", "a=b c", "Ünïcode +1"):
        body = vuldb.request_body(keyword)
        assert parse_qs(body, strict_parsing=True) == {"search": [keyword], "details": ["1"]}
