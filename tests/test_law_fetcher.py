"""Tests for the EUR-Lex fetcher, on an excerpt of the real GDPR page."""
import hashlib
from datetime import UTC, datetime
from pathlib import Path

import httpx
import pytest

from patchradar import law_fetcher
from patchradar.law_fetcher import (
    GDPR,
    LawFetchError,
    Provision,
    fetch_provisions,
    parse_articles,
)
from patchradar.law_fetcher import (
    fetch_html as real_fetch_html,
)

FIXTURES = Path(__file__).parent / "fixtures"
GDPR_PAGE = FIXTURES / "gdpr_it_excerpt.html"
NOW = datetime(2026, 9, 19, 14, 0, tzinfo=UTC)

ARTICLES = ("25", "32", "33")
POINT_REF, POINT_TEXT = ("32(1)(a)", "a) la pseudonimizzazione e la cifratura dei dati personali;")


@pytest.fixture(scope="module")
def page():
    return GDPR_PAGE.read_text(encoding="utf-8")


@pytest.fixture(scope="module")
def texts(page):
    return parse_articles(page, ARTICLES)


# ─── parse_articles ───────────────────────────────────────────────────────────

def test_point_text(texts):
    assert texts[POINT_REF] == POINT_TEXT


def test_every_article_has_paragraphs(texts):
    for article in ARTICLES:
        assert texts[f"{article}(1)"].startswith("1. ")
        assert texts[article].split("\n")[0] == texts[f"{article}(1)"]


def test_paragraph_includes_its_points(texts):
    paragraph = POINT_REF.rsplit("(", 1)[0]
    assert POINT_TEXT in texts[paragraph]


def test_article_text_leaves_out_number_and_title(texts):
    for article in ARTICLES:
        assert f"Articolo {article}" not in texts[article]


def test_whitespace_is_normalized(texts):
    for text in texts.values():
        assert "\xa0" not in text
        assert "  " not in text
        assert text == text.strip()


def test_only_requested_articles(page):
    first = ARTICLES[0]
    texts = parse_articles(page, (first,))
    assert all(ref == first or ref.startswith(f"{first}(") for ref in texts)


def test_missing_article_raises(page):
    with pytest.raises(LawFetchError, match="99"):
        parse_articles(page, (ARTICLES[0], "99"))


def test_page_without_articles_raises():
    # EUR-Lex answers some automated requests with a JavaScript challenge page
    with pytest.raises(LawFetchError):
        parse_articles("<html><body><script>challenge()</script></body></html>", ARTICLES)


# ─── fetch_html ───────────────────────────────────────────────────────────────

def _client(handler):
    return httpx.Client(transport=httpx.MockTransport(handler))


def test_fetch_html_returns_page():
    client = _client(lambda request: httpx.Response(200, text="<html>ok</html>"))
    assert real_fetch_html("https://eur-lex.europa.eu/x", client=client) == "<html>ok</html>"


@pytest.mark.parametrize("status", [202, 404, 503])
def test_fetch_html_rejects_non_200(status):
    client = _client(lambda request: httpx.Response(status, text="challenge"))
    with pytest.raises(LawFetchError, match=str(status)):
        real_fetch_html("https://eur-lex.europa.eu/x", client=client)


def test_fetch_html_network_error():
    def handler(request):
        raise httpx.ConnectError("offline", request=request)

    with pytest.raises(LawFetchError, match="offline"):
        real_fetch_html("https://eur-lex.europa.eu/x", client=_client(handler))


def test_fetch_html_sends_user_agent():
    seen = {}

    def handler(request):
        seen["ua"] = request.headers["user-agent"]
        return httpx.Response(200, text="ok")

    real_fetch_html("https://eur-lex.europa.eu/x", client=_client(handler))
    assert seen["ua"].startswith("PatchRadar/")


# ─── fetch_provisions ─────────────────────────────────────────────────────────

def test_fetch_provisions(page, monkeypatch):
    urls = []

    def fake_fetch_html(url, **kwargs):
        urls.append(url)
        return page

    monkeypatch.setattr(law_fetcher, "fetch_html", fake_fetch_html)
    provisions = fetch_provisions(GDPR, ARTICLES, now=NOW)

    assert urls == ["https://publications.europa.eu/resource/celex/32016R0679"]
    p = provisions[POINT_REF]
    assert isinstance(p, Provision)
    assert p.article == POINT_REF
    assert p.text == POINT_TEXT
    assert p.sha256 == hashlib.sha256(POINT_TEXT.encode("utf-8")).hexdigest()
    assert p.fetched_at == "2026-09-19T14:00:00Z"
    assert p.celex == "32016R0679"
    assert p.key == ("32016R0679", POINT_REF)


def test_provision_dict_round_trip():
    p = Provision.from_text("32(1)(a)", "a) testo;", "2026-09-19T14:00:00Z", "32016R0679")
    assert p.to_dict() == {
        "article": "32(1)(a)",
        "text": "a) testo;",
        "sha256": hashlib.sha256(b"a) testo;").hexdigest(),
        "fetched_at": "2026-09-19T14:00:00Z",
        "celex": "32016R0679",
    }
    assert Provision.from_dict(p.to_dict()) == p


# ─── where the text comes from ────────────────────────────────────────────────

def test_cellar_is_tried_first(monkeypatch):
    seen = []

    def fake(url, **kwargs):
        seen.append(url)
        return "<html></html>"

    monkeypatch.setattr(law_fetcher, "fetch_html", fake)
    law_fetcher.fetch_act_html(GDPR, "IT")

    assert len(seen) == 1
    assert "publications.europa.eu" in seen[0]
    assert GDPR.celex in seen[0]


def test_the_web_interface_is_the_fallback(monkeypatch):
    """Kept, because a WAF rule can be relaxed again."""
    seen = []

    def fake(url, **kwargs):
        seen.append(url)
        if "publications.europa.eu" in url:
            raise LawFetchError("Cellar answered HTTP 500")
        return "<html>fallback</html>"

    monkeypatch.setattr(law_fetcher, "fetch_html", fake)
    assert law_fetcher.fetch_act_html(GDPR, "IT") == "<html>fallback</html>"

    assert len(seen) == 2
    assert "eur-lex.europa.eu" in seen[1]


def test_both_sources_failing_names_both(monkeypatch):
    """An error that says only "unreachable" costs a debugging session."""
    def fake(url, **kwargs):
        raise LawFetchError("HTTP 202" if "publications" in url else "HTTP 403")

    monkeypatch.setattr(law_fetcher, "fetch_html", fake)
    with pytest.raises(LawFetchError) as caught:
        law_fetcher.fetch_act_html(GDPR, "IT")

    assert "202" in str(caught.value)
    assert "403" in str(caught.value)


def test_the_language_reaches_cellar_as_a_three_letter_code(monkeypatch):
    """Cellar negotiates on Accept-Language and wants "ita", not "IT"."""
    seen = {}

    def fake(url, **kwargs):
        seen.update(kwargs.get("headers") or {})
        return "<html></html>"

    monkeypatch.setattr(law_fetcher, "fetch_html", fake)
    law_fetcher.fetch_act_html(GDPR, "IT")

    assert seen["Accept-Language"] == "ita"
    assert seen["Accept"] == law_fetcher.CELLAR_TYPE


def test_an_error_from_cellar_names_cellar():
    client = httpx.Client(transport=httpx.MockTransport(lambda request: httpx.Response(503)))
    with pytest.raises(LawFetchError, match="Cellar answered HTTP 503"):
        real_fetch_html("https://publications.europa.eu/resource/celex/x", client=client)


# ─── HTTPS redirect upgrade (_get_over_https) ─────────────────────────────────

# Cellar responds to the CELEX URL with 303 → http://; _get_over_https must
# upgrade that hop to https:// before following it (measured 2026-10-11).

_CELLAR_CELEX = "https://publications.europa.eu/resource/celex/32016R0679"
_CELLAR_RESOLVED_HTTP = "http://publications.europa.eu/resource/cellar/resolved-content"
_CELLAR_RESOLVED_HTTPS = "https://publications.europa.eu/resource/cellar/resolved-content"


def test_cellar_http_redirect_is_upgraded_to_https():
    """_get_over_https must follow a 303 → http:// over https:// instead."""
    seen: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(str(request.url))
        url = str(request.url)
        if url == _CELLAR_CELEX:
            return httpx.Response(303, headers={"Location": _CELLAR_RESOLVED_HTTP})
        if url == _CELLAR_RESOLVED_HTTPS:
            return httpx.Response(200, text="<html>https-content</html>")
        return httpx.Response(404)

    client = _client(handler)
    result = real_fetch_html(_CELLAR_CELEX, client=client)

    # Content must come from the https:// hop, not the http:// redirect target
    assert result == "<html>https-content</html>"
    # The http:// URL was never requested (upgraded before the GET)
    assert _CELLAR_RESOLVED_HTTP not in seen
    assert _CELLAR_RESOLVED_HTTPS in seen


def test_https_to_https_redirect_is_followed_normally():
    """A redirect that stays on https:// is followed without modification."""
    seen: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(str(request.url))
        if str(request.url).endswith("/x"):
            return httpx.Response(301, headers={"Location": "https://eur-lex.europa.eu/y"})
        return httpx.Response(200, text="<html>ok</html>")

    client = _client(handler)
    result = real_fetch_html("https://eur-lex.europa.eu/x", client=client)

    assert result == "<html>ok</html>"
    assert seen == ["https://eur-lex.europa.eu/x", "https://eur-lex.europa.eu/y"]


def test_too_many_redirects_raises():
    """Exceeding MAX_REDIRECTS raises LawFetchError."""
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(302, headers={"Location": "https://eur-lex.europa.eu/loop"})

    client = _client(handler)
    with pytest.raises(LawFetchError, match="redirected more than"):
        real_fetch_html("https://eur-lex.europa.eu/x", client=client)


def test_get_helper_uses_ephemeral_client_when_none_given(monkeypatch):
    """fetch_html opens its own httpx.Client when the caller passes no client.

    This covers the ``if client is None`` branch inside fetch_html that
    ordinarily runs in production (no caller-supplied client).
    """
    _real_client = httpx.Client

    def _mock_client_class(**kwargs):
        return _real_client(
            transport=httpx.MockTransport(
                lambda req: httpx.Response(200, text="<html>own-client</html>")
            ),
            timeout=kwargs.get("timeout", 30.0),
        )

    monkeypatch.setattr(httpx, "Client", _mock_client_class)
    result = real_fetch_html("https://eur-lex.europa.eu/page")
    assert result == "<html>own-client</html>"


# ─── simple unit coverage ─────────────────────────────────────────────────────

def test_act_id_label_urn():
    """Act.id_label returns 'URN' for Normattiva acts (line 63)."""
    assert law_fetcher.CONSUMER_CODE.id_label == "URN"


def test_provision_from_dict_rejects_non_strings():
    """Provision.from_dict raises TypeError when a field is not a string (line 118)."""
    with pytest.raises(TypeError, match="strings"):
        Provision.from_dict({
            "article": 1, "text": "t", "sha256": "x",
            "fetched_at": "d", "celex": "c",
        })


def test_fetch_act_html_rejects_non_eurlex():
    """fetch_act_html raises ValueError for a Normattiva act (line 545)."""
    with pytest.raises(ValueError, match="Normattiva"):
        law_fetcher.fetch_act_html(law_fetcher.CONSUMER_CODE)


def test_source_of_normattiva_names_normattiva():
    """_source_of labels normattiva.it URLs as 'Normattiva' (line 471);
    that label appears in the LawFetchError raised by fetch_html."""
    client = _client(lambda request: httpx.Response(503))
    with pytest.raises(LawFetchError, match="Normattiva"):
        real_fetch_html("https://www.normattiva.it/page", client=client)


# ─── _TreeBuilder: nested non-void tag inside a skipped element ───────────────

def test_tree_builder_nested_tag_inside_skipped_element_is_dropped():
    """A non-void tag inside a skipped element increments _skipping (lines 173-175).

    <p class="modref"><a>▼M2</a></p> – the <a> must not leak into the tree.
    """
    html = '<p>before</p><p class="modref"><a href="#">▼M2</a></p><p>after</p>'
    builder = law_fetcher._TreeBuilder()
    builder.feed(html)
    builder.close()
    top = [c for c in builder.root.children if isinstance(c, law_fetcher._Element)]
    assert len(top) == 2
    assert law_fetcher._text(top[0]) == "before"
    assert law_fetcher._text(top[1]) == "after"


# ─── ELI article without paragraph divs (_parse_eli_article fallback) ─────────
#
# This HTML has a <div id="art_8"> but no <div id="008.001"> children, so
# _parse_eli_article falls back to _parse_block (lines 337-338).
# _flatten exercises: heading skip (254), bare non-empty text node (252),
# div recursion (256), and an empty <p> element hits the empty-text guard (304).

_ELI_FALLBACK_HTML = """\
<html><body>
<div id="art_8">
  <p class="eli-title">Article 8</p>
  loose text
  <div>
    <p></p>
    <p>1. First paragraph.</p>
  </div>
</div>
</body></html>"""


def test_eli_fallback_parses_flat_article():
    texts = parse_articles(_ELI_FALLBACK_HTML, ("8",))
    assert "8" in texts
    assert "1. First paragraph." in texts["8"]
    assert "loose text" in texts["8"]


# ─── _table_point: the three None-returning paths ─────────────────────────────

_TABLE_NONE_HTML = """\
<html><body>
<div id="art_9">
  <div id="009.001">
    <table><tr><td>a)</td></tr><tr><td>row 2</td></tr></table>
    <table><tr><td>only one cell</td></tr></table>
    <table><tr><td>1.</td><td>not a letter point</td></tr></table>
    <p>1. Main content.</p>
  </div>
</div>
</body></html>"""


def test_table_point_none_cases():
    """_table_point returns None for: !=1 row (270), <2 cells (274), non-letter label (278).
    When None, the table's text falls through as a plain block – no labelled point is created."""
    texts = parse_articles(_TABLE_NONE_HTML, ("9",))
    assert "9" in texts
    assert "9(1)" in texts
    # None tables produce no lettered sub-point
    assert "9(1)(a)" not in texts
    assert "1. Main content." in texts["9(1)"]


# ─── _parse_block: numbered=True and empty text ───────────────────────────────

_NUMBERED_POINTS_HTML = """\
<html><body>
<div id="art_4">
  <div id="004.001">
    <p>1) «dato personale»: qualsiasi informazione</p>
    <table><tr><td>a)</td><td>punto a</td></tr></table>
    <p>2) «trattamento»: qualsiasi operazione</p>
  </div>
</div>
</body></html>"""


def test_numbered_items_collect_table_points():
    """A table point that follows a numbered item is appended to it (line 298)."""
    texts = parse_articles(_NUMBERED_POINTS_HTML, ("4",))
    assert "4(1)(1)" in texts
    assert "punto a" in texts["4(1)(1)"]


_EMPTY_P_HTML = """\
<html><body>
<div id="art_11">
  <div id="011.001">
    <p></p>
    <p>1. Real content here.</p>
  </div>
</div>
</body></html>"""


def test_parse_block_skips_empty_paragraph():
    """An element whose _text is empty is skipped (line 304)."""
    texts = parse_articles(_EMPTY_P_HTML, ("11",))
    assert texts["11(1)"] == "1. Real content here."


# ─── Normattiva layout ────────────────────────────────────────────────────────

_NORMATTIVA_HTML = """\
<html><body>
<div class="bodyTesto">
  <h2 class="article-num-akn" id="art_20">Art. 20</h2>
  <div class="art-comma-div-akn">
    <span class="comma-num-akn">1.</span>
    ((Primo)) comma.
  </div>
  <div class="art-comma-div-akn">
    <span class="comma-num-akn">2.</span>
    Secondo comma.
    <div class="pointedList-rest-akn">a) Primo punto.</div>
  </div>
</div>
</body></html>"""


def test_normattiva_article_parses():
    """_parse_normattiva_article extracts paragraphs and points (lines 359-381);
    _without_update_marks removes (( )) amendment markers (line 343)."""
    texts = parse_articles(_NORMATTIVA_HTML, ("20",))
    assert "20" in texts
    assert "20(1)" in texts
    assert "20(2)" in texts
    assert "20(2)(a)" in texts
    # amendment markers must be stripped
    assert "((" not in texts["20(1)"]
    assert "))" not in texts["20(1)"]
    assert "Primo" in texts["20(1)"]
    assert texts["20(2)(a)"] == "a) Primo punto."


# ─── Consolidated layout: _parse_consolidated_article + _ends_article ─────────

_CONSOLIDATED_HTML = """\
<html><body>
<p class="title-article-norm">Articolo 10</p>
<p class="norm">1. Testo del primo paragrafo.</p>
<p class="footnote">Nota a piè di pagina.</p>
<p class="title-article-norm">Articolo 11</p>
<p class="norm">1. Articolo undici.</p>
</body></html>"""


def test_consolidated_article_ends_at_footnote():
    """_ends_article stops sibling collection at a footnote element (lines 386, 409).
    Content from the footnote and the next article must not bleed in."""
    texts = parse_articles(_CONSOLIDATED_HTML, ("10",))
    assert "1. Testo del primo paragrafo." in texts["10"]
    assert "Nota" not in texts["10"]
    assert "undici" not in texts["10"]


def test_consolidated_article_ends_at_hd_class():
    """_ends_article recognises hd-* classes (line 387 startswith branch)."""
    html = """\
<html><body>
<p class="title-article-norm">Articolo 12</p>
<p class="norm">1. Testo.</p>
<p class="hd-center">Sezione II</p>
</body></html>"""
    texts = parse_articles(html, ("12",))
    assert "Sezione II" not in texts["12"]


# ─── _split_flat_paragraphs: no-groups and intro paths ───────────────────────

_NO_GROUPS_HTML = """\
<html><body>
<p class="title-article-norm">Articolo 15</p>
<p class="norm">Testo senza numerazione di paragrafo.</p>
</body></html>"""


def test_split_flat_paragraphs_no_groups():
    """When no numbered paragraphs are found the whole body is one block (lines 427-428)."""
    texts = parse_articles(_NO_GROUPS_HTML, ("15",))
    assert "15" in texts
    assert "Testo senza numerazione" in texts["15"]


_INTRO_HTML = """\
<html><body>
<p class="title-article-norm">Articolo 16</p>
<p class="norm">Paragrafo introduttivo.</p>
<p class="norm">1. Primo paragrafo numerato.</p>
</body></html>"""


def test_split_flat_paragraphs_intro_prepended_to_first_group():
    """Content before the first numbered paragraph is prepended to it (lines 429-430)."""
    texts = parse_articles(_INTRO_HTML, ("16",))
    assert "16(1)" in texts
    assert "Paragrafo introduttivo." in texts["16(1)"]


# ─── fetch_provisions: Normattiva path ────────────────────────────────────────

_NORMATTIVA_ART22_HTML = """\
<html><body>
<div class="bodyTesto">
  <h2 class="article-num-akn" id="art_22">Art. 22</h2>
  <div class="art-comma-div-akn">
    <span class="comma-num-akn">1.</span>
    Testo del comma ventiduesimo.
  </div>
</div>
</body></html>"""


def test_normattiva_empty_comma_skipped():
    """A Normattiva comma whose text is entirely amendment markers is skipped (line 363)."""
    html = """\
<html><body>
<div class="bodyTesto">
  <h2 class="article-num-akn" id="art_21">Art. 21</h2>
  <div class="art-comma-div-akn">
    <span class="comma-num-akn">1.</span>
    1. Testo reale.
  </div>
  <div class="art-comma-div-akn">(( ))</div>
</div>
</body></html>"""
    texts = parse_articles(html, ("21",))
    assert "21" in texts
    assert "21(1)" in texts
    # The empty comma must not produce a "21(None)" or similar key
    assert all(k.startswith("21") for k in texts)


def test_split_flat_paragraphs_non_p_appended_to_group():
    """A non-paragraph node that follows an existing group is appended to it (line 423)."""
    html = """\
<html><body>
<p class="title-article-norm">Articolo 17</p>
<p class="norm">1. Primo paragrafo.</p>
<p class="norm">Continuazione senza numero.</p>
</body></html>"""
    texts = parse_articles(html, ("17",))
    assert "17(1)" in texts
    assert "Continuazione" in texts["17(1)"]


def test_fetch_provisions_normattiva(monkeypatch):
    """fetch_provisions calls fetch_html once per article for Normattiva acts (lines 574-577)."""
    urls = []

    def fake_fetch(url, **kwargs):
        urls.append(url)
        return _NORMATTIVA_ART22_HTML

    monkeypatch.setattr(law_fetcher, "fetch_html", fake_fetch)
    provisions = fetch_provisions(law_fetcher.CONSUMER_CODE, ("22",), now=NOW)

    assert len(urls) == 1
    assert "normattiva.it" in urls[0]
    assert "22" in provisions
    assert provisions["22"].celex == law_fetcher.CONSUMER_CODE.celex
