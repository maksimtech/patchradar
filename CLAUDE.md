# PatchRadar — CLAUDE.md

Contesto rapido per riprendere il lavoro senza dover ricostruire la storia.

## Cos'è

CVE intelligence per stack software aziendali. Aggrega NVD, KEV, EPSS, MSRC,
Debian/Ubuntu e segnala quali CVE toccano il software in inventario, con
priorità CVSS + exploit maturity. Lega ogni segnalazione alla norma di legge
(GDPR, NIS2, ecc.) che la richiede. API FastAPI + CLI Typer + Docker.

Repo: <https://github.com/maksimtech/patchradar>

## Struttura

```
src/patchradar/
  law_fetcher.py   # scarica GDPR/NIS2 da Cellar/EUR-Lex e Consumer Code da Normattiva
  law_checker.py   # confronta testo attuale col cache SHA-256
  law_cache.py     # ~/.patchradar/law_cache.json
  collectors/      # NVD, KEV, EPSS, MSRC, Debian …
  affected.py      # matching CVE ↔ inventario
  priority.py      # scoring finale
  cli.py           # entry point `patchradar`
  api/             # FastAPI app
  db/              # aiosqlite migrations
tests/             # ~2028 test, pytest-asyncio auto
```

## Comandi essenziali

```bash
pip install -e . --break-system-packages   # prima volta / dopo pyproject changes
pip install hypothesis --break-system-packages  # per test_properties.py

# Test
python -m pytest tests/test_law_fetcher.py -q          # solo law_fetcher
python -m pytest -q --ignore=tests/test_properties.py  # tutto tranne hypothesis
python -m pytest -q                                     # tutto (serve hypothesis)

# Coverage law_fetcher (100% — mantenere così)
python -m pytest tests/test_law_fetcher.py \
  --cov=patchradar.law_fetcher --cov-report=term-missing -q

# Linting
ruff check src/ tests/
mypy src/
```

## law_fetcher.py — decisioni chiave

**Sorgenti EU:** Cellar (`publications.europa.eu/resource/celex/{celex}`) è la
prima scelta; EUR-Lex (`eur-lex.europa.eu`) è il fallback (ora risponde 202 +
WAF challenge ma potrebbe tornare disponibile). Entrambi i fallimenti sono
riportati insieme nell'eccezione.

**Redirect HTTP→HTTPS:** Cellar risponde 303 → `http://` (misurato 2026-10-11).
`_get_over_https()` aggiorna lo schema a `https://` prima di ogni hop, non
dopo. Il file non arriva mai in chiaro.

**Layout HTML riconosciuti:**
- ELI / Official Journal: `<div id="art_5">` + `<div id="005.001">` per paragrafo
- Consolidated EUR-Lex: `<p class="title-article-norm">Articolo 5</p>` + `<p class="norm">`
- Normattiva (Akoma Ntoso): `<div class="bodyTesto">` + `<h2 class="article-num-akn" id="art_5">` + `<div class="art-comma-div-akn">` + `<div class="pointedList-rest-akn">`

**Normattiva:** Consumer Code (`CONSUMER_CODE`) — un articolo per request, URN
come chiave, marker `(( ))` rimossi da `_without_update_marks()`.

**Coverage:** `law_fetcher.py` è al 100%. Non rompere questo invariante.

## Atti monitorati

| Costante       | CELEX / URN                                           | Fonte       |
|----------------|-------------------------------------------------------|-------------|
| `GDPR`         | `32016R0679`                                          | EUR-Lex     |
| `EPRIVACY`     | `02002L0058-20091219` (consolidato 19.12.2009)        | EUR-Lex     |
| `NIS2`         | `32022L2555`                                          | EUR-Lex     |
| `DIGITAL_CONTENT` | `32019L0770`                                       | EUR-Lex     |
| `CONSUMER_CODE` | `urn:nir:stato:decreto.legislativo:2005-09-06;206`   | Normattiva  |

## Convenzioni di test

- `_client(handler)` → `httpx.Client(transport=httpx.MockTransport(handler))` — **senza** `follow_redirects=True` (patchradar gestisce i redirect a mano)
- `monkeypatch.setattr(law_fetcher, "fetch_html", fake)` per mock HTTP
- `NOW = datetime(2026, 9, 19, 14, 0, tzinfo=UTC)` nei test di fetch_provisions
- Fixture HTML inline come costanti `_UPPER_SNAKE_HTML` prima dei test che le usano

## Git

Branch principale: `main`. Push diretto (no PR richiesta per fix/test).
Prefissi commit: `fix(scope):`, `test(scope):`, `feat(scope):`, `docs(scope):`.

Attribuzione da aggiungere in fondo a ogni commit:
```
Co-Authored-By: Claude Sonnet 4.6 <noreply@anthropic.com>
Claude-Session: https://claude.ai/code/session_0154qVT8TUGnkx4DFoZCbD76
```

## PR aperte / stato attuale (12 ottobre 2026)

- `law_fetcher.py`: 100% coverage, tutto pushato su main
- Ultimi commit su main: `47ab50f` (100% coverage), `bb23124` (redirect paths), `ed6f915` (fix HTTPS #44)

## Dipendenze note mancanti in questa sessione cloud

```bash
pip install aiosqlite pytest-asyncio hypothesis --break-system-packages
pip install -e . --break-system-packages
```

## Radar correlati (stesso org GitHub maksimtech)

- **mailradar** — monitoraggio email security (SPF/DKIM/DMARC)
- **exeradar** — analisi eseguibili / supply chain
- Stessa struttura, stesse convenzioni, stessa CI

## Note veloci

- `Provision.key = (celex, article)` — univoco cross-act (art. 5 esiste sia in GDPR che ePrivacy)
- `text_sha256(text)` su UTF-8 — chiunque può ricomputarlo da `~/.patchradar/law_cache.json`
- `CELLAR_TYPE = "application/xhtml+xml"` — `text/html` risponde 404, `text/html;notice=branch` risponde 400
- `CELLAR_LANGUAGES = {"IT": "ita", ...}` — Cellar vuole ISO 639-2, non i due lettere
