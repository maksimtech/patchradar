# Changelog

Tutte le modifiche rilevanti a PatchRadar sono documentate in questo file.

Il formato segue [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).
Il progetto usa versionamento **CalVer** (`YYYY.M.PATCH`), non SemVer.

---

## [2026.9.3] — 2026-09-18

Chiude i warning dell'audit: una scansione fallita non si presenta più come
"nessuna CVE", la CSP blocca davvero gli script iniettati, le date di fonti
diverse si ordinano cronologicamente e SonarCloud misura di nuovo la coverage.

### Security

- **CSP con `'unsafe-inline'` su `script-src`.** La pagina usava handler inline
  (`onclick=`, `onkeydown=`, `oninput=`, `onchange=`) e un blocco `<script>`
  inline, quindi la policy doveva ammettere script inline e non fermava nulla:
  un attributo `on*=` sfuggito all'escaping sarebbe stato eseguito. Lo script è
  stato spostato in `/static/app.js` e ogni handler è collegato con
  `addEventListener`, così `script-src` è ora solo `'self'`. Aggiunti anche
  `object-src 'none'` e `base-uri 'none'`. Togliere i soli handler non sarebbe
  bastato: con `script-src 'self'` anche il blocco `<script>` inline viene
  rifiutato, e la pagina non avrebbe eseguito nulla.
- **Caratteri di controllo nelle risposte API.** `sanitize_cve` dichiarava di
  rimuovere "null bytes and control characters" ma rimuoveva solo `\x00`. ESC,
  BEL, backspace e i controlli C1 (incluso `\x9b`, il CSI a 8 bit) arrivavano
  nella risposta, e gli stessi record sono stampati a terminale dalla CLI, dove
  ESC apre una sequenza ANSI. Ora vengono rimossi tutti i controlli C0, DEL e C1,
  tranne tab e a capo; `\r\n` e `\r` sono normalizzati in `\n`.

### Fixed

- **Un errore della fonte appariva come "nessuna CVE".** Ogni collector catturava
  qualsiasi eccezione e restituiva `[]`: un 403/429 di NVD (che limita i client
  senza chiave a 5 richieste ogni 30 secondi), un 503 di Debian, un errore DNS o
  un proxy che risponde in HTML producevano lo stesso output di una scansione
  pulita: `nginx — no CVEs found`. Per un monitor di vulnerabilità è il modo
  peggiore di fallire. Ora i collector sollevano `CollectorError` con fonte,
  motivo (`rate_limited`, `forbidden`, `server_error`, `http_error`, `network`,
  `bad_payload`) e codice HTTP; la CLI indica quale fonte è fallita e dichiara i
  risultati incompleti, e la UI mostra "Scan incomplete" invece di "Found 0 CVEs".
- **Ordinamento delle CVE non cronologico.** Ogni fonte salvava la data nel
  proprio formato: NVD `2026-08-15T00:00:00.000` senza fuso, Debian con
  `+00:00` e microsecondi, MSRC senza fuso, con `Z` o con un offset. La colonna è
  TEXT, quindi `ORDER BY published_at DESC` confrontava stringhe:
  `…T20:00:00-07:00` (le 03:00 UTC del giorno dopo) finiva dopo
  `…T23:00:00+00:00`, e con `LIMIT` le CVE più recenti potevano uscire dalla
  pagina. Le date sono ora normalizzate al salvataggio in un unico formato UTC a
  larghezza fissa, `YYYY-MM-DDTHH:MM:SSZ`; gli orari senza fuso sono letti come
  UTC, come li pubblicano NVD e MSRC, indipendentemente dal fuso della macchina.
- **La UI si bloccava su qualsiasi errore dell'API.** `api()` segnalava l'errore e
  poi restituiva `{}`, e quasi ogni chiamante lo dereferenziava: `loadWatchlist`
  sollevava `TypeError` e interrompeva il caricamento della pagina, `loadStats`
  scriveva `undefined` nelle card, `addSoftware` sovrascriveva l'errore reale con
  "already in watchlist", `removeSoftware` confermava "Removed" anche se nulla era
  stato rimosso, `openCveDetail` apriva una modale vuota su un 404. Una risposta
  200 non JSON sfuggiva come rejection non gestita perché `r.json()` non era
  atteso dentro il `try`.
- **Crash di `patchradar status` su severity nulla.** `cve.get("severity",
  "UNKNOWN").upper()` usa il default solo se la chiave manca; la colonna è
  nullable, quindi una riga con severity `NULL` sollevava `AttributeError`.
- **Punteggio CVSS 0.0 mostrato come "N/A".** Nella CLI e nella UI il test era
  sulla veridicità del valore, e `0.0` è falso: un punteggio reale di zero era
  indistinguibile da "nessun punteggio". Un punteggio arrivato come stringa
  sollevava inoltre `ValueError` nella CLI.

### Changed

- **Nuovo contratto dei collector:** una lista vuota significa solo che la fonte ha
  risposto senza CVE. I risultati già raccolti prima di un errore sono conservati
  in `CollectorError.partial` e salvati; se MSRC fallisce su un mese, i mesi già
  scaricati non vanno persi.
- Una risposta 200 con corpo vuoto o non JSON è ora un errore `bad_payload`, non
  zero CVE.
- Un 404 di MSRC continua a indicare un mese non ancora pubblicato e non è un
  errore.
- Il 403 di NVD è classificato `forbidden` e non `rate_limited`: NVD lo usa per il
  superamento della quota senza chiave, ma lo stesso codice può indicare una
  chiave non valida.
- La risposta di `POST /api/scan` include un campo `errors` con software, fonte,
  motivo e codice HTTP di ogni fonte fallita.
- All'avvio, `init_db()` riscrive nel formato canonico le date salvate prima di
  questo rilascio; i valori non interpretabili diventano `NULL` e finiscono in
  fondo all'ordinamento. L'operazione è idempotente.
- La pagina web carica lo script da `/static/app.js`, servito dalla stessa origine.
  `style-src` mantiene `'unsafe-inline'`: la pagina usa attributi `style=`, e il
  CSS non può eseguire script.

### CI

- **SonarCloud non misurava alcuna coverage.** `sonar.coverage.exclusions=**/*`
  escludeva ogni file, e il workflow non generava comunque un report: rimuovere
  solo l'esclusione avrebbe mostrato 0%. Il workflow ora esegue la suite con
  `pytest --cov` e produce `coverage.xml` prima della scansione, Sonar lo legge
  tramite `sonar.python.coverage.reportPaths`, e l'esclusione è limitata a
  `static/**` e `templates/**` (JS e HTML, esercitati dall'harness Node che non
  produce un report di coverage). `relative_files = true` rende i percorsi del
  report relativi al checkout, così SonarCloud li risolve. Il quality gate
  potrebbe diventare rosso alla prima analisi, ora che vede la coverage reale.

### Added

- Harness Node (`tests/js/ui_harness.js`) che esegue lo script reale della pagina
  su un DOM minimo con `fetch` simulato. Non esegue gli attributi `on*=`, come un
  browser sotto la nuova CSP, quindi un controllo risulta funzionante solo se lo
  script lo ha davvero collegato.
- Suite di test portata da 370 a **912 test**.

---

## [2026.9.2] — 2026-09-17

Chiude i difetti di logica emersi dall'audit del codice: falsi positivi e falsi
negativi nei collector, validazione mancante sull'import e isolamento del
database nei test.

### Security

- **Import della watchlist senza alcuna validazione.** `POST /api/watchlist/import`
  applicava solo `strip().lower()[:100]`, mentre `POST /api/watchlist/{software}`
  imponeva `^[\w\s\-\.]+$` e `max_length=100`. Tutto ciò che la route path
  rifiutava poteva essere introdotto dall'import: `evil<script>alert(1)</script>`
  e `evil[bold]x` finivano entrambi in database. Entrambe le route ora condividono
  `normalise_software_name()`, quindi non possono più divergere.
- **Nomi multi-riga ammessi dal validatore.** Il pattern usava `\s`, che include
  newline e tab: `"a\nb"` era un nome valido su entrambe le route. Sostituito con
  uno spazio letterale (`^[\w \-\.]+$`).
- **`DELETE /api/watchlist/<nome>` cancellava dati mai richiesti.** La cancellazione
  a cascata delle CVE veniva eseguita incondizionatamente, anche quando il software
  non era in watchlist: la chiamata restituiva `false` e intanto svuotava lo storico
  CVE di quel nome. Ora la cascata avviene solo se una riga è stata davvero rimossa.

### Fixed

- **Dati del container persi a ogni riavvio.** `docker-compose.yml` montava il
  volume su `/root/.patchradar`, ma l'immagine gira come utente non privilegiato
  `patchradar` e l'applicazione scrive in `/home/patchradar/.patchradar`. Il volume
  restava vuoto e watchlist e storico CVE sparivano a ogni ricreazione del
  container — in silenzio, perché il database veniva comunque creato nel filesystem
  interno. Verificato end-to-end sull'immagine pubblicata.
- **7.924 CVE fantasma dal Security Tracker Debian.** Quando un pacchetto non aveva
  alcuna voce per la release target, `releases.get(release, {})` restituiva un dict
  vuoto, lo `status` risultava `""` — che non è `"resolved"` — e la CVE veniva
  riportata come **aperta**. Misurato sul feed reale: 7.924 CVE prive di voce
  `trixie` su tutto il tracker. Per pacchetto: **postgresql 109 → 0** (100% rumore),
  **python 332 → 173** (47%), **linux 2.226 → 1.631** (26%). Lo status passa inoltre
  da blacklist a whitelist `{open, undetermined}`.
- **Un intero Patch Tuesday mancante.** I mesi MSRC erano ricavati a passi di 30
  giorni, che non possono enumerare mesi di calendario: da 2026-03-31 con
  `days_back=90` la sequenza era `Dec, Jan, Mar` — **febbraio saltato del tutto**,
  quindi un Patch Tuesday completo non veniva mai scaricato. Sostituito con una
  camminata sui mesi di calendario, contigua per costruzione.
- **Severity Debian sempre UNKNOWN per le urgency che contano.** La tabella di
  mappatura era costruita sulle *bug severity* del BTS Debian (`grave`, `serious`,
  `important`, `moderate`, `critical`), che il Security Tracker non emette mai. I
  valori reali — verificati sul feed: `not yet assigned`, `unimportant`, `low`,
  `medium`, `high`, `end-of-life` — cadevano su UNKNOWN, rendendo `high` e `medium`
  invisibili ai filtri CRITICAL/HIGH e al grafico severity.
- **Un solo campo malformato interrompeva l'intera scansione.** I collector
  proteggevano con `try/except` solo la chiamata HTTP; tutto il parsing successivo
  indicizzava direttamente il JSON. `d["lang"]` sollevava `KeyError` su una
  descrizione NVD priva della chiave; `item.get("cve", {})` restituiva `None`
  quando la chiave era presente ma nulla, perché il default non scatta;
  `vuln.get("RevisionHistory", [{}])[0]` sollevava `IndexError` su una lista
  presente ma vuota.
- **Una voce MSRC malformata scartava tutto il mese.** Il `try/except` era *fuori*
  dal ciclo sulle vulnerabilità, quindi una singola eccezione faceva perdere in
  silenzio ogni CVE successiva di quel documento mensile. Spostato per-record.
- **HTTP 500 su elementi non stringa nell'import.** `sw.strip()` presupponeva una
  stringa: `{"software": [123]}` produceva `AttributeError` e un 500 anziché un
  errore di validazione.
- **Nomi dei mesi dipendenti dal locale.** `strftime('%b')` segue `LC_TIME`: su una
  macchina italiana generava `set` invece di `Sep`, ogni richiesta MSRC rispondeva
  non-200 e il collector restituiva zero CVE senza segnalare nulla. Sostituito con
  la costante `MONTH_ABBR`.
- **La suite di test scriveva sul database reale dell'utente.** I test giravano su
  `~/.patchradar/patchradar.db`, lasciandovi fixture (`testapp`, `duplicate-test`,
  un nome di 101 caratteri) e cancellandone righe. Ora una fixture di sessione
  redirige `DB_PATH` su una directory temporanea. Verificato: il database reale
  resta byte-identico (sha256 e mtime) dopo una suite completa.

### Changed

- I nomi troppo lunghi sono **rifiutati** invece che troncati silenziosamente a 100
  caratteri: monitorare un nome diverso da quello richiesto è peggio che rifiutarlo.
- Le CVE prive di `id` vengono scartate anziché salvate con `id=""`: l'id è la
  chiave primaria e più record senza id collidevano tra loro.
- `days_back` determina ora realmente i mesi MSRC interrogati. Il vecchio margine
  fisso di 30 giorni causava circa 276 richieste HTTP superflue all'anno con
  `days_back=7`.
- La risposta di `/api/watchlist/import` espone un terzo insieme `rejected` accanto
  ad `added` e `skipped`; la UI lo riporta.
- Entrambe le route della watchlist normalizzano il nome allo stesso modo, quindi
  scrivono lo stesso valore canonico in database.
- `database.py` espone `DEFAULT_DB_PATH` accanto a `DB_PATH`, così la posizione di
  produzione resta nota quando il valore attivo viene rediretto.
- La route `DELETE` resta deliberatamente permissiva (nessun pattern,
  `max_length=200`): irrigidirla renderebbe impossibile cancellare i nomi già
  finiti in database prima di questo rilascio.

### Added

- `logger.debug`/`logger.warning` sui record scartati e sui payload di forma
  inattesa, al posto del fallimento silenzioso.
- Suite di test portata da 105 a **370 test**, con file dedicati per escaping,
  hardening dello scan, contratto Docker, scope delle release Debian, enumerazione
  dei mesi MSRC, robustezza dei parser, rimozione dalla watchlist, validazione
  dell'import e isolamento del database.

---

## [2026.9.1] — 2026-09-17

Primo giro di correzioni dall'audit: markup injection nella CLI, endpoint di
health mancante, hardening di `/api/scan` e attivazione dei test in CI.

### Security

- **Markup injection nell'output della CLI.** Ogni valore di provenienza esterna
  finiva in una f-string interpretata da Rich: descrizioni CVE, nomi software e
  target di scansione. Una descrizione ostile poteva applicare colori, nascondere
  una CVE CRITICAL o piazzare un hyperlink OSC-8 cliccabile in uno strumento di
  sicurezza. Risolto con `escape()` sulle f-string e `Text()` sulle celle di
  tabella, che Rich rende sempre verbatim.
- **`/api/scan` senza autenticazione né limiti.** L'endpoint non aveva alcuna
  dipendenza di autenticazione mentre l'immagine Docker fa bind su `0.0.0.0`.
  Introdotta una API key opzionale via `PATCHRADAR_API_KEY`, confrontata con
  `hmac.compare_digest`, applicata a `/api/scan` e alle route di scrittura della
  watchlist. Quando la variabile non è impostata gli endpoint restano aperti per
  compatibilità con l'uso locale, e un warning viene emesso all'avvio.
- **Nessuna scadenza sulla scansione.** Un feed lento poteva occupare un worker
  indefinitamente (MSRC 4×30s + NVD 30s + Debian 60s per pacchetto, su una
  watchlist non limitata). Aggiunto `asyncio.timeout()` con budget configurabile
  via `PATCHRADAR_SCAN_TIMEOUT` (default 600s) e flag `timed_out` esplicito nella
  risposta, perché una scansione troncata non sembri completa.

### Fixed

- **Crash su descrizioni CVE del tutto legittime.** Percorsi Unix fra parentesi
  quadre (`[/tmp]`, `[/etc/passwd]`) sollevavano `MarkupError` e interrompevano
  `patchradar scan`; riferimenti come `[i]` venivano silenziosamente rimossi dal
  testo, corrompendo la descrizione della vulnerabilità.
- **375 MB scaricati per scansione invece di 75 MB.** Il dump del Security Tracker
  Debian (misurato: 75.173.966 byte) veniva riscaricato **una volta per pacchetto
  monitorato**: con 5 elementi in watchlist, 5 download identici. Introdotta una
  cache con TTL di un'ora e `asyncio.Lock`, che riduce il costo a un solo download
  per scansione e impedisce a scansioni concorrenti di avviarne una ciascuna. Un
  download fallito non viene mai messo in cache.
- **Healthcheck Docker sempre fallito.** Dockerfile e docker-compose sondavano
  `http://localhost:8000/health`, che non esisteva: il container risultava
  permanentemente `unhealthy`, causando loop di riavvio con
  `restart: unless-stopped` e bloccando qualsiasi `depends_on: service_healthy`.
- **La CI non eseguiva mai i test.** Il workflow `Tests` lanciava solo
  `patchradar --help` e `patchradar list`; `pytest` non veniva mai invocato. In più
  `respx`, importato dalla suite, non era dichiarato in nessun gruppo di dipendenze,
  quindi i test non erano nemmeno installabili a partire dal `pyproject.toml`.
- **Cinque test fallivano su macchina pulita.** `ASGITransport` non esegue
  l'handler `lifespan`, quindi `init_db()` non veniva mai chiamato durante i test
  API: passavano solo quando un test precedente aveva già creato il database.
- **Crash su `description=None`.** L'espressione di troncamento chiamava `len()` su
  un valore che il collector Debian può restituire nullo. Sostituita dall'helper
  `_truncate()`.

### Added

- Endpoint `GET /health` con verifica di raggiungibilità del database, che
  risponde 503 quando il database non è scrivibile. Deliberatamente non
  autenticato: un healthcheck non deve dover portare una credenziale.
- Variabili d'ambiente `PATCHRADAR_API_KEY` e `PATCHRADAR_SCAN_TIMEOUT`.
- Passo `Run test suite` nel workflow CI, su tutte e cinque le versioni di Python
  della matrice; `respx` aggiunto al gruppo di dipendenze `dev`.
- `tests/conftest.py` con inizializzazione del database a livello di sessione e
  azzeramento della cache Debian fra i test.

### Changed

- La UI conserva la API key in `localStorage` e la richiede al primo 401.
- La UI segnala esplicitamente una scansione troncata anziché mostrarla come
  completa.

---

## [2026.8.34] — 2026-08-26

### Fixed

- Documentate le risposte `HTTPException` negli endpoint API (SonarQube S8415).
- `CHANGELOG_FILE` definito come costante invece di ripetere il letterale, e
  corretta una auto-assegnazione (S1656).
- `days_back` limitato a un intervallo sicuro nel collector MSRC.
- Accessibilità della UI: `aria-label` su campo di aggiunta, import da file e
  ricerca; `role="dialog"` e `aria-modal` sull'overlay della modale (S6848);
  `Number.parseInt` al posto del `parseInt` globale (S7773).

### Changed

- Estratto `_scan_target` nella CLI e helper dedicati in `msrc.py` per ridurre la
  complessità cognitiva (S3776).

### Added

- Workflow di analisi SonarCloud basato su CI, con `pytest-cov` per il report di
  copertura.

---

## [2026.8.33] — 2026-08-25

### Security

- Il container Docker gira come utente non-root.
- `setuptools` e `msgpack` pinnati a versioni esatte; `msgpack` portato a 1.2.1 per
  correggere CVE HIGH; `--only-binary :all:` sulle installazioni pip.
- Tutte le GitHub Action dei workflow pinnate al commit SHA completo.

### Fixed

- Versione di PatchRadar pinnata e passata via `ARG` dalla CI al build Docker.
- Attesa di 60 secondi per la propagazione su PyPI prima del build Docker.
- Corretta la pubblicazione su PyPI (`release/v1` pinnato a SHA, flag di
  `pip install` sistemati, verifica dei metadati del wheel disabilitata).

### Added

- `sonar-project.properties` per un'analisi Python accurata.

---

## [2026.8.32] — 2026-08-22

### Changed

- Rimosso il marker `asyncio` globale dai test, applicato solo ai test asincroni.

---

## [2026.8.31] — 2026-08-21

### Added

- Test per il collector Debian Security Tracker.

---

## [2026.8.30] — 2026-08-20

### Added

- Collector Debian Security Tracker.

---

## [2026.8.29] — 2026-08-20

### Fixed

- Gestione degli errori nella funzione `api()` della UI.

---

## [2026.8.28] — 2026-08-20

### Security

- Aggiunto workflow dello scanner di sicurezza Trivy.
- Aggiunte configurazione Dependabot e security policy.

### Fixed

- `pkg_version` usato per la versione dell'applicazione, rimossi import duplicati.
- `save_cve` assegna il cursore, così `rowcount` viene restituito correttamente.

### Added

- Python 3.14 nella matrice CI e 3.15-dev come sperimentale.
- Configurazione Renovate.

### Changed

- Versioni minime delle dipendenze portate all'ultima stabile.
- Cinque GitHub Action aggiornate alla major successiva (Dependabot #14-#18).

---

## [2026.8.27] — 2026-08-19

### Fixed

- Correzioni varie alla UI.

### Added

- Script PowerShell per l'integrazione con winget.

---

## [2026.8.26] — 2026-08-19

### Added

- Import massivo di software nella watchlist da file.

---

## [2026.8.25] — 2026-08-19

### Added

- Filtro di ricerca sulla tabella delle CVE.

---

## [2026.8.24] — 2026-08-19

### Security

- Scansione CVE con Docker Scout nel workflow Docker.
- Permessi espliciti nei workflow per compatibilità con CodeQL.

---

## [2026.8.23] — 2026-08-19

### Security

- Immagine base portata a Debian trixie e dipendenze PyPI pinnate a versioni sicure.

---

## [2026.8.22] — 2026-08-19

### Security

- `apt-get upgrade` nel Dockerfile per correggere una vulnerabilità HIGH di OpenSSL.

---

## [2026.8.21] — 2026-08-19

### Fixed

- Le CVE orfane vengono cancellate quando il software è rimosso dalla watchlist.

### Added

- Benchmark di performance CodSpeed.

---

## [2026.8.20] — 2026-08-16

### Changed

- CHANGELOG riscritto con la cronologia completa da 2026.8.4 a 2026.8.19.

---

## [2026.8.19] — 2026-08-16

### Added

- Modale di dettaglio CVE nella UI.

### Fixed

- Overflow della watchlist nella UI.

---

## [2026.8.18] — 2026-08-16

### Changed

- README aggiornato: MSRC attivo, rimosso il changelog inline.

---

## [2026.8.17] — 2026-08-16

### Added

- Collector MSRC per il Patch Tuesday Microsoft.

---

## [2026.8.16] — 2026-08-16

### Changed

- GitHub Action aggiornate a versioni compatibili con Node.js 24.

---

## [2026.8.15] — 2026-08-16

### Fixed

- Sostituito il deprecato `@app.on_event` con l'handler `lifespan`.

---

## [2026.8.14] — 2026-08-16

### Added

- Suite di test completa: CLI, mock del collector NVD, CRUD del database.

---

## [2026.8.13] — 2026-08-16

### Added

- Supporto Docker: Dockerfile, docker-compose e `.dockerignore`.
- Workflow di build e push su Docker Hub.
- `RELEASING.md` con checklist e processo di rilascio.

---

## [2026.8.12] — 2026-08-16

### Security

- Corretta una DOM XSS (CWE-79) nel grafico severity della UI.

### Added

- Integrazione di git-cliff per la generazione automatica del changelog.

---

## [2026.8.11] — 2026-08-16

Rilascio di sola versione, nessuna modifica al codice.

---

## [2026.8.10] — 2026-08-16

### Security

- Middleware con Content-Security-Policy e header di sicurezza.
- Validazione degli input su tutti gli endpoint.
- Sanitizzazione dell'output per i dati CVE.

### Added

- Suite di test reale al posto del placeholder.
- Script `bump_version.py` e `release.py`.

---

## [2026.8.7] — 2026-08-15

### Security

- Corretta una DOM XSS (CWE-79) nella UI: `innerHTML` sostituito da
  `createElement`/`textContent`.

### Fixed

- `api/main.py` riscritto, versione dinamica nella UI.

---

## [2026.8.6] — 2026-08-14

### Fixed

- Versione dinamica nella UI e badge di versione aggiornato.

---

## [2026.8.5] — 2026-08-14

### Fixed

- Encoding UTF-8 per il template HTML su Windows.

---

## [2026.8.4] — 2026-08-14

### Changed

- Badge del README aggiornati.

---

## [2026.8.3] — 2026-08-14

Rilascio di sola versione, nessuna modifica al codice.

---

## [2026.8.2] — 2026-08-14

Primo rilascio pubblico.

### Added

- Prima release funzionante: CLI, collector NVD, database SQLite.
- UI web con dashboard, watchlist, tabella CVE e grafici.
- GitHub Actions per la pubblicazione su PyPI e per i test.

---

### Nota sulle versioni

Le versioni `2026.8.1`, `2026.8.8` e `2026.8.9` non sono mai state rilasciate: il
numero in `pyproject.toml` è stato incrementato ma non è stato creato alcun tag.
Il salto da `2026.8.34` a `2026.9.1` segue lo schema CalVer, che azzera la patch
al cambio di mese.

[2026.9.2]: https://github.com/maksimtech/patchradar/compare/2026.9.1...2026.9.2
[2026.9.1]: https://github.com/maksimtech/patchradar/compare/2026.8.34...2026.9.1
[2026.8.34]: https://github.com/maksimtech/patchradar/compare/2026.8.33...2026.8.34
[2026.8.33]: https://github.com/maksimtech/patchradar/compare/2026.8.32...2026.8.33
[2026.8.32]: https://github.com/maksimtech/patchradar/compare/2026.8.31...2026.8.32
[2026.8.31]: https://github.com/maksimtech/patchradar/compare/2026.8.30...2026.8.31
[2026.8.30]: https://github.com/maksimtech/patchradar/compare/2026.8.29...2026.8.30
[2026.8.29]: https://github.com/maksimtech/patchradar/compare/2026.8.28...2026.8.29
[2026.8.28]: https://github.com/maksimtech/patchradar/compare/2026.8.27...2026.8.28
[2026.8.27]: https://github.com/maksimtech/patchradar/compare/2026.8.26...2026.8.27
[2026.8.26]: https://github.com/maksimtech/patchradar/compare/2026.8.25...2026.8.26
[2026.8.25]: https://github.com/maksimtech/patchradar/compare/2026.8.24...2026.8.25
[2026.8.24]: https://github.com/maksimtech/patchradar/compare/2026.8.23...2026.8.24
[2026.8.23]: https://github.com/maksimtech/patchradar/compare/2026.8.22...2026.8.23
[2026.8.22]: https://github.com/maksimtech/patchradar/compare/2026.8.21...2026.8.22
[2026.8.21]: https://github.com/maksimtech/patchradar/compare/2026.8.20...2026.8.21
[2026.8.20]: https://github.com/maksimtech/patchradar/compare/2026.8.19...2026.8.20
[2026.8.19]: https://github.com/maksimtech/patchradar/compare/2026.8.18...2026.8.19
[2026.8.18]: https://github.com/maksimtech/patchradar/compare/2026.8.17...2026.8.18
[2026.8.17]: https://github.com/maksimtech/patchradar/compare/2026.8.16...2026.8.17
[2026.8.16]: https://github.com/maksimtech/patchradar/compare/2026.8.15...2026.8.16
[2026.8.15]: https://github.com/maksimtech/patchradar/compare/2026.8.14...2026.8.15
[2026.8.14]: https://github.com/maksimtech/patchradar/compare/2026.8.13...2026.8.14
[2026.8.13]: https://github.com/maksimtech/patchradar/compare/2026.8.12...2026.8.13
[2026.8.12]: https://github.com/maksimtech/patchradar/compare/2026.8.11...2026.8.12
[2026.8.11]: https://github.com/maksimtech/patchradar/compare/2026.8.10...2026.8.11
[2026.8.10]: https://github.com/maksimtech/patchradar/compare/2026.8.7...2026.8.10
[2026.8.7]: https://github.com/maksimtech/patchradar/compare/2026.8.6...2026.8.7
[2026.8.6]: https://github.com/maksimtech/patchradar/compare/2026.8.5...2026.8.6
[2026.8.5]: https://github.com/maksimtech/patchradar/compare/2026.8.4...2026.8.5
[2026.8.4]: https://github.com/maksimtech/patchradar/compare/2026.8.3...2026.8.4
[2026.8.3]: https://github.com/maksimtech/patchradar/compare/2026.8.2...2026.8.3
[2026.8.2]: https://github.com/maksimtech/patchradar/releases/tag/2026.8.2
