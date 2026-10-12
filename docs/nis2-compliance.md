# PatchRadar: risposte alle sette domande NIS2 sul software

Revisione 1 · 2026-10-11 · vale per il ramo `main` e per le release successive alla 2026.46

Questo documento risponde alle domande che un cliente soggetto alla direttiva NIS2
(UE 2022/2555, recepita in Italia con il d.lgs. 138/2024) può porre a un fornitore di
software. Ogni affermazione verificabile nel repository è controllata dai test in
`tests/test_nis2_evidence.py`: se il codice cambia e il documento no, la CI fallisce.
Quello che il repository non può dimostrare è indicato con la data in cui è stato
verificato, oppure dichiarato assente.

La NIS2 non prevede una certificazione di prodotto: gli obblighi della direttiva
ricadono sui soggetti, non sugli strumenti che usano. Quello che segue sono le prove
che il fornitore è in grado di dare, non un attestato di conformità.

## 1. Di cosa è fatto il software

- Dipendenze dichiarate in `pyproject.toml`; risoluzione completa in `uv.lock`. La CI
  (workflow Quality) fallisce se `uv.lock` non corrisponde più a `pyproject.toml`.
- Ogni release su GitHub porta in allegato due SBOM in formato CycloneDX 1.5:
  quella dell'immagine Docker, pacchetti di sistema inclusi, e quella dell'ambiente
  Python del pacchetto installato da sorgente (vedi la tabella al punto 6).
- Provenienza, verificata il 2026-10-11 sulla release 2026.46: la wheel e l'archivio
  sorgente su PyPI hanno un'attestazione PEP 740 firmata con Sigstore, che indica come
  origine il workflow `publish.yml` di questo repository; l'immagine su Docker Hub
  (`maksimtech/patchradar`) ha, per ciascuna delle due piattaforme, un'attestazione di
  provenienza SLSA v1 generata da BuildKit al momento del push.
- Licenze: il workflow License Check fallisce se una dipendenza è sotto GPL, AGPL o
  LGPL.

## 2. Chi può vedere cosa, dentro l'applicazione

PatchRadar non ha account, sessioni né ruoli: una matrice ruoli-permessi non esiste
perché non ci sono ruoli. I comandi da riga di comando girano con i permessi di chi li
esegue, e l'accesso al sistema è responsabilità dell'operatore.

`patchradar serve` avvia un'interfaccia web, ed è qui che il controllo degli accessi
conta:

- per impostazione predefinita ascolta solo su `127.0.0.1`, porta 8000; con l'opzione
  `--host` ascolta sull'indirizzo indicato, anche su tutte le interfacce;
- l'immagine Docker avvia `patchradar serve --host 0.0.0.0 --port 8000`, cioè ascolta
  su `0.0.0.0`, tutte le interfacce del container, ed espone la porta 8000. Il
  `docker-compose.yml` del repository la pubblica solo sul loopback dell'host
  (`127.0.0.1:8000:8000`); chi la pubblica in altro modo, per esempio con
  `docker run -p 8000:8000`, la rende raggiungibile dalla rete;
- l'unica autenticazione è una chiave condivisa, facoltativa, nella variabile
  d'ambiente `PATCHRADAR_API_KEY`, che il client invia nell'intestazione `X-API-Key`.
  Non identifica una persona: chiunque la conosca ha gli stessi poteri;
- la chiave protegge solo le scritture: aggiungere o togliere software dalla
  watchlist e avviare una scansione. **Senza chiave, chiunque raggiunga la porta può
  farlo.** All'avvio senza chiave il server lo segnala con un avviso sull'output di
  errore;
- **le letture non chiedono mai la chiave, anche quando la chiave è impostata**:
  chiunque raggiunga la porta legge la watchlist, cioè l'elenco del software in uso, e
  le vulnerabilità trovate. Verificato il 2026-10-11 avviando `patchradar serve` con la
  chiave impostata: la watchlist è stata restituita a una richiesta senza chiave;
- il server parla HTTP in chiaro, senza TLS: la chiave e i dati viaggiano leggibili
  sulla rete se davanti non c'è un proxy che termina TLS;
- una scrittura che un browser invia per conto di un altro sito viene rifiutata con
  403: il server accetta solo `Sec-Fetch-Site` uguale a `same-origin` o `none` e, se
  quell'intestazione manca, un `Origin` uguale al server. È una difesa contro le pagine
  web ostili visitate dall'utente, non un controllo degli accessi.

In pratica: esposta oltre la macchina locale, l'interfaccia mostra a chiunque la
raggiunga l'inventario del software e le sue vulnerabilità. Va lasciata sul loopback,
oppure messa dietro un proxy con TLS e autenticazione gestiti dall'operatore.

Gli indirizzi del server, e quali chiedono la chiave quando è impostata:

<!-- endpoints:start -->
| Indirizzo | Chiave richiesta | Cosa fa |
| --- | --- | --- |
| `GET /` | no | la pagina dell'interfaccia |
| `GET /health` | no | stato del server e del database |
| `GET /api/watchlist` | no | la watchlist |
| `GET /api/cves` | no | le vulnerabilità salvate, al massimo 200 per richiesta |
| `GET /api/cves/{cve_id}` | no | una vulnerabilità salvata |
| `GET /api/stats` | no | conteggi per gravità e per software |
| `POST /api/watchlist/{software}` | sì | aggiunge un software alla watchlist |
| `POST /api/watchlist/import` | sì | aggiunge un elenco di software |
| `DELETE /api/watchlist/{software}` | sì | toglie un software, e le vulnerabilità che riguardano solo quello |
| `POST /api/scan` | sì | avvia una scansione, che contatta i servizi del punto 3 |
| `GET /docs` | no | documentazione automatica dell'API |
| `GET /docs/oauth2-redirect` | no | pagina di servizio della documentazione |
| `GET /redoc` | no | documentazione automatica dell'API |
| `GET /openapi.json` | no | descrizione dell'API |
<!-- endpoints:end -->

A questi si aggiungono i file statici dell'interfaccia, sotto `/static`, senza chiave.

L'immagine Docker gira come utente non privilegiato `patchradar`, UID 1000.

## 3. Se succede qualcosa, si può ricostruire chi ha fatto cosa

PatchRadar non tiene un registro proprio. I comandi scrivono i risultati e gli errori
sulla console. `patchradar serve` scrive sull'output standard una riga per ogni
richiesta, con l'indirizzo e la porta del client, il metodo, il percorso e l'esito
(il formato predefinito di uvicorn); le righe non hanno data e ora proprie, e non
possono dire chi ha fatto la richiesta perché non esistono utenti. La conservazione dei
log è a carico di chi lo esegue. PatchRadar non contiene telemetria e non invia nulla
al fornitore.

Per cercare le vulnerabilità contatta servizi esterni, e il cliente deve sapere che
cosa ricevono:

<!-- hosts:start -->
| Host | Quando | Cosa riceve |
| --- | --- | --- |
| `services.nvd.nist.gov` | `scan`, da riga di comando o dall'interfaccia web | il nome di ogni software della watchlist (o quello passato a `scan`) come parola chiave di ricerca, con l'intervallo di date; la chiave `NVD_API_KEY`, se impostata, in un'intestazione |
| `api.msrc.microsoft.com` | `scan` | il mese dei bollettini richiesti; nessun nome di software, il filtro avviene sulla macchina |
| `www.cisa.gov` | `scan` | nulla: scarica il catalogo KEV intero e lo filtra sulla macchina |
| `security-tracker.debian.org` | `scan` dall'interfaccia web; `patchradar debian` senza `--file` | nulla: scarica il tracker intero e lo filtra sulla macchina |
| `vuldb.com` | `scan`, solo se `VULDB_API_KEY` è impostata | il nome di ogni software della watchlist come parola chiave di ricerca; la chiave `VULDB_API_KEY` in un'intestazione |
| `api.first.org` | `scan` | gli identificativi CVE trovati dalla scansione |
| `publications.europa.eu` | `scan` da riga di comando, quando ci sono rilievi da citare | il numero CELEX dell'atto citato |
| `eur-lex.europa.eu` | come sopra, se `publications.europa.eu` non risponde | il numero CELEX dell'atto citato |
| `www.normattiva.it` | con le citazioni attuali, mai: serve agli atti italiani, e PatchRadar cita solo GDPR e NIS2, pubblicati su EUR-Lex | il riferimento dell'atto e dell'articolo |
<!-- hosts:end -->

Ogni host riceve inoltre, come per qualunque connessione, l'indirizzo IP della
macchina. Solo le richieste dei testi di legge portano uno User-Agent che indica questo
repository; le altre portano quello predefinito della libreria httpx
(`python-httpx/<versione>`).

Ogni vulnerabilità salvata porta un link alla pagina che la descrive, su
`nvd.nist.gov`, `msrc.microsoft.com`, `www.cisa.gov`,
`vuldb.com` o `security-tracker.debian.org`. PatchRadar non li apre: l'interfaccia li mostra, e li
apre il browser dell'utente se ci fa clic.

Su disco PatchRadar scrive:

- il database SQLite `~/.patchradar/patchradar.db`, con la watchlist (nome del
  software e data di inserimento) e le vulnerabilità trovate (identificativo, software
  a cui si riferiscono, descrizione, punteggio, gravità, data di pubblicazione, fonte,
  link, previsione EPSS, data in cui sono state viste). Il percorso è fisso: la variabile `PATCHRADAR_HOME` non sposta il
  database. Nell'immagine Docker la cartella è il volume
  `/home/patchradar/.patchradar`;
- la cache dei testi di legge citati, in `~/.patchradar/law_cache.json` (oppure nella
  cartella indicata da `PATCHRADAR_HOME`), che non contiene dati sul software
  analizzato;
- con `patchradar collector`, lo script `inventory.ps1` nella cartella corrente o nel
  file indicato con `--output`.

Lo script `inventory.ps1` è il raccoglitore dell'inventario di una macchina Windows: va
eseguito a mano, possibilmente come amministratore, e scrive un solo file JSON, nella
cartella corrente o nel percorso indicato con `-OutFile`. Non contiene comandi di rete e non invia il file a nessuno; il file
resta dove viene scritto. `patchradar import` lo legge e non scrive nulla né contatta
nessuno. Per verificare le firme dei driver lo script chiede a Windows
`Get-AuthenticodeSignature`, e per farlo Windows può contattare i server delle CA
indicate nei certificati: quei contatti li decide la configurazione di Windows, non
PatchRadar.

Il file contiene molto più dell'elenco dei programmi, e chi lo maneggia deve saperlo:

<!-- inventory:start -->
| Sezione | Contenuto |
| --- | --- |
| `system` | versione e build di Windows, data di installazione e ultimo avvio, produttore e modello della macchina e della scheda madre |
| `firmware` | produttore, versione e data del BIOS |
| `posture` | Secure Boot, modalità di firma di test e controlli di integrità, sicurezza basata sulla virtualizzazione, blocklist dei driver vulnerabili, stato di Microsoft Defender e minacce rilevate negli ultimi 30 giorni |
| `devices` | i dispositivi Plug and Play, con stato e codice di errore |
| `drivers` | i driver associati ai dispositivi, con versione, fornitore e firma |
| `driverStore` | i pacchetti di driver installati (`pnputil /enum-drivers`) |
| `driverFiles` | i file `.sys` in `System32\drivers`, con firma e SHA-256 |
| `driverStoreFiles` | le copie degli stessi file nel DriverStore, con firma e SHA-256 |
| `installedSoftware` | i programmi installati: nome, versione, editore, data di installazione, cartella di installazione, icona, comando di disinstallazione |
| `crashArtefacts` | percorso, dimensione e data dei file di dump dei crash e dei rapporti di errore di Windows |
| `events` | errori, errori critici e avvisi degli ultimi 90 giorni di tre registri eventi, con il testo del messaggio |
| `driverInstallLog` | le sezioni di `setupapi.dev.log`: cosa è stato installato, quando e con quale comando |
<!-- inventory:end -->

Il file riporta anche quando è stato raccolto e se lo script girava come
amministratore. I percorsi e i messaggi del registro eventi possono contenere il nome
dell'utente della macchina.

## 4. Come arrivano gli aggiornamenti, e in quanto tempo

La politica completa è in `SECURITY.md`: fonti di monitoraggio, tempi di risposta,
notifica ai clienti, procedura di rollback. In sintesi:

- le correzioni escono con la release successiva, che può arrivare fino a un mese dopo
  la precedente; per una vulnerabilità con CVSS pari o superiore a 9.0 il cliente che
  ha indicato un contatto di sicurezza viene avvisato entro 48 ore dalla presa in
  carico, anche se la correzione non è ancora pronta;
- le vulnerabilità accettate, con motivazione e data di revisione, sono in
  `SECURITY-EXCEPTIONS.toml`.

<!-- rollback:start -->
Ogni versione resta installabile: da PyPI con `pip install patchradar==<versione>`, da
Docker Hub con il tag della versione, senza prefisso (es.
`maksimtech/patchradar:2026.46`), e con il digest SHA256 dell'immagine, che non può
cambiare. Il rollback consiste nel tornare a quella versione o a quel digest.

I workflow del repository riscrivono il tag di una versione in un solo caso: se il
manutentore ricostruisce a mano quella versione (avvio manuale del workflow
`Build and Push Docker Image`), che riscrive anche `latest`. Per un rollback
riproducibile conviene fissare il digest.

L'immagine viene costruita quando esce una release, su `python:3.14-slim-trixie`
(Debian Trixie), e non viene ricostruita automaticamente tra una release e l'altra: le
patch di sicurezza di Debian arrivano nell'immagine con la release successiva.
<!-- rollback:end -->

Contatto per le segnalazioni: <security@maksimtech.com>.

## 5. Il codice viene controllato prima di andare in produzione

Analisi automatiche, ciascuna con il proprio workflow in `.github/workflows`:

<!-- scanners:start -->
| Strumento | Cosa controlla | Quando |
| --- | --- | --- |
| `CodeQL` | analisi statica del codice | ogni pull request, ogni push su `main`, ogni settimana |
| `Bandit` | analisi statica di sicurezza Python | ogni pull request, ogni push su `main`, ogni settimana |
| `Trivy` | vulnerabilità note nei file del repository | ogni pull request, ogni push su `main`, ogni settimana |
| `Snyk` | analisi statica del codice, vulnerabilità note nelle dipendenze e nell'immagine costruita dal sorgente | ogni pull request, ogni push su `main` |
| `SonarCloud` | qualità, duplicazioni e copertura | ogni pull request, ogni push su `main` |
| `Docker Scout` | vulnerabilità note nell'immagine pubblicata | ogni push su `main`, ogni build dell'immagine, ogni settimana |
| `Security Posture` | raccoglie gli avvisi pubblicati dagli altri e fallisce se un avviso alto o critico non ha un'eccezione motivata | ogni pull request, ogni push su `main`, ogni settimana |
| `CodSpeed` | prestazioni: esegue i benchmark del repository e pubblica sulla pull request il confronto con `main`; non blocca il merge | ogni pull request, ogni push su `main` |
| `mutmut` | mutation testing: verifica che i test si accorgano delle modifiche al codice | ogni settimana |
<!-- scanners:end -->

A questi si aggiungono i test automatici (pytest, con copertura inviata a Codecov),
ruff e mypy nel workflow Quality. L'esecuzione settimanale di mutmut del 2026-10-10 si
è fermata prima di provare i mutanti, perché nella sua copia di lavoro mancavano due
file letti dai test; questa revisione li aggiunge.

Sul repository sono attivi, verificato il 2026-10-11, gli avvisi Dependabot sulle
dipendenze (nessun avviso registrato a quella data) e gli aggiornamenti di sicurezza
automatici di Dependabot; `.github/dependabot.yml` chiede ogni settimana gli
aggiornamenti delle dipendenze Python, delle GitHub Actions e dell'immagine di base.

Le regole del ramo `main`, lette dalle impostazioni del repository il 2026-10-11
(ruleset "main protection", attivo), vietano la cancellazione del ramo e la riscrittura
della storia e richiedono due controlli superati: Tests e Quality. Non c'è una regola
che imponga la pull request, né una che imponga una storia lineare, e l'account
`maksimtech` del manutentore può scavalcare le regole. CodeQL, Security Posture e gli
altri strumenti della tabella girano su ogni pull request ma non sono tra i controlli
obbligatori.

PatchRadar ha un manutentore unico. Non c'è nessuna revisione obbligatoria da parte di
una seconda persona: le modifiche vengono unite dal manutentore dopo che la CI è verde,
e i commit di release vanno direttamente su `main`. È un limite noto di un progetto con
una sola persona.

## 6. Qualcuno dall'esterno ha provato a entrare

Non è stato eseguito un penetration test. Esiste una scansione automatica continua
delle vulnerabilità note, descritta al punto 5, ma non è un penetration test: non ha un
ambito concordato, non è condotta da un tester indipendente e non produce un rapporto
con vulnerabilità trovate e correzioni datate. In particolare, nessuno ha provato a
forzare l'interfaccia web descritta al punto 2.

Ogni release porta in allegato i risultati datati di quella scansione, insieme alle
SBOM:

<!-- assets:start -->
| File allegato alla release | Contenuto |
| --- | --- |
| `sbom-image-<versione>.cdx.json` | SBOM CycloneDX 1.5 dell'immagine Docker della versione |
| `sbom-source-<versione>.cdx.json` | SBOM CycloneDX 1.5 dell'ambiente Python del pacchetto |
| `trivy-image-<versione>-<data>.json` | vulnerabilità note nell'immagine, scansione Trivy |
| `trivy-fs-<versione>-<data>.json` | vulnerabilità note nei file del repository al tag, scansione Trivy |
| `EVIDENCE-<versione>.md` | cosa sono questi file, quando e da quale commit e digest sono stati prodotti |
<!-- assets:end -->

Se a un tag il repository non contiene un file che Trivy sappia analizzare, come un
lockfile, il rapporto `trivy-fs` di quella release è vuoto. Un rapporto vuoto non
indica l'assenza di vulnerabilità, e in quel caso la nota `EVIDENCE` lo dice.

## 7. E se il fornitore sparisce

Il codice sorgente è pubblico su <https://github.com/maksimtech/patchradar> con licenza
MIT, e resta accessibile indipendentemente dalle sorti commerciali del fornitore. Le
versioni pubblicate restano su PyPI e su Docker Hub.

Il fornitore non conserva dati del cliente: la watchlist e le vulnerabilità trovate
stanno nel database `~/.patchradar/patchradar.db` sulla macchina di chi esegue
PatchRadar (punto 3). Non esiste un comando di esportazione: il file è un database
SQLite 3, un formato aperto e documentato, leggibile con qualunque client SQLite, per
esempio con `sqlite3 ~/.patchradar/patchradar.db .dump`. Con l'interfaccia web
avviata, `GET /api/watchlist` restituisce la watchlist in JSON.

Una clausola contrattuale su questo punto va concordata caso per caso e fatta rivedere
da un legale.
