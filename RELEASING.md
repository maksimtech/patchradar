# Release Process

## Versioning

PatchRadar uses **CalVer, Apple style**: `YYYY.count[.fix]`.

```
2026.40      generazione 2026, quarantesimo conteggio
2026.41      il conteggio si muove perche' si e' mosso il codice
2026.40.1    intervento fuori programma su cio' che e' gia' fuori
```

`YYYY` è la **generazione**, condivisa dai cinque Radar: nella stessa
generazione i cinque parlano della stessa annata. Il conteggio invece appartiene
a ciascuno e si muove quando si muove il suo codice.

### Il terzo segmento

Non è «il rilascio piccolo». È **fuori programma e a scopo singolo**.

Il modello è iOS 11.2.6, del febbraio 2018: il carattere telugu mandava in crash
qualunque app lo ricevesse, e Apple pubblicò undici giorni dopo la 11.2.5 una
versione che conteneva quella correzione e nient'altro.

Se in un rilascio entra anche solo una cosa che non è quella urgenza, allora è
un conteggio, non un fix. Usare il terzo segmento per «le cose minori» lo svuota
di significato — che è esattamente la deriva da cui i cinque Radar sono usciti
il 26/09/2026, quando si trovarono a `.32`, `.12`, `.11`, `.6` e `.3` della
stessa generazione senza che quel numero volesse più dire niente.

Accorpare una feature e delle correzioni nello stesso conteggio è normale e
previsto: `2026.41` porta la fonte CISA KEV insieme a quattro difetti risolti.

## Il CHANGELOG si scrive a mano

`CHANGELOG.md` segue [Keep a Changelog](https://keepachangelog.com/en/1.1.0/) ed
è **scritto a mano**. git-cliff è stato usato in passato e non lo è più: le note
generate dai messaggi di commit dicono cosa è cambiato e mai perché, che è
l'unica cosa che un lettore cerca.

`scripts/release.py` cerca la sezione `## [<versione>]` e **fallisce prima di
toccare qualunque cosa** se non la trova. Quindi la voce va scritta prima del
bump, sotto un titolo che corrisponda alla versione che uscirà.

## Prima di rilasciare

- [ ] `pytest -q` — tutto verde
- [ ] `ruff check src tests benchmarks` — pulito
- [ ] `mypy src/patchradar` — pulito
- [ ] `CHANGELOG.md` ha la sezione della versione che sta per uscire
- [ ] il tag non esiste già: `git ls-remote --tags origin | grep <versione>`
- [ ] nessun avviso di sicurezza critico o alto aperto
- [ ] provato su Windows e su Linux

## Rilascio

```bash
# 1. Bump della versione (interattivo: chiede conferma)
python scripts/bump_version.py          # il conteggio sale
python scripts/bump_version.py --fix    # oppure il terzo segmento

# 2. Rilascio (interattivo: chiede conferma)
python scripts/release.py
```

`release.py` fa, in quest'ordine:

1. `git push origin main`
2. `gh release create <versione> --latest`, con le note prese dal CHANGELOG
3. si ferma: **`publish.yml` parte da solo** su `release: published` e pubblica
   su PyPI con trusted publishing — nessun token da passare

Il punto 3 è **irreversibile**: una versione su PyPI non si ritira, si può solo
marcare come *yanked*. Vale la pena rileggere il CHANGELOG un'ultima volta prima
di confermare.

## Rami

`main` è l'unico ramo permanente, ed è sempre rilasciabile: i commit di rilascio
ci vanno sopra direttamente. Il lavoro più lungo o più rischioso sta su rami
brevi (`feat/…`, `fix/…`) finché non è pronto — è così che `feature/version-gap`
è rimasto fuori da 2026.41, perché aveva il codice ma non ancora una faccia.

Non esiste un ramo `develop`. Le versioni precedenti di questo documento ne
descrivevano uno, insieme a uno schema di versioni `YYYY.MM.PATCH` che il
progetto ha abbandonato: entrambi erano fermi a prima del 26/09/2026.

## Regole

- Un rilascio contiene un insieme di modifiche che ha senso raccontare insieme.
- Niente rattoppi: si capisce il difetto prima di rilasciare, non dopo.
- Il CHANGELOG si scrive per chi legge fra sei mesi, non per chi ha appena
  scritto il codice.
