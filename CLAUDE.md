# PatchRadar — istruzioni per Claude Code

Claude Code legge questo file da solo. Contiene regole di lavoro e fatti che il
repository conferma; la storia sta nel CHANGELOG e nelle pull request, non qui.

## Cos'è

Raccolta di CVE per il software in una watchlist, con CLI (`add`, `remove`,
`list`, `scan`, `status`, `serve`, `collector`, `import`, `debian`), API e
interfaccia web FastAPI (`patchradar serve`) e database SQLite in
`~/.patchradar/patchradar.db`. Cosa contatta in rete, cosa scrive su disco e chi
può usare l'interfaccia web è in `docs/nis2-compliance.md`, sezioni 2 e 3.

## Regole di lavoro

- **Ogni modifica passa da una pull request** su `main`, unita quando i controlli
  obbligatori sono verdi. Dal 2026-10-12 il ruleset la impone senza eccezioni,
  nemmeno per il proprietario: un push diretto su `main` viene rifiutato, e lo è
  anche `gh pr merge --admin`. Anche il commit di versione passa da una PR (vedi
  `RELEASING.md`).
- **Commit firmati** con l'identità e la chiave configurate nel repository:
  `git log -1 --format=%G?` deve dare `G`. Messaggi `tipo(ambito): …`, con il
  perché nel corpo. La riga `Co-Authored-By` la indica l'ambiente di Claude Code;
  non scrivere nomi di modello né link a sessioni in questo file.
- **TDD**: il test che riproduce il difetto fallisce prima della correzione, e si
  vede fallire.
- **Niente mock.** Input reali, oggetti reali, server locali veri. Al confine di
  rete si possono riprodurre solo risposte registrate dal servizio vero, in
  fixture che lo dichiarano (`_recorded`); una fixture costruita o ricavata si
  dichiara `_derived`. Risposte inventate e patch di funzioni interne per
  simulare un comportamento non si usano. "Non misurato" non è zero. Alcuni test
  esistenti costruiscono risposte a mano: non è il modello da copiare.
- **`docs/nis2-compliance.md` è documentazione per i clienti** ed è tenuta al
  codice da `tests/test_nis2_evidence.py`: se cambiano gli host contattati, i file
  scritti, gli endpoint dell'API, l'immagine o i workflow, il documento si
  aggiorna nella stessa PR. Nessuna affermazione che il repository non possa
  dimostrare.
- **Avvisi di sicurezza accettati** solo in `SECURITY-EXCEPTIONS.toml`, con motivo
  e `review_by`; mai `# nosec` o `# noqa` per zittire uno scanner.
- **Repository di terzi**: nessuna issue, PR o commento senza conferma esplicita
  del proprietario.

## Comandi

Come li esegue la CI (Quality e Tests). Su Windows il Python del venv è
`.venv/Scripts/python`, su Linux `.venv/bin/python`. Le dipendenze di sviluppo
sono un gruppo PEP 735 e servono pip 25.1 o successivo. I test asincroni girano
con `asyncio_mode = "auto"`.

```bash
python -m venv .venv
.venv/Scripts/python -m pip install --upgrade pip
.venv/Scripts/python -m pip install --group dev -e .
.venv/Scripts/python -m pytest -q
.venv/Scripts/ruff check src tests benchmarks scripts tools
.venv/Scripts/mypy src/patchradar
uv lock --check            # con uv 0.12.18, la versione fissata in quality.yml
```

## Release

`scripts/bump_version.py` porta la versione (CalVer `YYYY.count[.fix]`, vedi
`RELEASING.md`), fa girare la suite e mette il commit su `release/<versione>`; poi
pubblica quel ramo e apre la PR con auto-merge. Dopo il merge, `git pull` e
`scripts/release.py`, che non spinge nulla: verifica che `main` locale sia quello
del remoto e crea la release GitHub su quel commit, con un tag senza `v` (per
esempio `2026.46`). L'evento di release fa partire PyPI e l'immagine
`maksimtech/patchradar:2026.46`; poi Release Evidence (`sbom.yml`) allega SBOM e
scansioni datate. Per una release già uscita:
`gh workflow run sbom.yml -f tag=2026.46`.

## Note

- `law_fetcher.py` e `law_cache.py` sono copiati, non condivisi, in mailradar,
  exeradar, cookieradar, apkradar e patchradar: una correzione va portata in
  tutte le copie. I redirect si seguono a mano e mai in chiaro
  (`_get_over_https`): Cellar risponde con un 303 verso `http://`.
- Chiavi lette dall'ambiente: `NVD_API_KEY` (facoltativa), `VULDB_API_KEY` (senza,
  VulDB non viene interrogato), `PATCHRADAR_API_KEY` (protegge solo le scritture
  dell'API), `PATCHRADAR_HOME` (sposta solo la cache dei testi di legge).
