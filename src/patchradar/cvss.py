"""Le scale qualitative CVSS, come le pubblica FIRST.

Due scale, non una, e **non sono convertibili**: v2 e v3 sono metriche diverse
e FIRST non pubblica alcuna tabella di conversione fra le due. Quindi un
punteggio senza la sua versione non ha un gradino, e questo modulo lo dice
invece di sceglierne uno.

    CVSS v3.x                        CVSS v2
        None      0.0                    Low       0.0 - 3.9
        Low       0.1 - 3.9              Medium    4.0 - 6.9
        Medium    4.0 - 6.9              High      7.0 - 10.0
        High      7.0 - 8.9
        Critical  9.0 - 10.0

La differenza si vede nei dati. Fra i 695 CVE misurati su una macchina reale il
26/09/2026 convivono `CVE-2014-0566 10.0 HIGH` (v2) e `CVE-2018-4872 10.0
CRITICAL` (v3): due 10.0 con etichette diverse, entrambe corrette per la propria
scala. Ne segue una regola per chi mostra questi dati: **mai un'etichetta senza
la sua versione accanto, e mai un ordinamento per etichetta.**
"""
from __future__ import annotations

import math

UNKNOWN = "UNKNOWN"

# Tutti i gradini che questo modulo puo' restituire, UNKNOWN compreso. Serve a
# tenere in riga la tavolozza dell'interfaccia: un gradino che non ha un colore
# esce bianco e non si distingue da una riga qualunque.
SEVERITIES = ("NONE", "LOW", "MEDIUM", "HIGH", "CRITICAL", UNKNOWN)

# Soglie come estremi INFERIORI inclusivi, dal piu' grave al meno grave. Scritte
# cosi' e non come intervalli perche' gli estremi superiori della specifica
# (3.9, 6.9, 8.9) sono un artificio della notazione decimale: il confine vero e'
# il gradino successivo.
_V3 = ((9.0, "CRITICAL"), (7.0, "HIGH"), (4.0, "MEDIUM"), (0.1, "LOW"), (0.0, "NONE"))

# La v2 non ha Critical e il suo Low parte da 0.0: non esiste un "None".
_V2 = ((7.0, "HIGH"), (4.0, "MEDIUM"), (0.0, "LOW"))

_SCALES = {"2.0": _V2, "3.0": _V3, "3.1": _V3}


def severity_for(score: float | None, cvss_version: str | None) -> str:
    """Il gradino qualitativo di `score` nella scala di `cvss_version`.

    UNKNOWN quando manca il punteggio, quando e' fuori dall'intervallo 0-10, o
    quando la versione non e' una di quelle tabulate qui. La v4.0 rientra in
    quest'ultimo caso di proposito: ha una scala propria, e finche' non e'
    scritta sopra la risposta onesta e' UNKNOWN, non "uso quella della v3 che
    le somiglia".
    """
    scale = _SCALES.get(str(cvss_version or "").strip())
    if scale is None:
        return UNKNOWN
    try:
        value = float(score)  # type: ignore[arg-type]
    except (TypeError, ValueError):
        return UNKNOWN
    if math.isnan(value) or not (0.0 <= value <= 10.0):
        return UNKNOWN
    for threshold, label in scale:
        if value >= threshold:
            return label
    return UNKNOWN
