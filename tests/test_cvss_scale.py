"""
PatchRadar — le scale qualitative CVSS, secondo FIRST

Due scale, non una, e non sono convertibili l'una nell'altra: sono metriche
diverse e FIRST non pubblica alcuna tabella di conversione.

CVSS v3.x (specifica, sezione 5)      CVSS v2 (guida, sezione 2.3)
    None      0.0                         Low       0.0 – 3.9
    Low       0.1 – 3.9                   Medium    4.0 – 6.9
    Medium    4.0 – 6.9                   High      7.0 – 10.0
    High      7.0 – 8.9
    Critical  9.0 – 10.0

La differenza non e' accademica. Nei 695 CVE misurati su una macchina reale il
26/09/2026 convivono:

    CVE-2014-0566   10.0  HIGH        v2
    CVE-2018-4872   10.0  CRITICAL    v3

Due 10.0 con etichette diverse, entrambe corrette. Chi ordina per etichetta
mette un 9.8 CRITICAL sopra un 10.0 HIGH.
"""
import pytest

from patchradar.cvss import SEVERITIES, severity_for

# ── v3.x: i cinque gradini e i loro estremi ──────────────────────────────────

@pytest.mark.parametrize("score, expected", [
    (0.0, "NONE"),
    (0.1, "LOW"), (3.9, "LOW"),
    (4.0, "MEDIUM"), (6.9, "MEDIUM"),
    (7.0, "HIGH"), (8.9, "HIGH"),
    (9.0, "CRITICAL"), (10.0, "CRITICAL"),
])
def test_v3_scale(score, expected):
    assert severity_for(score, "3.1") == expected
    assert severity_for(score, "3.0") == expected


def test_zero_is_none_not_low():
    """Il difetto che questo modulo corregge.

    `msrc._score_to_severity` restituiva LOW per 0.0, mentre la v3 parte da 0.1
    e riserva NONE allo zero. Nessun test fissava il comportamento sbagliato.
    """
    assert severity_for(0.0, "3.1") == "NONE"


# ── v2: quattro gradini, e nessun Critical ───────────────────────────────────

@pytest.mark.parametrize("score, expected", [
    (0.0, "LOW"), (3.9, "LOW"),
    (4.0, "MEDIUM"), (6.9, "MEDIUM"),
    (7.0, "HIGH"), (10.0, "HIGH"),
])
def test_v2_scale(score, expected):
    assert severity_for(score, "2.0") == expected


def test_v2_has_no_critical():
    """La v2 chiama High tutto da 7.0 a 10.0.

    Applicare le soglie v3 a un punteggio v2 promuoverebbe a CRITICAL una
    trentina di voci nei dati del 26/09/2026, dando loro una gravita' che il
    loro stesso standard non prevede.
    """
    assert severity_for(10.0, "2.0") == "HIGH"
    assert "CRITICAL" not in {severity_for(s / 10, "2.0") for s in range(0, 101)}


def test_the_same_score_differs_between_versions():
    """Il caso osservato: due 10.0, due etichette, entrambe giuste."""
    assert severity_for(10.0, "2.0") == "HIGH"
    assert severity_for(10.0, "3.1") == "CRITICAL"


# ── cio' che non si puo' dire ────────────────────────────────────────────────

@pytest.mark.parametrize("score", [None, -0.1, 10.1, float("nan")])
def test_a_score_outside_the_scale_is_unknown(score):
    """Fuori dall'intervallo non c'e' un gradino, e inventarlo sarebbe peggio
    che ammetterlo."""
    assert severity_for(score, "3.1") == "UNKNOWN"


@pytest.mark.parametrize("version", [None, "", "4.0", "boh"])
def test_an_unknown_cvss_version_is_unknown(version):
    """Senza sapere QUALE scala, un punteggio non ha un gradino.

    v4.0 e' fuori di proposito: ha la sua scala e finche' non e' scritta qui
    la risposta onesta e' UNKNOWN, non "uso quella della v3 che le somiglia".
    """
    assert severity_for(7.5, version) == "UNKNOWN"


def test_severities_are_the_ones_the_ui_knows():
    """Un gradino che l'interfaccia non colora esce bianco e non si nota."""
    from patchradar.cli import SEVERITY_STYLES
    assert set(SEVERITIES) <= set(SEVERITY_STYLES)
