"""
PatchRadar — a CPE is typed by a person, and checked for form only (DESIGN §5.2)

The name is never turned into a CPE by deduction: on a real inventory a guess
mapped `MX5` to a Juniper router. What `add --cpe` can do is refuse a string NVD
would match nothing with, and the commonest one is a product written the way a
person reads it: `notepad++`, where CPE 2.3 and NVD write `notepad\\+\\+`. Passed
as is, the scan raises nothing, finds nothing, and reads as clean.
"""
from __future__ import annotations

import pytest

from patchradar.cpe import CpeError, parse_cpe

NOTEPADPP = "cpe:2.3:a:notepad-plus-plus:notepad\\+\\+"


def test_the_vendor_and_product_are_read_as_nvd_writes_them():
    cpe = parse_cpe(NOTEPADPP)

    assert cpe.part == "a"
    assert cpe.vendor == "notepad-plus-plus"
    assert cpe.product == "notepad\\+\\+"
    assert cpe.text == NOTEPADPP


def test_a_full_cpe_with_version_and_wildcards_keeps_its_product():
    cpe = parse_cpe("cpe:2.3:a:notepad-plus-plus:notepad\\+\\+:8.5.0:*:*:*:*:*:*:*")

    assert (cpe.vendor, cpe.product) == ("notepad-plus-plus", "notepad\\+\\+")


def test_dots_dashes_and_underscores_need_no_escape():
    """NVD's own spelling: `.net_framework`, `visual_studio_2022`."""
    cpe = parse_cpe("cpe:2.3:a:microsoft:.net_framework")

    assert cpe.product == ".net_framework"


def test_surrounding_spaces_are_not_part_of_it():
    assert parse_cpe(f"  {NOTEPADPP} \n").text == NOTEPADPP


@pytest.mark.parametrize("text", [
    "notepad-plus-plus:notepad\\+\\+",          # no prefix
    "cpe:/a:notepad-plus-plus:notepad%2b%2b",   # CPE 2.2 URI binding
    "cpe:2.3:a:notepad-plus-plus",              # no product
    "cpe:2.3:x:notepad-plus-plus:notepad",      # not a, o or h
])
def test_what_is_not_a_cpe_2_3_name_is_refused(text):
    with pytest.raises(CpeError):
        parse_cpe(text)


@pytest.mark.parametrize("text", [
    "cpe:2.3:a:*:notepad",
    "cpe:2.3:a:notepad-plus-plus:*",
    "cpe:2.3:a:-:notepad",
    "cpe:2.3:a:notepad-plus-plus:",
])
def test_a_wildcard_or_empty_vendor_or_product_names_no_product(text):
    """`*` is ANY and `-` is NA: a watchlist entry for "any product of any
    vendor" is not something a verdict can be given about."""
    with pytest.raises(CpeError):
        parse_cpe(text)


def test_an_unescaped_special_character_is_refused_with_the_escaped_form():
    with pytest.raises(CpeError) as raised:
        parse_cpe("cpe:2.3:a:notepad-plus-plus:notepad++")

    assert "notepad\\+\\+" in str(raised.value)


def test_a_character_already_escaped_is_not_escaped_twice():
    with pytest.raises(CpeError) as raised:
        parse_cpe("cpe:2.3:a:notepad-plus-plus:notepad\\++")

    assert "notepad\\+\\+" in str(raised.value)
    assert "\\\\+" not in str(raised.value)
