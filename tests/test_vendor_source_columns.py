"""
PatchRadar — `vendor` and `product_id` belong to the vendor source (docs/DESIGN.md §5.1)

`inventory.py` named the watchlist columns before they existed: `vendor`,
`product_id`, `installed_version`, `channel`, `cpe`. In it, a vendor source is a
feed that answers by version — Chrome's, Edge's, MSRC, Mozilla's — and
`product_id` is the product that feed needs ("chrome", "Edge"); the CPE is the
separate route, NVD by CPE. #58 filled `vendor` and `product_id` with the CPE's
fields instead, which would have had `import` write a vendor source over the
CPE's vendor, or the other way round.

The CPE's vendor and product are now read from `cpe` itself, and the two
columns are left to the vendor source, written by `set_source`.
"""
from __future__ import annotations

import pytest

from patchradar.cpe import parse_cpe
from patchradar.db import database

NOTEPADPP = "cpe:2.3:a:notepad-plus-plus:notepad\\+\\+"


@pytest.mark.asyncio
async def test_a_cpe_does_not_fill_the_vendor_source_columns():
    await database.add_to_watchlist("notepad")
    await database.set_installed("notepad", version="8.5.0", cpe=parse_cpe(NOTEPADPP))

    [entry] = await database.get_watch_entries()

    assert (entry.vendor, entry.product_id) == (None, None)
    assert (entry.cpe_vendor, entry.cpe_product) == ("notepad-plus-plus", "notepad\\+\\+")
    assert entry.installed() == ("8.5.0", "notepad-plus-plus", "notepad\\+\\+")


@pytest.mark.asyncio
async def test_the_vendor_source_is_stored_beside_the_cpe():
    await database.add_to_watchlist("google chrome")
    await database.set_installed("google chrome", version="141.0.7390.65",
                                 cpe=parse_cpe("cpe:2.3:a:google:chrome"))

    assert await database.set_source("google chrome", vendor="chrome", product_id="chrome", channel="stable")

    [entry] = await database.get_watch_entries()
    assert (entry.vendor, entry.product_id, entry.channel) == ("chrome", "chrome", "stable")
    assert entry.cpe == "cpe:2.3:a:google:chrome"
    assert entry.installed() == ("141.0.7390.65", "google", "chrome")


@pytest.mark.asyncio
async def test_a_vendor_source_alone_does_not_make_an_entry_judgeable():
    """The scan judges with NVD's configurations, which need the CPE."""
    await database.add_to_watchlist("microsoft edge")
    await database.set_installed("microsoft edge", version="141.0.3537.71", cpe=None)
    await database.set_source("microsoft edge", vendor="edge", product_id="Edge", channel=None)

    [entry] = await database.get_watch_entries()
    assert (entry.vendor, entry.product_id) == ("edge", "Edge")
    assert not entry.judgeable


@pytest.mark.asyncio
async def test_a_cpe_without_a_version_is_not_judgeable_either():
    await database.add_to_watchlist("notepad")
    await database.set_installed("notepad", version=None, cpe=parse_cpe(NOTEPADPP))

    [entry] = await database.get_watch_entries()
    assert entry.installed() is None


@pytest.mark.asyncio
async def test_set_source_never_adds_a_name():
    assert not await database.set_source("thunderbird", vendor="mozilla", product_id="thunderbird",
                                         channel="release")
    assert await database.get_watchlist() == []
