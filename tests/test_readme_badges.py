"""The README's badges are well formed, and none of them states the version by hand.

The README is also the long description on PyPI, so what is broken here is broken
there too. On 2026-11-16 one badge held another inside its URL, the PyPI one pasted
into itself, and rendered as a broken image; another, a static `calver-2026.8.2`,
named a release that had been out of date for two months. A version belongs in a
badge that asks PyPI for it, which cannot fall behind.
"""

from __future__ import annotations

import re
from pathlib import Path

README = Path(__file__).resolve().parents[1] / "README.md"

# `![alt](url)`, the URL up to the first closing parenthesis or space.
IMAGE = re.compile(r"!\[[^\]]*\]\(([^)\s]*)")

# A CalVer number of this project's shape: 2026.48, 2026.8.2.
VERSION = re.compile(r"\b20\d\d\.\d+(?:\.\d+)?\b")


def _image_urls() -> list[str]:
    return IMAGE.findall(README.read_text(encoding="utf-8"))


def test_no_image_link_holds_another():
    assert [url for url in _image_urls() if "![" in url] == []


def test_no_static_badge_states_a_version():
    static = [url for url in _image_urls() if "img.shields.io/badge/" in url]
    assert static, "the README has no static badge left to check"
    assert [url for url in static if VERSION.search(url)] == []


def test_the_patterns_recognise_what_was_broken():
    pasted = (
        "![PyPI](https://img.shields.io/pypi/v/patchradar?style=flat-square"
        "![PyPI](https://img.shields.io/pypi/v/patchradar?style=flat-square)label=pypi)"
    )
    assert "![" in IMAGE.findall(pasted)[0]
    assert VERSION.search("https://img.shields.io/badge/calver-2026.8.2-green?style=flat-square")
    assert not VERSION.search("https://img.shields.io/badge/python-3.11+-blue?style=flat-square")
