"""
PatchRadar — sanitize_cve control characters (W4)

The docstring and inline comment said "removes null bytes and control
characters"; the code removed only \\x00. ESC (\\x1b), BEL (\\x07), backspace
(\\x08) and the rest survived into the API response — and the same stored
records are printed to terminals by the CLI, where ESC starts an ANSI sequence
that can recolour, move the cursor, or hide text.
"""
import pytest

from patchradar.api.main import sanitize_cve

C0_EXCEPT_WHITESPACE = [chr(c) for c in range(0x00, 0x20) if chr(c) not in "\t\n\r"]
C1 = [chr(c) for c in range(0x80, 0xA0)]   # includes \x9b, the 8-bit CSI
DEL = "\x7f"


@pytest.mark.parametrize("char", C0_EXCEPT_WHITESPACE + [DEL] + C1,
                         ids=lambda c: f"U+{ord(c):04X}")
@pytest.mark.parametrize("field", ["description", "id", "software", "severity", "source", "url"])
def test_control_characters_are_removed(field, char):
    out = sanitize_cve({field: f"a{char}b"})
    assert out[field] == "ab", f"{field}: U+{ord(char):04X} survived"


def test_ansi_escape_sequence_is_neutralised():
    """The concrete threat: an ESC-led colour/cursor sequence."""
    out = sanitize_cve({"description": "safe \x1b[31mRED\x1b[0m \x1b[2Jclear"})
    assert "\x1b" not in out["description"]


@pytest.mark.parametrize("ws", ["\n", "\t"])
def test_ordinary_whitespace_inside_text_is_kept(ws):
    """Descriptions legitimately contain newlines and tabs."""
    out = sanitize_cve({"description": f"line1{ws}line2"})
    assert out["description"] == f"line1{ws}line2"


def test_crlf_is_normalised_to_lf():
    out = sanitize_cve({"description": "a\r\nb\rc"})
    assert out["description"] == "a\nb\nc"


def test_printable_unicode_is_untouched():
    text = "Überlauf in données — 缓冲区溢出 ✓"
    assert sanitize_cve({"description": text})["description"] == text


def test_existing_truncation_still_applies_after_cleaning():
    out = sanitize_cve({"description": "\x1b" * 10 + "A" * 2500})
    assert out["description"] == "A" * 2000 + "..."


def test_non_string_fields_pass_through():
    out = sanitize_cve({"description": None, "cvss_score": 0.0})
    assert out["description"] is None
    assert out["cvss_score"] == 0.0
