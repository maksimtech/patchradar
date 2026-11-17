"""A CPE 2.3 name as a person types it for `patchradar add --cpe` (DESIGN §5.2).

Checked for form only. The name is never turned into a CPE by deduction —
measured on a real inventory, a guess mapped `MX5` to a Juniper router and
`Visual C++ 2012` to `visual_c++:2008` — so all this can do is refuse a string
NVD would match nothing with. The commonest is a product written the way it is
read: `notepad++`, where CPE 2.3 and NVD write `notepad\\+\\+`. Passed on as
typed, the scan raises nothing, finds nothing, and reads as clean.
"""
from __future__ import annotations

from dataclasses import dataclass

PREFIX = "cpe:2.3:"

# The parts CPE 2.3 defines: application, operating system, hardware.
_PARTS = {"a", "o", "h"}

# ANY and NA. A vendor or product of either names no product to judge.
WILDCARDS = frozenset({"*", "-", ""})


class CpeError(ValueError):
    """Not a CPE 2.3 name the scan could judge a version with."""


@dataclass(frozen=True)
class Cpe:
    text: str
    part: str
    vendor: str
    product: str
    # Every field, as split from `text`: [0] "cpe", [1] "2.3", [2] the part, ...
    fields: tuple[str, ...] = ()

    def field(self, index: int) -> str:
        """The field at `index` of the CPE 2.3 formatted string — 6 update,
        9 sw_edition, 10 target_sw, ... — and `*` (ANY) where the name stops
        before it, as CPE 2.3 reads a name written short."""
        return self.fields[index] if index < len(self.fields) and self.fields[index] else "*"


def split_fields(text: str) -> list[str]:
    """Split on the colons that are not escaped."""
    fields, current, escaped = [], [], False
    for char in text:
        if escaped:
            current.append(char)
            escaped = False
        elif char == "\\":
            current.append(char)
            escaped = True
        elif char == ":":
            fields.append("".join(current))
            current = []
        else:
            current.append(char)
    fields.append("".join(current))
    return fields


def _escaped(value: str) -> str:
    """`value` with every special character escaped once, as NVD writes it.

    Letters, digits, `_`, `-` and `.` stand as they are — NVD's own
    `.net_framework` — and anything already escaped is left alone.
    """
    out, escaped = [], False
    for char in value:
        if escaped:
            out.append(char)
            escaped = False
        elif char == "\\":
            out.append(char)
            escaped = True
        elif char.isalnum() or char in "_-.":
            out.append(char)
        else:
            out.append("\\" + char)
    return "".join(out)


def parse_cpe(text: str) -> Cpe:
    """The CPE in `text`, in lower case.

    CPE 2.3 names match without regard to case, and NVD writes them in lower
    case. Kept as typed, `cpe:2.3:a:Mozilla:Thunderbird` matched none of NVD's
    names, and every CVE of the program was judged "not affected" — hidden from
    the table, an all-clear made of a capital letter.
    """
    cleaned = text.strip().lower()
    if not cleaned.startswith(PREFIX):
        raise CpeError(f"'{cleaned}' is not a CPE 2.3 name: it must start with '{PREFIX}'")
    fields = split_fields(cleaned)
    if len(fields) < 5:
        raise CpeError(f"'{cleaned}' names no product: cpe:2.3:<part>:<vendor>:<product>")
    part, vendor, product = fields[2], fields[3], fields[4]
    if part not in _PARTS:
        raise CpeError(f"'{cleaned}': the part is '{part}', and CPE 2.3 knows only a, o and h")
    for label, value in (("vendor", vendor), ("product", product)):
        if value in WILDCARDS:
            shown = f"'{value}'" if value else "empty"
            raise CpeError(f"'{cleaned}': the {label} is {shown}, which names no product")
        if _escaped(value) != value:
            raise CpeError(
                f"'{cleaned}': the {label} '{value}' has characters NVD writes escaped, "
                f"and as typed it would match nothing; NVD's form is '{_escaped(value)}'"
            )
    return Cpe(text=cleaned, part=part, vendor=vendor, product=product, fields=tuple(fields))
