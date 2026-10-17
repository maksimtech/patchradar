"""
PatchRadar — no statement in the database layer is built from a formatted string

Bandit's B608 flagged three on #58 and #64: the watchlist UPDATE whose column
list was joined at run time, and the two listings of `get_cves` whose select
list and ORDER BY were interpolated. Every interpolated piece was a module
constant, so nothing a user typed could reach them — but the project accepts no
`# nosec`, and the cleaner answer is a statement written out: there is then
nothing for a reader, or a scanner, to trust.

The listings' ORDER BY is still the order `priority()` ranks by: it is written
out in database.py and checked against `priority.sql_order` here, which keeps
the one-source rule without building the statement from it.
"""
from __future__ import annotations

import ast
import pathlib
import re

import patchradar.db.database as database
from patchradar.priority import sql_order

SOURCE = pathlib.Path(database.__file__).read_text(encoding="utf-8")
DML = re.compile(r"^\s*(SELECT|INSERT|UPDATE|DELETE)\b", re.I)


def _formatted_statements() -> list[int]:
    lines = []
    for node in ast.walk(ast.parse(SOURCE)):
        if not (isinstance(node, ast.Call) and getattr(node.func, "attr", "") in {"execute", "executemany"}):
            continue
        if not node.args:
            continue
        statement = node.args[0]
        if isinstance(statement, ast.JoinedStr):
            text = "".join(v.value for v in statement.values if isinstance(v, ast.Constant))
            if DML.match(text):
                lines.append(node.lineno)
        elif isinstance(statement, ast.BinOp | ast.Call):
            lines.append(node.lineno)
    return lines


def test_no_select_insert_update_or_delete_is_a_formatted_string():
    assert _formatted_statements() == []


def test_the_listings_are_ordered_by_what_priority_ranks_by():
    order = re.sub(r"\s+", " ", sql_order("cves"))
    listings = re.sub(r"\s+", " ", SOURCE)
    assert listings.count(f"ORDER BY {order}, published_at DESC, cves.id DESC LIMIT ?") == 2


def test_the_priority_index_holds_the_same_expression():
    order = re.sub(r"\s+", " ", sql_order())
    assert f"ON cves ({order}, published_at DESC, id DESC)" in re.sub(r"\s+", " ", SOURCE)
