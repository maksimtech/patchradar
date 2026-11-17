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

DML = re.compile(r"^\s*(SELECT|INSERT|UPDATE|DELETE)\b", re.I)


def _repository_file(path: pathlib.Path) -> pathlib.Path:
    """The file in the repository that `path` stands for.

    mutmut copies the repository into `mutants/` and imports the package from
    there, so `database.__file__` is its copy, with every mutant beside the code;
    the file the checks are about is the same path without that component. The
    claims are about what is written, which a mutant does not change: under mutmut
    they hold or fail exactly as they do in the ordinary run.
    """
    parts = path.parts
    if "mutants" not in parts:
        return path
    cut = len(parts) - 1 - parts[::-1].index("mutants")
    return pathlib.Path(*parts[:cut], *parts[cut + 1 :])


SOURCE = _repository_file(pathlib.Path(database.__file__)).read_text(encoding="utf-8")


def _formatted_statements(source: str) -> list[int]:
    lines = []
    for node in ast.walk(ast.parse(source)):
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
    assert _formatted_statements(SOURCE) == []


def test_under_mutmut_the_checks_read_the_repository_not_its_copy(tmp_path):
    """mutmut runs the suite from `mutants/`, a copy of the repository in which
    database.py holds, beside every function, each of its mutated variants. One
    of them drops the statement from `db.execute(sql, params)` and leaves the
    parameters first, a tuple built with `*` and `+`, which is a formatted
    statement to the check above; another few dozen repeat the listings' ORDER
    BY. Read there, the checks fail on code nobody wrote, and the weekly mutation
    run stopped in its stats phase on 2026-10-24 and every Saturday since.

    The copy is made by mutmut itself, from the real database.py, in a tree laid
    out as mutmut lays out its own.
    """
    from mutmut.mutation.file_mutation import mutate_file_contents

    source = _repository_file(pathlib.Path(database.__file__)).read_text(encoding="utf-8")
    original = tmp_path / "src" / "patchradar" / "db" / "database.py"
    copy = tmp_path / "mutants" / "src" / "patchradar" / "db" / "database.py"
    for path in (original, copy):
        path.parent.mkdir(parents=True)
    original.write_text(source, encoding="utf-8")
    copy.write_text(mutate_file_contents(str(original), source).code, encoding="utf-8")

    assert _formatted_statements(copy.read_text(encoding="utf-8")) != []
    assert _formatted_statements(_repository_file(copy).read_text(encoding="utf-8")) == []


def test_the_listings_are_ordered_by_what_priority_ranks_by():
    order = re.sub(r"\s+", " ", sql_order("cves"))
    listings = re.sub(r"\s+", " ", SOURCE)
    assert listings.count(f"ORDER BY {order}, published_at DESC, cves.id DESC LIMIT ?") == 2


def test_the_priority_index_holds_the_same_expression():
    order = re.sub(r"\s+", " ", sql_order())
    assert f"ON cves ({order}, published_at DESC, id DESC)" in re.sub(r"\s+", " ", SOURCE)
