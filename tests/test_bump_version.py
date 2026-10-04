"""The release tool, which had no test and would have refused to run.

`scripts/bump_version.py` is step three of RELEASING.md. It parsed YYYY.M.PATCH
and raised `ValueError: Invalid CalVer format` on anything else, so the day the
month left the version the documented release path would have stopped — not
with a wrong number, but with no number at all, on the one script nobody runs
except at release time.

Rewritten for the scheme the five Radar now share: the year is the generation
and the count belongs to this Radar. The part worth testing is not the
arithmetic but the refusal: coming off the old scheme, the month sat in the
second segment, so 2026.7 sorts *below* 2026.9.6 and publishing it would be a
downgrade PyPI never lets anyone take back.
"""

from __future__ import annotations

import sys
from datetime import datetime
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))

import bump_version as bump  # noqa: E402


class TestOrdering:
    """`is_after` has to read two versions the way PEP 440 does."""

    def test_a_shorter_version_is_padded_not_truncated(self):
        assert not bump.is_after("2026.7", "2026.9.6")
        assert bump.is_after("2026.10", "2026.9.6")

    def test_equal_versions_are_not_after_each_other(self):
        assert not bump.is_after("2026.10", "2026.10")

    def test_leading_zeros_do_not_change_the_order(self):
        assert not bump.is_after("2026.09.4", "2026.9.4")
        assert bump.is_after("2026.10", "2026.09.4")


class TestParsing:
    def test_the_generation_form(self):
        assert bump.parse_version("2026.40") == (2026, 40, 0)

    def test_a_fix_on_top_of_a_baseline(self):
        assert bump.parse_version("2026.40.1") == (2026, 40, 1)

    def test_the_legacy_form_keeps_its_count(self):
        """YYYY.M.PATCH: the patch was the count, the month is dropped."""
        assert bump.parse_version("2026.9.33") == (2026, 33, 0)

    def test_three_segments_are_told_apart_by_the_middle_one(self):
        """The ambiguity that lasts one more cycle. 2026.9.6 is September's
        sixth release; 2026.40.6 is fix six of baseline forty. The baseline is
        forty, so a middle segment of twelve or less can only be a month."""
        assert bump.parse_version("2026.12.3") == (2026, 3, 0)
        assert bump.parse_version("2026.13.3") == (2026, 13, 3)

    def test_something_that_is_not_a_version_says_so(self):
        with pytest.raises(ValueError):
            bump.parse_version("2026")


class TestBumping:
    def test_the_count_goes_up_within_a_generation(self):
        assert bump.bump_version("2026.10") == "2026.11"

    def test_coming_off_the_old_scheme_never_goes_backwards(self):
        """The case that made this rewrite necessary. 2026.9.6 would have
        become 2026.7, which is lower than where it started."""
        assert bump.bump_version("2026.9.6") == "2026.10"
        assert bump.is_after(bump.bump_version("2026.9.6"), "2026.9.6")

    def test_a_high_count_carries_over_untouched(self):
        assert bump.bump_version("2026.09.33") == "2026.34"

    @pytest.mark.parametrize(
        "current", ["2026.9.1", "2026.9.6", "2026.9.9", "2026.9.10", "2026.10"]
    )
    def test_whatever_it_is_handed_the_answer_sorts_after_it(self, current):
        """The property the loop exists for, rather than the five numbers it
        happens to produce today."""
        assert bump.is_after(bump.bump_version(current), current)

    def test_a_new_year_restarts_the_count(self, monkeypatch):
        """The generation is the year, so January is 1 again.

        The clock is pinned rather than read: written against the real one,
        this test says 2026 today and goes red on the first of January for a
        reason that has nothing to do with the code.
        """
        class _Frozen(datetime):
            @classmethod
            def now(cls, tz=None):
                return cls(2027, 1, 4)

        monkeypatch.setattr(bump, "datetime", _Frozen)

        assert bump.bump_version("2026.33") == "2027.1"
        assert bump.is_after("2027.1", "2026.33")


class TestFixes:
    """The third segment: something urgent on a count that already shipped."""

    def test_a_fix_starts_at_one(self):
        assert bump.bump_version("2026.40", fix=True) == "2026.40.1"

    def test_a_fix_never_spells_zero(self):
        """PEP 440 strips it: 2026.40.0 *is* 2026.40, so PyPI would refuse the
        upload as a duplicate of a version already there."""
        assert not bump.bump_version("2026.40", fix=True).endswith(".0")

    def test_a_fix_on_a_fix_goes_up(self):
        assert bump.bump_version("2026.40.1", fix=True) == "2026.40.2"

    def test_an_ordinary_release_leaves_the_fixes_behind(self):
        """2026.40.2 is followed by 2026.41, not by 2026.41.2."""
        assert bump.bump_version("2026.40.2") == "2026.41"

    @pytest.mark.parametrize(
        "current", ["2026.40", "2026.40.1", "2026.40.9", "2026.41"]
    )
    @pytest.mark.parametrize("fix", [True, False])
    def test_whichever_level_moves_the_answer_sorts_after(self, current, fix):
        assert bump.is_after(bump.bump_version(current, fix=fix), current)


class TestTheSuiteGate:
    """The suite has to run with the new version in place, before the commit.

    `bump_version.py` writes the version first, so a suite run before a release
    cannot see what the bump breaks. apkradar met this twice in two days — its
    README states the version its examples were captured with, and the test that
    holds that failed in CI, on main, with the tag already pushed. patchradar has
    the same shape of test and the same gap.

    Before the commit on purpose: a refusal then leaves the two version files
    modified and nothing else touched, and `git checkout` undoes it. A gate after
    the commit would have to undo one.
    """

    def test_a_failing_suite_is_refused(self, tmp_path):
        # A tests/ directory, or the gate returns early on having nothing to run —
        # which is what the third case below is about.
        (tmp_path / "tests").mkdir()
        failed = tmp_path / "ran"
        result = bump.check_suite(
            command=[sys.executable, "-c",
                     f"open(r'{failed}', 'w').write('x'); raise SystemExit(1)"],
            cwd=tmp_path,
        )

        assert result is False
        assert failed.is_file(), "it reported without running anything"

    def test_a_passing_suite_is_accepted(self, tmp_path):
        (tmp_path / "tests").mkdir()

        assert bump.check_suite(
            command=[sys.executable, "-c", "raise SystemExit(0)"], cwd=tmp_path,
        ) is True

    def test_a_tree_with_no_tests_is_not_held_up(self, tmp_path):
        """Nothing to run is not a failure — and `tests/` is absent here."""
        assert bump.check_suite(cwd=tmp_path) is True

    def _driven(self, monkeypatch, suite_passes: bool) -> list:
        """`main()` with everything that touches the world replaced, so what is
        asserted is the order of its decisions and nothing else."""
        calls: list[str] = []

        def answer(prompt: str) -> str:
            # Keyed on the question, not on call order: "Proceed?" has to be yes or
            # nothing below it runs, and "Push to remote?" has to be no or this test
            # pushes for real.
            if "Proceed" in prompt:
                return "y"
            if "Push" in prompt:
                return "n"
            raise AssertionError(f"main() asked something unexpected: {prompt!r}")

        monkeypatch.setattr("builtins.input", answer)
        monkeypatch.setattr(bump, "git_push", lambda *a: calls.append("push"))
        monkeypatch.setattr(bump, "get_current_version", lambda: "2026.43")
        monkeypatch.setattr(bump, "update_pyproject", lambda *a: calls.append("pyproject"))
        monkeypatch.setattr(bump, "update_init", lambda *a: calls.append("init"))
        monkeypatch.setattr(bump, "git_commit", lambda *a: calls.append("commit"))
        monkeypatch.setattr(bump, "check_suite", lambda *a, **k: suite_passes)
        monkeypatch.setattr(sys, "argv", ["bump_version.py"])
        return calls

    def test_main_writes_the_version_and_then_refuses_to_commit(self, monkeypatch):
        """The case the gate exists for, and the one the tests above could not see:
        they exercise `check_suite` in isolation, so removing the call from `main`
        left all of them green. This is what notices.
        """
        calls = self._driven(monkeypatch, suite_passes=False)

        with pytest.raises(SystemExit) as exit_code:
            bump.main()

        assert exit_code.value.code == 1
        assert "commit" not in calls, "it committed a version its suite refuses"
        assert calls == ["pyproject", "init"], (
            "the version has to be written before the suite runs, or the suite "
            "cannot see what the bump breaks"
        )

    def test_main_commits_when_the_suite_passes(self, monkeypatch):
        calls = self._driven(monkeypatch, suite_passes=True)

        bump.main()

        assert calls == ["pyproject", "init", "commit"]

    def test_the_default_command_is_this_project_suite(self):
        """Read off the module rather than written here, so renaming it fails."""
        assert bump.SUITE_COMMAND[:2] == [sys.executable, "-m"]
        assert "pytest" in bump.SUITE_COMMAND
