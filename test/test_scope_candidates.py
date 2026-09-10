"""The scope reviewer's deterministic seams must fail closed, and only pass on evidence.

``scripts/scope_candidates.py`` sits on both sides of the security-scope review: it
turns a MODEL's candidate file into a corpus the denial differential can classify,
and it folds the per-platform differential reports back into one verdict.

Both seams are places the lane could publish a false green, and a false green here
is worse than no lane at all -- the check name stands as evidence the question was
asked. So every test below stages one specific way that could happen:

*The candidate file is untrusted input.* It is written by a model, from a diff, and
a diff can carry instructions. Malformed rows, a runaway row count, and a
kilobyte-long "command" must all be exit 2 rather than a silently narrowed corpus,
because a differential over a subset nobody chose reports "no regressions" about
rows it never saw.

*An unmeasured run is not a clean run.* No report, a report whose shape is wrong,
and legs that classified nothing all mean the change was never actually judged. Each
is exit 2. Only a leg that classified rows and found no flip earns exit 0.

*The schema has one owner.* ``validate`` proves its output against
``deny_diff.load_corpus`` itself rather than a second validator that could drift, so
the round-trip tests here are the pin: what this script writes, the differential can
read, and what it proposes, a human can paste.
"""

from __future__ import annotations

import importlib.util
import json
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "scope_candidates.py"
DENY_DIFF = ROOT / "scripts" / "deny_diff.py"


def _load(name: str, path: Path):
    """Import a script by path, registered in ``sys.modules`` before exec.

    A script's dataclasses resolve their own annotations through
    ``sys.modules[cls.__module__]``, so a module executed without a registration
    raises at class-creation time rather than at use.
    """
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


scope = _load("scope_candidates", SCRIPT)
deny_diff = _load("deny_diff_for_scope", DENY_DIFF)


def _row(command: str, platform: str = "any", kind: str = "shell", reason: str = "why") -> dict:
    return {
        "kind": kind,
        "command_or_flow": command,
        "platform": platform,
        "reason": reason,
    }


def _write(path: Path, rows: list[dict]) -> Path:
    path.write_text(json.dumps({"golden_paths": rows}, indent=2), encoding="utf-8")
    return path


def _report(
    platform: str,
    *,
    classified: int,
    regressions: list[dict] | None = None,
    total_rows: int = 1,
    skipped_platform: int = 0,
    base_absent_tiers: int = 0,
) -> dict:
    rows = regressions or []
    return {
        "base": "base",
        "base_sha": "a" * 7,
        "head": "head",
        "head_sha": "b" * 7,
        "platform": platform,
        "corpus": "corpus.json",
        "counts": {
            "total_rows": total_rows,
            "classified": classified,
            "skipped_kind": 0,
            "skipped_platform": skipped_platform,
            "base_absent_tiers": base_absent_tiers,
            "regressions": len(rows),
            "loosenings": 0,
            "unchanged_allowed": max(classified - len(rows), 0),
            "unchanged_denied": 0,
        },
        "regressions": rows,
        "loosenings": [],
        "exit_code": 1 if rows else 0,
    }


class TestValidate:
    def test_novel_candidates_survive_and_reach_the_differential(self, tmp_path: Path) -> None:
        """The kept rows must be readable by the classifier's OWN corpus parser.

        This is the round-trip that makes the single-owner schema claim true: a row
        this script accepted and the differential then rejected would surface as a
        gate that errored rather than as the malformed row it is.
        """
        candidates = _write(tmp_path / "c.json", [_row("gh pr view 1"), _row("ls -la")])
        out = tmp_path / "normalized.json"

        assert scope.main(["validate", "--candidates", str(candidates), "--out", str(out)]) == 0

        parsed = deny_diff.load_corpus(out)
        assert [row.command for row in parsed] == ["gh pr view 1", "ls -la"]

    def test_a_row_the_committed_corpus_already_holds_is_dropped(self, tmp_path: Path) -> None:
        """Re-probing a committed row spends a slot on a finding another lane owns."""
        corpus = _write(tmp_path / "base.json", [_row("gh pr view 1")])
        candidates = _write(tmp_path / "c.json", [_row("gh pr view 1"), _row("ls -la")])
        out = tmp_path / "normalized.json"

        code = scope.main(
            [
                "validate",
                "--candidates",
                str(candidates),
                "--corpus",
                str(corpus),
                "--out",
                str(out),
            ]
        )

        assert code == 0
        assert [row.command for row in deny_diff.load_corpus(out)] == ["ls -la"]

    def test_a_candidate_repeated_within_the_file_is_dropped_once(self, tmp_path: Path) -> None:
        candidates = _write(tmp_path / "c.json", [_row("ls -la"), _row("ls -la")])
        out = tmp_path / "normalized.json"

        assert scope.main(["validate", "--candidates", str(candidates), "--out", str(out)]) == 0
        assert [row.command for row in deny_diff.load_corpus(out)] == ["ls -la"]

    def test_a_platform_variant_is_its_own_row(self, tmp_path: Path) -> None:
        """Dedupe keys on platform, or the windows spelling would vanish as a dupe.

        The platform triple is half of what this lane exists to check, so the two
        spellings of one operation must both survive to be classified.
        """
        candidates = _write(
            tmp_path / "c.json",
            [_row("pytest test", platform="posix"), _row("pytest test", platform="windows")],
        )
        out = tmp_path / "normalized.json"

        assert scope.main(["validate", "--candidates", str(candidates), "--out", str(out)]) == 0
        assert {row.platform for row in deny_diff.load_corpus(out)} == {"posix", "windows"}

    def test_everything_already_covered_is_exit_3_not_a_written_empty_corpus(
        self, tmp_path: Path
    ) -> None:
        """An empty corpus would make the differential error; say so with its own code."""
        corpus = _write(tmp_path / "base.json", [_row("gh pr view 1")])
        candidates = _write(tmp_path / "c.json", [_row("gh pr view 1")])
        out = tmp_path / "normalized.json"

        code = scope.main(
            [
                "validate",
                "--candidates",
                str(candidates),
                "--corpus",
                str(corpus),
                "--out",
                str(out),
            ]
        )

        assert code == 3
        assert not out.exists()

    @pytest.mark.parametrize(
        "payload",
        [
            pytest.param("not json at all", id="unparseable"),
            pytest.param(json.dumps({"rows": []}), id="no-golden-paths-key"),
            pytest.param(json.dumps({"golden_paths": []}), id="empty"),
            pytest.param(json.dumps({"golden_paths": ["a string"]}), id="row-not-an-object"),
            pytest.param(
                json.dumps({"golden_paths": [{"kind": "nope", "command_or_flow": "ls"}]}),
                id="unknown-kind",
            ),
            pytest.param(
                json.dumps({"golden_paths": [{"kind": "shell", "command_or_flow": "  "}]}),
                id="blank-command",
            ),
            pytest.param(
                json.dumps(
                    {
                        "golden_paths": [
                            {"kind": "shell", "command_or_flow": "ls", "platform": "solaris"}
                        ]
                    }
                ),
                id="unknown-platform",
            ),
        ],
    )
    def test_an_untrustworthy_candidate_file_is_exit_2(self, tmp_path: Path, payload: str) -> None:
        """Never a narrowed corpus: a file that cannot be trusted stops the lane."""
        candidates = tmp_path / "c.json"
        candidates.write_text(payload, encoding="utf-8")
        out = tmp_path / "normalized.json"

        assert scope.main(["validate", "--candidates", str(candidates), "--out", str(out)]) == 2
        assert not out.exists()

    def test_row_count_is_capped_before_dedupe(self, tmp_path: Path) -> None:
        """Counting after dedupe would let a padded file buy itself room."""
        candidates = _write(tmp_path / "c.json", [_row("ls -la")] * 6)
        out = tmp_path / "normalized.json"

        code = scope.main(
            ["validate", "--candidates", str(candidates), "--out", str(out), "--max-rows", "5"]
        )

        assert code == 2
        assert not out.exists()

    def test_an_oversized_command_is_refused(self, tmp_path: Path) -> None:
        """The corpus holds operations, not payloads."""
        candidates = _write(tmp_path / "c.json", [_row("ls " + "a" * 600)])
        out = tmp_path / "normalized.json"

        assert scope.main(["validate", "--candidates", str(candidates), "--out", str(out)]) == 2

    def test_a_missing_candidate_file_is_exit_2(self, tmp_path: Path) -> None:
        out = tmp_path / "normalized.json"
        code = scope.main(
            ["validate", "--candidates", str(tmp_path / "absent.json"), "--out", str(out)]
        )
        assert code == 2


class TestVerdict:
    def test_a_confirmed_regression_is_exit_1(self, tmp_path: Path) -> None:
        report = tmp_path / "posix.json"
        report.write_text(
            json.dumps(
                _report(
                    "posix",
                    classified=2,
                    regressions=[
                        {
                            "command": "gh pr view 1",
                            "platform": "any",
                            "kind": "shell",
                            "why_legitimate": "maintainers read PR state",
                            "head_tier": "rule-catalog",
                            "head_refusal": "rule=broadened-gh",
                        }
                    ],
                )
            ),
            encoding="utf-8",
        )
        body = tmp_path / "body.md"

        code = scope.main(["verdict", "--report", str(report), "--out-md", str(body)])

        assert code == 1
        text = body.read_text(encoding="utf-8")
        assert "gh pr view 1" in text
        # The tier decides the fix, so it must reach the reader.
        assert "rule-catalog" in text

    def test_a_clean_measured_run_is_exit_0(self, tmp_path: Path) -> None:
        report = tmp_path / "posix.json"
        report.write_text(json.dumps(_report("posix", classified=3)), encoding="utf-8")

        assert scope.main(["verdict", "--report", str(report)]) == 0

    def test_no_report_at_all_is_exit_2(self) -> None:
        """The caller must not reach a green by producing no evidence."""
        assert scope.main(["verdict"]) == 2

    def test_legs_that_classified_nothing_are_exit_2(self, tmp_path: Path) -> None:
        """NO VERDICT everywhere is an unmeasured change, not a pass."""
        report = tmp_path / "windows.json"
        report.write_text(
            json.dumps(_report("windows", classified=0, total_rows=2, skipped_platform=2)),
            encoding="utf-8",
        )

        assert scope.main(["verdict", "--report", str(report)]) == 2

    def test_one_measured_leg_beside_an_unmeasured_one_still_reports_the_gap(
        self, tmp_path: Path
    ) -> None:
        """A platform with no verdict must be named, not averaged away into a pass."""
        measured = tmp_path / "posix.json"
        measured.write_text(json.dumps(_report("posix", classified=2)), encoding="utf-8")
        unmeasured = tmp_path / "windows.json"
        unmeasured.write_text(
            json.dumps(_report("windows", classified=0, total_rows=2, skipped_platform=2)),
            encoding="utf-8",
        )
        body = tmp_path / "body.md"

        code = scope.main(
            [
                "verdict",
                "--report",
                str(measured),
                "--report",
                str(unmeasured),
                "--out-md",
                str(body),
            ]
        )

        assert code == 0
        text = body.read_text(encoding="utf-8")
        assert "windows: NO VERDICT" in text
        assert "Not a pass for this platform." in text

    @pytest.mark.parametrize(
        "payload",
        [
            pytest.param("{", id="unparseable"),
            pytest.param(json.dumps([]), id="not-an-object"),
            pytest.param(json.dumps({"platform": "posix", "counts": {}}), id="no-regressions-key"),
            pytest.param(
                json.dumps({"platform": "posix", "counts": [], "regressions": []}),
                id="malformed-counts",
            ),
        ],
    )
    def test_a_report_that_cannot_be_read_is_exit_2(self, tmp_path: Path, payload: str) -> None:
        report = tmp_path / "leg.json"
        report.write_text(payload, encoding="utf-8")

        assert scope.main(["verdict", "--report", str(report)]) == 2

    def test_proposed_rows_are_a_corpus_a_human_can_paste(self, tmp_path: Path) -> None:
        """A confirmed regression IS the row the corpus was missing.

        The paste-ready output must therefore satisfy the committed corpus's own
        parser, or the reviewer's only actionable artifact is a snippet that would
        break the gate it is meant to feed.
        """
        report = tmp_path / "posix.json"
        report.write_text(
            json.dumps(
                _report(
                    "posix",
                    classified=1,
                    regressions=[
                        {
                            "command": "py -3 -m pytest test\\unit",
                            "platform": "windows",
                            "kind": "shell",
                            "why_legitimate": "the Windows spelling of the test run",
                            "head_tier": "argv-floor",
                            "head_refusal": "rule=inline-interpreter",
                        }
                    ],
                )
            ),
            encoding="utf-8",
        )
        rows = tmp_path / "rows.json"

        assert scope.main(["verdict", "--report", str(report), "--out-rows", str(rows)]) == 1

        parsed = deny_diff.load_corpus(rows)
        assert len(parsed) == 1
        assert parsed[0].platform == "windows"
        assert parsed[0].reason == "the Windows spelling of the test run"
