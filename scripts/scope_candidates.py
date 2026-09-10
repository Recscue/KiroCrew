#!/usr/bin/env python3
"""scope_candidates — the deterministic half of the security-scope review.

The scope reviewer asks one question about a security-tightening change: which
legitimate operations does it newly refuse? A model cannot answer that by reading
the matcher -- it would have to simulate four checks and thousands of lines, and a
model that reports a refusal it did not observe produces a confident finding about
nothing. So the lane splits the work: the model PROPOSES candidate legitimate
operations, and ``scripts/deny_diff.py`` DECIDES, by classifying each candidate
with the real code at the base ref and at the head ref.

This script is the two seams around that decision.

``validate``
    Takes the model's ``candidates.json``, proves it is a corpus ``deny_diff`` can
    consume, and writes the normalized file the differential is pointed at.

``verdict``
    Takes the per-platform ``deny_diff --json`` reports, folds them into one
    verdict, and renders the review body plus the paste-ready golden-path rows.

Why a script and not shell in the workflow: every rule below is a way the lane
could report a false green, and a false green here is worse than no lane at all --
it stands as evidence the question was asked. The rules are testable here and
untestable in a heredoc.

Exit codes, ``validate``: ``0`` a corpus was written, ``2`` the file cannot be
trusted, ``3`` valid but nothing left to adjudicate. Exit codes, ``verdict``: ``0``
no confirmed regression, ``1`` at least one, ``2`` a report was missing or
unreadable. Both fail CLOSED -- a check that could not run never exits 0, because
"could not run" and "found nothing" are the same badge to a reader and must not be
the same exit code.

A candidate is DATA, never authorization. ``deny_diff`` classifies a corpus row's
string; it never executes one. That property is what makes it safe to let a model
write the corpus this lane classifies, and nothing in this script may weaken it --
neither subcommand runs, resolves, or expands anything a candidate names.
"""

from __future__ import annotations

import argparse
import importlib.util
import json
import sys
from pathlib import Path
from typing import Any

#: Row ceiling. A capped file is a bounded blast radius for a prompt-injected or
#: runaway generator, and the cap doubles as a quality floor the prompt states in
#: its own terms: fifteen boundary-probing rows beat sixty restatements. Counted
#: BEFORE dedupe, so padding a file with duplicates cannot buy room.
MAX_ROWS = 60

#: Per-command ceiling. The corpus holds operations, not payloads; a multi-kilobyte
#: "command" is either a generated blob or an attempt to smuggle prose through the
#: classifier, and neither is a golden path.
MAX_COMMAND_CHARS = 512


class CandidateError(Exception):
    """A candidate file that cannot be trusted. Always exit 2, never a pass."""


def _load_deny_diff() -> Any:
    """Import ``deny_diff`` beside this file, for its row schema and nothing else.

    The schema lives in ONE place on purpose. A second validator here would drift
    from the classifier's, and the drift would show up as a row this script
    accepted and the differential then rejected -- which surfaces as a gate that
    errored rather than as the malformed row it is.
    """
    path = Path(__file__).resolve().parent / "deny_diff.py"
    spec = importlib.util.spec_from_file_location("_scope_deny_diff", path)
    if spec is None or spec.loader is None:
        raise CandidateError(f"cannot load the row schema from {path}")
    module = importlib.util.module_from_spec(spec)
    # Registered BEFORE exec: a script's dataclasses resolve their own annotations
    # through `sys.modules[cls.__module__]`, so a module executed without a
    # registration raises at class-creation time rather than at use.
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def _read_json(path: Path, what: str) -> Any:
    try:
        raw = path.read_text(encoding="utf-8")
    except OSError as exc:
        raise CandidateError(f"cannot read {what} {path}: {exc}") from exc
    try:
        return json.loads(raw)
    except json.JSONDecodeError as exc:
        raise CandidateError(f"{what} {path} is not valid JSON: {exc}") from exc


def _rows_of(payload: Any, what: str) -> list[dict[str, Any]]:
    """The ``golden_paths`` array out of a corpus-shaped payload.

    Accepts the wrapper object and a bare list, matching ``deny_diff.load_corpus``
    so a candidate file and the committed corpus are the same shape.
    """
    if isinstance(payload, dict):
        if "golden_paths" not in payload:
            raise CandidateError(f"{what} is an object without a 'golden_paths' key")
        payload = payload["golden_paths"]
    if not isinstance(payload, list):
        raise CandidateError(f"{what} must hold a list of rows, got {type(payload).__name__}")
    return payload


def _key(row: dict[str, Any]) -> tuple[str, str, str]:
    """The identity of a row: kind, command, platform.

    The same triple ``ledger.py import-golden-paths`` is idempotent on, so a
    candidate the corpus already carries is recognised as the duplicate it is
    rather than probed a second time.
    """
    return (
        str(row.get("kind", "")).strip(),
        str(row.get("command_or_flow", "")).strip(),
        str(row.get("platform", "any")).strip(),
    )


def validate(
    candidates_path: Path,
    corpus_path: Path | None,
    out_path: Path,
    max_rows: int = MAX_ROWS,
    max_command_chars: int = MAX_COMMAND_CHARS,
) -> int:
    """Normalize the model's candidates into a corpus the differential can read.

    Four rules, each closing a way this lane could report a false green:

    *Schema by the classifier's own validator.* Every row goes through
    ``deny_diff``'s row parser, which rejects an unknown ``kind``, an empty
    command, and an unknown ``platform`` by position. A dropped-and-continued row
    would mean the differential ran over a subset nobody chose.

    *Caps before dedupe.* :data:`MAX_ROWS` and :data:`MAX_COMMAND_CHARS` bound a
    generator that ran away or was steered, and counting before dedupe means a
    padded file cannot buy itself room.

    *Dedupe against the BASE corpus.* A candidate the committed corpus already
    holds is already gated by the denial differential; re-probing it spends a slot
    and reports a finding the other lane owns. Dropped, and counted in the report.

    *An empty result is exit 3, not exit 0.* ``deny_diff`` refuses an empty corpus,
    so writing one would surface as a gate that errored. "Every candidate was
    already covered" is a real and honest outcome, and it needs its own code so
    the workflow can say so instead of failing.
    """
    deny_diff = _load_deny_diff()

    payload = _read_json(candidates_path, "candidate file")
    raw_rows = _rows_of(payload, f"candidate file {candidates_path}")
    if not raw_rows:
        raise CandidateError(f"candidate file {candidates_path} holds no rows")
    if len(raw_rows) > max_rows:
        raise CandidateError(
            f"candidate file {candidates_path} holds {len(raw_rows)} rows, cap is {max_rows}"
        )

    for position, row in enumerate(raw_rows):
        if not isinstance(row, dict):
            raise CandidateError(f"candidate row {position} is not an object")
        command = row.get("command_or_flow")
        if isinstance(command, str) and len(command) > max_command_chars:
            raise CandidateError(
                f"candidate row {position} has a {len(command)}-char command, "
                f"cap is {max_command_chars}"
            )

    # The classifier's own parser is the schema. It raises DenyDiffError naming the
    # offending position, which is the message a reviewer needs, so let it through
    # as a CandidateError rather than restating it.
    try:
        deny_diff.load_corpus(candidates_path)
    except Exception as exc:  # DenyDiffError, by any other import path
        raise CandidateError(f"{candidates_path} is not a valid corpus: {exc}") from exc

    known: set[tuple[str, str, str]] = set()
    if corpus_path is not None:
        for row in _rows_of(_read_json(corpus_path, "base corpus"), f"base corpus {corpus_path}"):
            if isinstance(row, dict):
                known.add(_key(row))

    kept: list[dict[str, Any]] = []
    seen: set[tuple[str, str, str]] = set()
    already_covered = 0
    self_duplicates = 0
    for row in raw_rows:
        key = _key(row)
        if key in known:
            already_covered += 1
            continue
        if key in seen:
            self_duplicates += 1
            continue
        seen.add(key)
        kept.append(row)

    summary = {
        "proposed": len(raw_rows),
        "already_in_corpus": already_covered,
        "duplicate_candidates": self_duplicates,
        "to_adjudicate": len(kept),
    }

    if not kept:
        print(json.dumps(summary, indent=2))
        print(
            "Every candidate is already a committed golden path -- nothing new to "
            "adjudicate. The denial differential already gates these rows.",
            file=sys.stderr,
        )
        return 3

    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(json.dumps({"golden_paths": kept}, indent=2), encoding="utf-8")
    print(json.dumps(summary, indent=2))
    return 0


def _report_leg(path: Path) -> dict[str, Any]:
    """One ``deny_diff --json`` report, validated enough to be summarized.

    A report whose shape is not what this reader expects is exit 2, not an empty
    leg: a leg silently read as "no regressions" is the exact false green the
    fail-closed rule exists for.
    """
    payload = _read_json(path, "differential report")
    if not isinstance(payload, dict):
        raise CandidateError(f"differential report {path} is not an object")
    for field in ("platform", "counts", "regressions"):
        if field not in payload:
            raise CandidateError(f"differential report {path} has no '{field}'")
    if not isinstance(payload["counts"], dict) or not isinstance(payload["regressions"], list):
        raise CandidateError(f"differential report {path} has a malformed 'counts'/'regressions'")
    return payload


def verdict(report_paths: list[Path], out_md: Path | None, out_rows: Path | None) -> int:
    """Fold the per-platform reports into one verdict and one review body.

    Two properties earn their place here:

    *No report is exit 2.* A lane with nothing to read has measured nothing. The
    caller must not be able to reach a green by failing to produce a report.

    *A leg that classified nothing is reported as NO VERDICT*, never as a pass.
    Every row skipped on platform grounds means this host was asked about rows that
    do not apply to it, and the platform the diff actually touched may be the one
    with no verdict at all. The prompt requires that stated per platform; this is
    where the statement comes from.
    """
    if not report_paths:
        raise CandidateError("no differential report given -- nothing was measured")

    legs = [(path, _report_leg(path)) for path in report_paths]

    # Fail closed on a run where NOTHING was classified. Every leg reporting zero
    # classified rows means no host was asked a question it could answer -- the
    # markdown says NO VERDICT, and an exit 0 beside it would publish a green badge
    # over an unmeasured change, which is this lane's worst failure mode.
    if not any(int(report["counts"].get("classified", 0) or 0) for _, report in legs):
        raise CandidateError(
            "no leg classified a single candidate -- nothing was measured, so there "
            "is nothing to pass"
        )

    lines: list[str] = ["### Security scope review -- adjudicated candidates", ""]
    confirmed: list[dict[str, Any]] = []
    for path, report in legs:
        counts = report["counts"]
        platform = str(report.get("platform", "?"))
        classified = int(counts.get("classified", 0) or 0)
        regressions = report["regressions"]
        if classified == 0:
            lines.append(
                f"- **{platform}: NO VERDICT** -- {counts.get('total_rows', 0)} rows in the "
                f"corpus, none classified on this host "
                f"(skipped on platform: {counts.get('skipped_platform', 0)}, "
                f"on kind: {counts.get('skipped_kind', 0)}). "
                "Not a pass for this platform."
            )
        else:
            lines.append(
                f"- **{platform}**: {classified} classified, "
                f"**{len(regressions)} newly refused**, "
                f"{counts.get('unchanged_allowed', 0)} still allowed."
            )
        absent = int(counts.get("base_absent_tiers", 0) or 0)
        if absent:
            lines.append(
                f"    - {absent} deny check(s) absent at the base ref -- this change "
                "introduces them, so their refusals are new by construction."
            )
        for row in regressions:
            entry = dict(row)
            entry["platform_leg"] = platform
            confirmed.append(entry)

    if confirmed:
        lines += ["", "#### Newly refused (confirmed by the real classifier at both refs)", ""]
        for row in confirmed:
            lines += [
                f"- `{row.get('command')}` ({row.get('platform')}, leg {row.get('platform_leg')})",
                f"    - Who loses it: {row.get('why_legitimate')}",
                f"    - Refused by: **{row.get('head_tier') or 'unreported tier'}** -- "
                f"{row.get('head_refusal')}",
            ]
        lines += [
            "",
            "Each row above is an operation that the base ref ALLOWS and this change "
            "REFUSES. Narrow the rule at the tier named. Withdrawing a row is not the "
            "way to green: that is its own pull request, on its own merits.",
        ]
    else:
        lines += ["", "No candidate flipped from allowed to refused."]

    body = "\n".join(lines) + "\n"
    print(body, end="")
    if out_md is not None:
        out_md.write_text(body, encoding="utf-8")

    if out_rows is not None:
        # Paste-ready, in the committed corpus's own shape: a confirmed regression is
        # exactly the row the corpus was missing. Proposed only -- adding it is a
        # reviewed edit with an approver, never this script's to make.
        rows = [
            {
                "kind": row.get("kind", "shell"),
                "command_or_flow": row.get("command"),
                "platform": row.get("platform", "any"),
                "reason": row.get("why_legitimate", ""),
            }
            for row in confirmed
        ]
        out_rows.write_text(json.dumps({"golden_paths": rows}, indent=2), encoding="utf-8")

    return 1 if confirmed else 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    sub = parser.add_subparsers(dest="command", required=True)

    v = sub.add_parser("validate", help="normalize a candidate file into a corpus")
    v.add_argument("--candidates", required=True, type=Path, help="the model's candidate JSON")
    v.add_argument(
        "--corpus",
        type=Path,
        default=None,
        help="the BASE golden-paths corpus, to drop candidates it already holds",
    )
    v.add_argument("--out", required=True, type=Path, help="where to write the normalized corpus")
    v.add_argument("--max-rows", type=int, default=MAX_ROWS)
    v.add_argument("--max-command-chars", type=int, default=MAX_COMMAND_CHARS)

    d = sub.add_parser("verdict", help="fold per-platform differential reports into one verdict")
    d.add_argument(
        "--report",
        action="append",
        default=[],
        type=Path,
        help="a deny_diff --json report; repeat once per platform leg",
    )
    d.add_argument("--out-md", type=Path, default=None, help="write the review body here")
    d.add_argument(
        "--out-rows",
        type=Path,
        default=None,
        help="write the confirmed rows as a paste-ready golden_paths corpus",
    )

    parsed = parser.parse_args(list(sys.argv[1:] if argv is None else argv))
    try:
        if parsed.command == "validate":
            return validate(
                parsed.candidates,
                parsed.corpus,
                parsed.out,
                max_rows=parsed.max_rows,
                max_command_chars=parsed.max_command_chars,
            )
        return verdict(parsed.report, parsed.out_md, parsed.out_rows)
    except CandidateError as exc:
        print(f"scope_candidates: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
