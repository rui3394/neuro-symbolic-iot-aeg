from __future__ import annotations

import argparse
import sys

from ns_aeg.tasks.loader import TaskLoadError, load_dangerous_path_task
from ns_aeg.verifier.symbolic_task_runner import run_symbolic_task_verification
from ns_aeg.verifier.task_adapter import (
    CandidateLoadError,
    load_candidate,
    task_to_verifier_config,
    verify_candidate_for_task,
    write_json,
)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Run task-driven candidate verifier adapter mode.",
    )
    parser.add_argument("--task", required=True, help="dangerous_path_task JSON path.")
    parser.add_argument("--candidate", required=True, help="candidate JSON path.")
    parser.add_argument(
        "--mode",
        choices=["dry-run", "symbolic"],
        default="dry-run",
        help="Verifier mode. Defaults to dry-run for backward compatibility.",
    )
    parser.add_argument(
        "--startup-mode",
        choices=["auto", "full-init", "direct-main"],
        default="auto",
        help="symbolic startup mode. Used only with --mode symbolic.",
    )
    parser.add_argument(
        "--allow-direct-main-for-non-toy",
        action="store_true",
        help="allow direct-main symbolic startup for non-toy/unknown tasks. Use only for explicit debugging.",
    )
    parser.add_argument("--out", required=True, help="output verification result JSON path.")
    args = parser.parse_args(argv)

    try:
        if args.mode == "symbolic":
            task = load_dangerous_path_task(args.task)
            candidate = load_candidate(args.candidate)
            config = task_to_verifier_config(task)
            result = run_symbolic_task_verification(
                config,
                candidate,
                startup_mode=args.startup_mode,
                allow_direct_main_for_non_toy=args.allow_direct_main_for_non_toy,
            )
            result["provenance"] = {
                "task_path": args.task,
                "candidate_path": args.candidate,
            }
            write_json(result, args.out)
        else:
            result = verify_candidate_for_task(args.task, args.candidate, output_path=args.out)
    except (TaskLoadError, CandidateLoadError, ValueError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2

    print(
        f"verified candidate in {result['mode']} mode "
        f"status={result['status']} task_id={result['task_id']} "
        f"candidate_id={result['candidate_id']} out={args.out}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
