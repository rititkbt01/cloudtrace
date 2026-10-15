"""Command line: cloudtrace analyze LOG [--config FILE] [--out DIR] [--format md|json] ...

Exit codes: 0 = done, 1 = findings at or above --fail-on, 2 = a problem with the input or settings.
"""
import argparse
import sys
from pathlib import Path

from cloudtrace import config as settings
from cloudtrace import report as rep
from cloudtrace.ingest import IngestError, load_records

SEVERITIES = ("low", "medium", "high")


def _parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="cloudtrace",
        description="Read CloudTrail-style logs and explain risky access-key changes. Read-only.")
    sub = p.add_subparsers(dest="command", required=True)
    a = sub.add_parser("analyze", help="analyze a log file or a folder of log files")
    a.add_argument("input", help="a .json / .json.gz CloudTrail file, or a folder of them")
    a.add_argument("--config", help="settings file (TOML), e.g. rules/default.toml")
    a.add_argument("--out", help="folder to write report.json and report.md into")
    a.add_argument("--format", choices=("md", "json"), default="md",
                   help="what to print when --out is not given (default: md)")
    a.add_argument("--no-baseline", action="store_true",
                   help="skip the comparison with the single-event rule")
    a.add_argument("--fail-on", choices=SEVERITIES,
                   help="exit with code 1 if any finding is at this level or higher")
    e = sub.add_parser("evaluate", help="run the synthetic evaluation and attacker-change tests")
    e.add_argument("--out", default="results/eval", help="folder for RESULTS.md and results.json")
    e.add_argument("--seeds", type=int, nargs="+", default=[1, 2, 3, 4, 5],
                   help="random seeds for the generated logs (default: 1 2 3 4 5)")
    e.add_argument("--variants", type=int, default=20,
                   help="random variants per attacker-change test (default: 20)")
    q = sub.add_parser("evaluate-public",
                       help="score a public log kept outside the repository (totals only)")
    q.add_argument("input", help="folder or file with the public CloudTrail log")
    q.add_argument("--out", default="results/public", help="folder for RESULTS_T3.md")
    return p


def _run_evaluate_public(args) -> int:
    from cloudtrace.evaluation import public
    try:
        t3 = public.run(args.input, args.out)
    except IngestError as err:
        print(f"cloudtrace: {err}", file=sys.stderr)
        return 2
    except OSError as err:
        print(f"cloudtrace: cannot write results: {err}", file=sys.stderr)
        return 2
    print(f"Public-log result written to {args.out}/RESULTS_T3.md "
          f"({t3['records']} records, {t3['labelled_attacks']} labelled attacks)")
    return 0


def _run_evaluate(args) -> int:
    from cloudtrace.evaluation import run
    try:
        run.run_all(args.out, seeds=tuple(args.seeds), variants=args.variants)
    except OSError as err:
        print(f"cloudtrace: cannot write results: {err}", file=sys.stderr)
        return 2
    print(f"Evaluation written to {args.out} (RESULTS.md and results.json)")
    return 0


def _run_analyze(args) -> int:
    try:
        cfg = settings.load(args.config) if args.config else settings.resolve(None)
        records = load_records(args.input)
    except (IngestError, settings.ConfigError) as err:
        print(f"cloudtrace: {err}", file=sys.stderr)
        return 2
    name = Path(args.input).name
    report = rep.build(records, cfg, input_name=name, baseline=not args.no_baseline)

    if args.out:
        out = Path(args.out)
        try:
            out.mkdir(parents=True, exist_ok=True)
            (out / "report.json").write_text(rep.to_json(report), encoding="utf-8")
            (out / "report.md").write_text(rep.to_markdown(report), encoding="utf-8")
        except OSError as err:
            print(f"cloudtrace: cannot write the report: {err}", file=sys.stderr)
            return 2
        s = report["summary"]["alerts"]
        print(f"Report written to {out}  (findings: high {s['high']}, medium {s['medium']}, "
              f"low {s['low']})")
    elif args.format == "json":
        sys.stdout.write(rep.to_json(report))
    else:
        sys.stdout.write(rep.to_markdown(report))

    if args.fail_on:
        top = rep.highest_severity(report)
        if top and SEVERITIES.index(top) >= SEVERITIES.index(args.fail_on):
            return 1
    return 0


def main(argv=None) -> int:
    args = _parser().parse_args(argv)
    if args.command == "evaluate":
        return _run_evaluate(args)
    if args.command == "evaluate-public":
        return _run_evaluate_public(args)
    return _run_analyze(args) if args.command == "analyze" else 2


if __name__ == "__main__":
    sys.exit(main())
