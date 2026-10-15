"""T3: run every detector on a public log that lives outside the repository.

Only totals are written. No account number, user name, address or event ID from the public
log is printed, so nothing from that data is copied into this repository.

Labels come from the dataset's own documentation (Stratus Red Team technique pages) and were
written down before the log was scored. Settings and scoring weights were not changed after
the log was first opened.
"""
from collections import Counter
from pathlib import Path

from cloudtrace import __version__
from cloudtrace.evaluation import detectors
from cloudtrace.evaluation.run import LABELS
from cloudtrace.ingest import load_records

# Stratus Red Team technique pages: the user that receives the new key -> technique name.
TECHNIQUES = {
    "stratus-red-team-backdoor-u-user": "aws.persistence.iam-backdoor-user",
    "malicious-iam-user": "aws.persistence.iam-create-admin-user",
}
SOURCE = "Invictus Incident Response, Sigma-AWS (GitHub), MIT licence"
ORDER = ("ct", "ct_any", "b1", "b2", "b2x", "b3")


def _key_target(record: dict) -> str | None:
    key = (record.get("responseElements") or {}).get("accessKey") or {}
    return key.get("userName")


def _successful_key_creations(records: list) -> list:
    return [r for r in records
            if r.get("eventSource") == "iam.amazonaws.com" and r.get("eventName") == "CreateAccessKey"
            and not r.get("errorCode")]


def run_t3(path, techniques: dict | None = None) -> dict:
    """Score one folder or file of public CloudTrail records. Returns totals only."""
    techniques = TECHNIQUES if techniques is None else techniques
    source = Path(path)
    records = load_records(source)
    det = detectors.run_all(records)

    creations = _successful_key_creations(records)
    labelled = {r["eventID"]: techniques[_key_target(r)]
                for r in creations if _key_target(r) in techniques}
    unlabelled = {r["eventID"] for r in creations} - set(labelled)

    keys_never_used = sum(1 for k in det["_history"] if not k["uses"])
    quality = det["_quality"]
    verdicts = Counter((row["verdict"], row["reason"]) for row in det["_rows"])
    files = 1 if source.is_file() else sum(1 for _ in source.rglob("*.json*"))
    per_detector = {}
    for name in ORDER:
        events = det[name]["events"]
        per_detector[name] = {"caught": len(events & set(labelled)),
                              "other_key_creations_flagged": len(events & unlabelled)}
    return {
        "files": files,
        "records": quality["total_records"],
        "usable": quality["usable_events"],
        "time_start": quality["time_start"],
        "time_end": quality["time_end"],
        "duplicates_removed": quality["duplicates_removed"],
        "reordered": quality["reordered"],
        "missing_fields": quality["missing_fields"],
        "key_creations": len(creations),
        "labelled_attacks": len(labelled),
        "techniques": sorted(set(labelled.values())),
        "other_key_creations": len(unlabelled),
        "keys_tracked": len(det["_history"]),
        "keys_never_used": keys_never_used,
        "detectors": per_detector,
        "cloudtrace_decisions": {f"{v} {reason}": n for (v, reason), n in sorted(verdicts.items())},
    }


INTRO = ("The log files are not stored in this repository and nothing from them (accounts, "
         "users, addresses, event IDs) is printed here.")
HONEST = [
    "- Only {n} labelled key creations exist in this log. Percentages would mislead, so counts are shown.",
    ("- The log contains attack techniques only. It has no normal key stories, so precision and "
     "false alarms cannot be measured from it; that is what the generated logs (T2) are for."),
    ("- A key that is never used later in the log gives Check 2 nothing to judge, so it can only "
     "reach medium through Check 3."),
    ("- Labels come from the Stratus Red Team technique pages, not from any detector. B1, B2 and "
     "B3 are re-implementations of published rule logic."),
    "- The log was first opened to check its format. No setting or weight was changed afterwards.",
]


def render(t3: dict) -> str:
    n = t3["labelled_attacks"]
    missing = ", ".join(f"{k} ({v})" for k, v in sorted(t3["missing_fields"].items())) or "none"
    techniques = ", ".join(t3["techniques"]) or "none"
    reordered = "yes" if t3["reordered"] else "no"
    out = [
        "# T3: public log result (totals only)", "",
        f"Tool version {__version__}. Source: {SOURCE}. {INTRO}", "",
        "## The log", "",
        f"- Files read: {t3['files']}; records read: {t3['records']}; usable: {t3['usable']}",
        f"- Time range: {t3['time_start']} to {t3['time_end']}",
        f"- Duplicates removed: {t3['duplicates_removed']}; out of order: {reordered}",
        f"- Missing fields: {missing}",
        (f"- Successful key creations: {t3['key_creations']} (labelled attacks: {n}; "
         f"not labelled: {t3['other_key_creations']})"),
        (f"- Keys followed: {t3['keys_tracked']}; never used later in the log: "
         f"{t3['keys_never_used']}"),
        f"- Labelled techniques: {techniques}", "",
        "## Result", "",
        "| Detector | Labelled attacks caught | Other key creations flagged |", "|---|---|---|",
    ]
    for name in ORDER:
        d = t3["detectors"][name]
        out.append(f"| {LABELS[name]} | {d['caught']}/{n} | {d['other_key_creations_flagged']} |")
    out += ["", "## What CloudTrace decided (counts)", ""]
    out += [f"- {k}: {v}" for k, v in t3["cloudtrace_decisions"].items()] or ["- no decisions"]
    out += ["", "## Reading this honestly", ""]
    out += [line.format(n=n) for line in HONEST] + [""]
    return "\n".join(out)


def run(path, out_dir) -> dict:
    t3 = run_t3(path)
    out = Path(out_dir)
    out.mkdir(parents=True, exist_ok=True)
    (out / "RESULTS_T3.md").write_text(render(t3), encoding="utf-8")
    return t3
