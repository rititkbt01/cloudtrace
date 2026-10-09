"""Turns the decision record into a report: JSON for machines, Markdown for people.

The report never says an attack is confirmed. A finding means "please review".
The output is the same every time for the same input (no clock values).
"""
import json

from cloudtrace import __version__, baselines, engine

SEVERITY_ORDER = {"high": 0, "medium": 1, "low": 2}

NEXT_STEP = {
    "KEY_FOR_OTHER_ACCOUNT": (
        "Ask the creator and the key's owner whether this key was expected. If not, review "
        "what the key was used for and consider disabling it."),
    "KEY_USED_FROM_NEW_SOURCE": (
        "Check with the key's owner whether the new address is theirs. If not, review other "
        "activity from that address and consider disabling the key."),
    "GRANT_THEN_CREDENTIAL": (
        "Check that the rights grant and the new key were both approved. If not, review the "
        "identity's recent activity."),
}

LIMITS = [
    ("Results come from the log file you supplied only. 'Usual' addresses mean 'seen earlier in "
     "this log', so a short log makes many things look new."),
    ("A finding means 'please review', not 'attack confirmed'. No finding does not mean safe: "
     "CloudTrail does not record everything, and time windows can be waited out."),
    "CloudTrace only reads files. It never connects to a cloud account or changes anything.",
]


def build(records: list, config: dict | None = None, input_name: str = "input",
          baseline: bool = True) -> dict:
    result = engine.analyze(records, config)
    verdicts = result["verdicts"]
    alerts = [v for v in verdicts if v["verdict"] == "ALERT"]
    q = result["quality"]
    total = q["total_records"]
    report = {
        "tool": "cloudtrace",
        "version": __version__,
        "input": input_name,
        "settings": result["config"],
        "summary": {
            "records_read": total,
            "usable_events": q["usable_events"],
            "coverage_percent": round(100 * q["usable_events"] / total, 1) if total else 0.0,
            "candidate_events": len({v["event_id"] for v in verdicts}),
            "alerts": {s: sum(1 for v in alerts if v["severity"] == s)
                       for s in ("high", "medium", "low")},
            "ignored": sum(1 for v in verdicts if v["verdict"] == "IGNORED"),
            "not_checked": sum(1 for v in verdicts if v["verdict"] == "NOT_CHECKED"),
        },
        "quality": q,
        "verdicts": verdicts,
        "key_history": result["key_history"],
    }
    if baseline:
        b1 = baselines.b1_backdoor_keys(records)
        report["baseline_b1"] = {
            "name": baselines.B1_NAME,
            "alerts": b1,
            "comparison": baselines.compare_with_check1(
                b1, [v for v in verdicts if v["check"] == "check1"]),
        }
    return report


def to_json(report: dict) -> str:
    return json.dumps(report, indent=2, sort_keys=False) + "\n"


def highest_severity(report: dict) -> str | None:
    found = [s for s, n in report["summary"]["alerts"].items() if n]
    return min(found, key=SEVERITY_ORDER.get) if found else None


def _cell(text) -> str:
    return str(text if text is not None else "").replace("|", "\\|").replace("\n", " ")


def _breakdown(v: dict) -> str:
    return ", ".join(f"{k} {n}" for k, n in v["score_breakdown"].items())


def to_markdown(report: dict) -> str:
    s, q = report["summary"], report["quality"]
    out = ["# CloudTrace report", "",
           f"- Input: `{report['input']}`",
           f"- Tool version: {report['version']}",
           f"- Time range in log: {q['time_start'] or 'n/a'} to {q['time_end'] or 'n/a'}",
           (f"- Records read: {s['records_read']}; usable: {s['usable_events']} "
            f"({s['coverage_percent']}%)"),
           f"- Key-creation events examined: {s['candidate_events']}", ""]

    out += ["## Summary", "", "| Result | Count |", "|---|---|",
            f"| Findings, high | {s['alerts']['high']} |",
            f"| Findings, medium | {s['alerts']['medium']} |",
            f"| Findings, low | {s['alerts']['low']} |",
            f"| Ignored (with reason) | {s['ignored']} |",
            f"| Not checked (with reason) | {s['not_checked']} |", ""]

    alerts = sorted((v for v in report["verdicts"] if v["verdict"] == "ALERT"),
                    key=lambda v: (SEVERITY_ORDER[v["severity"]], v["evidence"]["time"]))
    out += ["## Findings to review", ""]
    if not alerts:
        out += ["No findings. This does not mean the account is safe (see Notes and limits).", ""]
    for v in alerts:
        out += [f"### [{v['severity'].upper()}] {v['reason']} - event {v['event_id']}", "",
                f"- Check: {v['check']}",
                f"- Time: {v['evidence']['time']}",
                f"- Why: {v['explanation']}",
                f"- Score: {v['score']} ({_breakdown(v)})",
                f"- Next step for a person: {NEXT_STEP.get(v['reason'], 'Review this event.')}",
                ""]

    out += ["## Decision record (why each candidate did or did not alert)", "",
            "| Check | Event | Time | Result | Reason | Explanation |", "|---|---|---|---|---|---|"]
    for v in report["verdicts"]:
        out.append(f"| {v['check']} | {_cell(v['event_id'])} | {_cell(v['evidence']['time'])} | "
                   f"{v['verdict']} | {v['reason']} | {_cell(v['explanation'])} |")
    out.append("")

    out += ["## Log quality", "",
            (f"- Duplicates removed: {q['duplicates_removed']} "
             f"(conflicting copies: {q['conflicting_duplicates']})"),
            f"- Events were out of time order: {'yes' if q['reordered'] else 'no'}",
            f"- Unusable records: {len(q['unusable'])}"]
    for u in q["unusable"]:
        out.append(f"  - record {u['index']}: {u['reason']}")
    if q["missing_fields"]:
        out.append("- Missing fields: " + ", ".join(
            f"{k} ({n})" for k, n in sorted(q["missing_fields"].items())))
    out.append("")

    out += ["## Key history", ""]
    if report["key_history"]:
        out += ["| Key | Created (event) | Created by | Made for | First use |", "|---|---|---|---|---|"]
        for k in report["key_history"]:
            use = k["uses"][0] if k["uses"] else None
            first = f"{use['time']} from {use['source_ip']}" if use else "not used in this log"
            out.append(f"| {_cell(k['key_id'])} | {k['created_time']} ({k['created_event_id']}) | "
                       f"{_cell(k['creator_arn'])} | {_cell(k['target_user'])} | {_cell(first)} |")
    else:
        out.append("No keys were created successfully in this log.")
    out.append("")

    if "baseline_b1" in report:
        b = report["baseline_b1"]
        out += [f"## Comparison with a single-event rule: {b['name']}", "",
                f"The single-event rule raised {len(b['alerts'])} alert(s) on the raw log.", ""]
        if b["comparison"]:
            out += ["| Event | B1 alerts | Check 1 | Agreement |", "|---|---|---|---|"]
            for c in b["comparison"]:
                out.append(f"| {_cell(c['event_id'])} | {c['b1_alerts']} | "
                           f"{c['check1_verdict']} / {c['check1_reason']} | {_cell(c['note'])} |")
        out.append("")

    out += ["## Notes and limits", ""] + [f"- {t}" for t in LIMITS] + [""]
    return "\n".join(out)
