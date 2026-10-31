"""Describe settings on one supplied log without labels or recommendations.

Only aggregate counts and durations are rendered. User names, key IDs, source addresses,
input paths and absolute event timestamps are never included in the settings guide.
"""
from datetime import datetime
from statistics import median

from cloudtrace import __version__, config, engine

WINDOWS = (15, 30, 60, 120, 240, 480, 1440)
HISTORIES = (1, 3, 5, 7, 9)


def _count(result: dict) -> dict:
    rows = result["verdicts"]
    alerts = [r for r in rows if r["verdict"] == "ALERT" and r["score"] >= 3]
    return {
        "medium_plus_findings": len(alerts),
        "flagged_events": len({r["event_id"] for r in alerts}),
        "not_checked_decisions": sum(r["verdict"] == "NOT_CHECKED" for r in rows),
        "check2_outside_window": sum(r["reason"] == "OUTSIDE_WINDOW" for r in rows),
    }


def analyze(records: list, settings: dict | None = None) -> dict:
    cfg = config.resolve(settings)
    base = engine.analyze(records, cfg)
    delays = sorted(
        (datetime.fromisoformat(k["uses"][0]["time"])
         - datetime.fromisoformat(k["created_time"])).total_seconds() / 60
        for k in base["key_history"] if k["uses"])
    windows = sorted(set(WINDOWS) | {cfg["window_minutes"]})
    histories = sorted(set(HISTORIES) | {cfg["baseline_min_events"]})
    return {
        "records": base["quality"]["total_records"],
        "usable_events": base["quality"]["usable_events"],
        "tracked_keys": len(base["key_history"]),
        "keys_with_observed_use": len(delays),
        "keys_without_observed_use": len(base["key_history"]) - len(delays),
        "first_use_minutes": {"minimum": round(min(delays), 2),
                              "median": round(median(delays), 2),
                              "maximum": round(max(delays), 2)} if delays else None,
        "window_minutes": cfg["window_minutes"],
        "baseline_min_events": cfg["baseline_min_events"],
        "windows": {w: _count(engine.analyze(records, {**cfg, "window_minutes": w}))
                    for w in windows},
        "histories": {n: _count(engine.analyze(records, {**cfg, "baseline_min_events": n}))
                      for n in histories},
    }


def _table(title: str, data: dict, current: int) -> list[str]:
    out = [f"## {title}", "",
           ("| Setting | Medium+ findings | Distinct flagged events | NOT_CHECKED decisions | "
            "Check 2 outside-window decisions |"), "|---|---|---|---|---|"]
    for value, counts in data.items():
        mark = " (current)" if value == current else ""
        out.append(f"| {value}{mark} | {counts['medium_plus_findings']} | "
                   f"{counts['flagged_events']} | {counts['not_checked_decisions']} | "
                   f"{counts['check2_outside_window']} |")
    return out + [""]


def render(data: dict) -> str:
    out = ["# CloudTrace settings guide", "", f"Tool version {__version__}.", "",
           f"- Records read: {data['records']}; usable: {data['usable_events']}",
           (f"- Keys tracked: {data['tracked_keys']}; observed use: {data['keys_with_observed_use']}; "
            f"no observed use: {data['keys_without_observed_use']}")]
    delays = data["first_use_minutes"]
    if delays:
        out.append(f"- First observed use after creation (minutes): minimum {delays['minimum']}, "
                   f"median {delays['median']}, maximum {delays['maximum']}")
    else:
        out.append("- No linked use observed; first-use durations cannot be calculated.")
    out += ["", ("Counts describe observations in this log. They are not attack labels, false-positive "
                 "rates or recommended settings."), ""]
    out += _table("Time window in minutes", data["windows"], data["window_minutes"])
    out += _table("Earlier owner events required", data["histories"], data["baseline_min_events"])
    out += ["## Interpretation", "",
            "- One setting changes at a time. Other supplied settings remain fixed.",
            "- The time window affects both Check 2 use correlation and Check 3 grant correlation.",
            ("- Check 2 examines cross-identity keys not excluded by an approved-role exception. "
             "Self-created keys remain outside Check 2 scope."),
            "- Findings are rows; several findings can refer to one event. NOT_CHECKED is uncertainty.",
            ("- No observed use means no linked event in this file, not that the key was never used. "
             "The end of the log limits observation."),
            ("- Timing summaries cover all tracked keys, including self-created and excluded keys. "
             "Finding counts follow the actual detector scope."),
            "- Without labels these tables cannot identify attacks, false alarms or an optimal setting.",
            "- Only counts and durations are printed. Analysis reads files without contacting AWS.", ""]
    return "\n".join(out)
