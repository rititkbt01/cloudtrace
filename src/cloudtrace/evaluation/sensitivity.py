"""How much do the two main settings matter?

We change one setting at a time on the generated logs (T2) and count what CloudTrace (medium and
above) catches and flags. The shipped defaults were fixed before this table was made and are not
tuned to it: this is a description of the trade-off, not a search for better numbers.
"""
from cloudtrace import engine
from cloudtrace.evaluation import detectors, generator

WINDOWS = (15, 30, 60, 120, 240)
BASELINES = (1, 3, 5, 7, 9)
SEEDS = (1, 2, 3, 4, 5)  # the same seeds as run.DEFAULT_SEEDS (checked by a test)
DEFAULT = {"window_minutes": 60, "baseline_min_events": 3}


def _count(logs: list, cfg: dict) -> dict:
    caught = in_scope = flagged = benign = unknown = 0
    for records, scenarios in logs:
        rows = engine.analyze(records, {**detectors.CONFIG, **cfg})["verdicts"]
        alerts = {r["event_id"] for r in rows
                  if r["verdict"] == "ALERT" and r["score"] >= detectors.MEDIUM}
        not_checked = {r["event_id"] for r in rows if r["verdict"] == "NOT_CHECKED"}
        for s in scenarios:
            ids = set(s.event_ids)
            if s.attack and s.in_scope:
                in_scope += 1
                if ids & alerts:
                    caught += 1
                elif ids & not_checked:
                    unknown += 1
            elif not s.attack:
                benign += 1
                flagged += bool(ids & alerts)
    return {"caught": caught, "in_scope": in_scope, "flagged": flagged, "benign": benign,
            "not_checked": unknown}


def run_sensitivity(seeds=SEEDS) -> dict:
    logs = [generator.generate(seed) for seed in seeds]
    return {
        "seeds": list(seeds),
        "window_minutes": {w: _count(logs, {**DEFAULT, "window_minutes": w}) for w in WINDOWS},
        "baseline_min_events": {b: _count(logs, {**DEFAULT, "baseline_min_events": b})
                                for b in BASELINES},
    }


def _table(title: str, setting: str, data: dict) -> list:
    head = (f"| {setting} | Attacks caught | Normal stories flagged | "
            "Attacks it said 'not checked' |")
    out = [f"### {title}", "", head, "|---|---|---|---|"]
    for value, d in data.items():
        mark = " (default)" if value == DEFAULT[setting] else ""
        out.append(f"| {value}{mark} | {d['caught']}/{d['in_scope']} | "
                   f"{d['flagged']}/{d['benign']} | {d['not_checked']} |")
    return out + [""]


def render(s: dict) -> str:
    intro = (f"Seeds {s['seeds']}, all added up. One setting changes at a time; the other stays at its "
             "default. 'CloudTrace (medium and above)' is counted, as in RESULTS.md.")
    out = ["# Settings sensitivity (generated logs, T2)", "", intro, ""]
    out += _table("Time window (minutes)", "window_minutes", s["window_minutes"])
    out += _table("Earlier events needed before 'usual addresses' are trusted", "baseline_min_events",
                  s["baseline_min_events"])
    out += ["## How to read this", "",
            ("- The defaults (60 minutes, 3 events) were chosen before this table existed and were not "
             "changed after seeing it."),
            ("- A shorter window misses attacks whose first use comes later. Going above 60 minutes changes "
             "nothing here because the generated stories use the key 2 to 40 minutes after it is made; "
             "on real logs a longer window may also let in more look-alike normal cases."),
            ("- A higher history requirement makes CloudTrace say 'not checked' more often (accounts with "
             "little history), which loses attacks but never invents alerts."),
            ("- These are generated logs. They show how the settings behave, not the best values for a "
             "real organisation."), ""]
    return "\n".join(out)
