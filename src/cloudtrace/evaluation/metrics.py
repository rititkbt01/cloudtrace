"""Scoring: turn detector output plus ground truth into the numbers we report.

Unit of judgement: a SCENARIO (one key story). A detector "flags" a scenario when it raises an
alert on any event of that story. We also count false alarms per 1,000 normal events.
"""
from cloudtrace.evaluation.mutations import DETECTORS


def _ratio(a: int, b: int) -> float | None:
    return round(a / b, 3) if b else None


def score_t2(records: list, scenarios: list, det: dict) -> dict:
    """Numbers for one generated log."""
    attack_ids = {e for s in scenarios if s.attack for e in s.event_ids}
    normal_total = len({r["eventID"] for r in records} - attack_ids)
    rows = det["_rows"]
    state = {}
    for r in rows:
        state.setdefault(r["event_id"], set()).add((r["verdict"], r["reason"]))
    out = {}
    for d in DETECTORS:
        events = det[d]["events"]
        flagged = [(s, bool(events & set(s.event_ids))) for s in scenarios]
        tp_in = sum(1 for s, f in flagged if f and s.attack and s.in_scope)
        tp_out = sum(1 for s, f in flagged if f and s.attack and not s.in_scope)
        fp = sum(1 for s, f in flagged if f and not s.attack)
        by_kind: dict = {}
        for s, f in flagged:
            k = by_kind.setdefault(s.kind, [0, 0])
            k[0] += f
            k[1] += 1
        false_alarm_events = len(events - attack_ids)
        out[d] = {
            "tp_in_scope": tp_in, "n_in_scope": sum(1 for s in scenarios if s.attack and s.in_scope),
            "tp_out_of_scope": tp_out,
            "n_out_of_scope": sum(1 for s in scenarios if s.attack and not s.in_scope),
            "fp_scenarios": fp, "n_benign": sum(1 for s in scenarios if not s.attack),
            "alert_events": len(events), "raw_alerts": det[d]["raw_alerts"],
            "false_alarm_events": false_alarm_events, "normal_events": normal_total,
            "by_kind": by_kind,
        }
    # CloudTrace extras: honest "don't know" count and explained suppressions.
    unknown = 0
    for s in scenarios:
        missed = s.attack and s.in_scope and not (det["ct"]["events"] & set(s.event_ids))
        if missed and any(v == "NOT_CHECKED" for e in s.event_ids for v, _ in state.get(e, ())):
            unknown += 1
    b1_normal = det["b1"]["events"] - attack_ids
    explained = sum(1 for e in b1_normal
                    if any(v in ("IGNORED", "NOT_CHECKED") for v, _ in state.get(e, ())))
    out["extras"] = {"ct_in_scope_attacks_not_checked": unknown,
                     "b1_alerts_on_normal_events": len(b1_normal),
                     "of_those_ct_gave_a_reason": explained}
    return out


def pool(per_seed: list[dict]) -> dict:
    """Add up the counts over several seeds and keep the per-seed ranges."""
    pooled: dict = {"seeds": len(per_seed)}
    for d in DETECTORS:
        keys = [k for k in per_seed[0][d] if k != "by_kind"]
        tot = {k: sum(p[d][k] for p in per_seed) for k in keys}
        by_kind: dict = {}
        for p in per_seed:
            for kind, (a, b) in p[d]["by_kind"].items():
                cur = by_kind.setdefault(kind, [0, 0])
                cur[0] += a
                cur[1] += b
        recalls = [_ratio(p[d]["tp_in_scope"], p[d]["n_in_scope"]) for p in per_seed]
        fa = [round(1000 * p[d]["false_alarm_events"] / p[d]["normal_events"], 2)
              for p in per_seed]
        tp = tot["tp_in_scope"] + tot["tp_out_of_scope"]
        tot.update(
            by_kind=by_kind,
            precision=_ratio(tp, tp + tot["fp_scenarios"]),
            recall_in_scope=_ratio(tot["tp_in_scope"], tot["n_in_scope"]),
            recall_out_of_scope=_ratio(tot["tp_out_of_scope"], tot["n_out_of_scope"]),
            false_alarms_per_1000_normal_events=round(
                1000 * tot["false_alarm_events"] / tot["normal_events"], 2),
            recall_in_scope_range=[min(recalls), max(recalls)],
            false_alarms_per_1000_range=[min(fa), max(fa)],
        )
        pooled[d] = tot
    pooled["extras"] = {k: sum(p["extras"][k] for p in per_seed) for k in per_seed[0]["extras"]}
    return pooled
