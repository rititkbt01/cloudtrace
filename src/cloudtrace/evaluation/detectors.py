"""One uniform interface to every detector: records in, the set of alerted event IDs out."""
from cloudtrace import baselines, engine
from cloudtrace.evaluation.scenarios import APPROVED_ROLE

CONFIG = {"allowed_roles": [APPROVED_ROLE]}
MEDIUM = 3  # score at which a CloudTrace finding counts as an alert (bands: 1-2 low, 3-4 medium)


def run_all(records: list) -> dict:
    """Return {detector: {"events": set of event IDs, "raw_alerts": int, ...}}."""
    result = engine.analyze(records, CONFIG)
    rows = result["verdicts"]
    alerts = [r for r in rows if r["verdict"] == "ALERT"]
    b1 = baselines.b1_backdoor_keys(records)
    b2 = baselines.b2_cross_user(records)
    b2x = baselines.b2_cross_user(records, exclude_roles=(APPROVED_ROLE,))
    b3 = baselines.b3_self_key_used(records)
    return {
        "ct": {"events": {r["event_id"] for r in alerts if r["score"] >= MEDIUM},
               "raw_alerts": sum(1 for r in alerts if r["score"] >= MEDIUM)},
        "ct_any": {"events": {r["event_id"] for r in alerts}, "raw_alerts": len(alerts)},
        "b1": {"events": {r["event_id"] for r in b1}, "raw_alerts": len(b1)},
        "b2": {"events": {r["event_id"] for r in b2}, "raw_alerts": len(b2)},
        "b2x": {"events": {r["event_id"] for r in b2x}, "raw_alerts": len(b2x)},
        "b3": {"events": {r["event_id"] for r in b3}, "raw_alerts": len(b3)},
        "_rows": rows,
        "_quality": result["quality"],
        "_history": result["key_history"],
    }
