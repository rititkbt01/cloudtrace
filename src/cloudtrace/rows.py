"""One shared way to build a decision-record row, so every check writes the same shape."""
from cloudtrace import scoring
from cloudtrace.quality import Event


def iso(e: Event) -> str:
    return e.time.isoformat().replace("+00:00", "Z")


def make_row(check: str, e: Event, verdict: str, reason: str, why: str, evidence: dict,
             points: list[str] | None = None) -> dict:
    """Build a row. `points` (alerts only) lists the evidence names that add up to the score."""
    row = {"check": check, "event_id": e.event_id, "verdict": verdict, "reason": reason,
           "explanation": why, "evidence": {"time": iso(e), **evidence}}
    if points is not None:
        breakdown, total, band = scoring.score(points)
        row.update(severity=band, score=total, score_breakdown=breakdown)
    return row
