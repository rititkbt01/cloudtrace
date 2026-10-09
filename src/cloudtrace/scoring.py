"""Evidence-based severity.

Severity is the sum of points for the evidence found, and the points are always shown.
Nothing is guessed: the same evidence always gives the same score.
These weights are frozen before any public log is scored (Stage 6).
"""

WEIGHTS = {
    "cross_identity": 1,  # key made for a different identity
    "first_use_in_window": 2,  # the new key was used within the window
    "new_source": 2,  # used from an address never seen for that identity in this log
    "creator_source": 3,  # used from the creator's own address
    "elevated_grant": 3,  # strong rights granted just before the key was made
}

# (lowest score, label); checked from the top down
BANDS = ((5, "high"), (3, "medium"), (1, "low"))


def score(evidence: list[str]) -> tuple[dict, int, str]:
    """Return (breakdown, total, band) for a list of evidence names."""
    breakdown = {}
    for name in evidence:
        if name not in WEIGHTS:
            raise KeyError(f"Unknown evidence name: {name}")
        breakdown[name] = WEIGHTS[name]
    total = sum(breakdown.values())
    band = next((label for floor, label in BANDS if total >= floor), "none")
    return breakdown, total, band
