"""Tier T2: a seeded synthetic log with many scenarios (normal noise + injected attacks)."""
import random

from cloudtrace.evaluation import scenarios as sc

DEFAULT_COUNTS = {
    "attack_cross_new_ip": 8, "attack_cross_creator_ip": 8, "attack_grant_key": 8,
    "attack_self_key": 8,
    "benign_self_rotation": 12, "benign_handover_usual_ip": 12, "benign_handover_new_ip": 6,
    "benign_automation": 8, "benign_onboarding": 4, "benign_failed": 4, "benign_unused_key": 8,
}


def generate(seed: int, counts: dict | None = None) -> tuple[list, list]:
    """Return (records sorted by time, scenarios). The same seed always gives the same log."""
    counts = counts or DEFAULT_COUNTS
    rng = random.Random(seed)
    alloc = sc.Allocator(rng)
    log = sc.Log(prefix=f"t2s{seed}")
    kinds = [k for k, n in counts.items() for _ in range(n)]
    rng.shuffle(kinds)
    scenarios = []
    for i, kind in enumerate(kinds):
        t0 = sc.BASE_TIME + sc.timedelta(days=1, minutes=rng.randint(0, 14 * 24 * 60))
        scenarios.append(sc.build(kind, log, rng, alloc, t0, sid=f"s{seed}-{i:03d}"))
    records = sorted(log.records, key=lambda r: r["eventTime"])
    return records, scenarios
