"""Delayed key use versus the time window.

Check 2 only looks at uses of a key inside the window after it is created. A patient attacker can wait
longer. This test makes the same story many times, changes how long after creation the key is first used,
and counts what CloudTrace (medium and above) flags for each window size.

Two stories are run on the same grid:
  - an attack: key made for someone else, first used from an address the owner never used;
  - a look-alike normal story: key handed to a colleague who first uses it from a new address.
Both are flagged under exactly the same condition (first use inside the window), because from the log alone
they look the same. The table therefore shows the price of a longer window only if real hand-overs are
slow; how slow they are cannot be learned from made-up data.
"""
import random

from cloudtrace import engine
from cloudtrace.evaluation import detectors, scenarios

DELAYS = (10, 30, 60, 90, 120, 240, 480, 1440)    # minutes between key creation and first use
WINDOWS = (30, 60, 120, 240, 480, 1440)           # window_minutes settings tried
VARIANTS = 20
ATTACK = "attack_cross_new_ip"
LOOKALIKE = "benign_handover_new_ip"


def _records(kind: str, delay: int, variant: int) -> tuple[list, set]:
    rng = random.Random(f"delay-{kind}-{delay}-{variant}")
    alloc = scenarios.Allocator(rng)
    log = scenarios.Log(prefix=f"dl{delay}v{variant}")
    t0 = scenarios.BASE_TIME + scenarios.timedelta(days=1)
    sc = scenarios.build(kind, log, rng, alloc, t0, {"use_delay": delay}, sid=f"{kind}-{delay}-{variant}")
    return sorted(log.records, key=lambda r: r["eventTime"]), set(sc.event_ids)


def _flagged(records: list, chain: set, window: int) -> bool:
    rows = engine.analyze(records, {**detectors.CONFIG, "window_minutes": window})["verdicts"]
    return any(r["verdict"] == "ALERT" and r["score"] >= detectors.MEDIUM and r["event_id"] in chain
               for r in rows)


def run_delay(variants: int = VARIANTS) -> dict:
    out = {"variants": variants, "delays": list(DELAYS), "windows": list(WINDOWS)}
    for kind in (ATTACK, LOOKALIKE):
        grid = {d: dict.fromkeys(WINDOWS, 0) for d in DELAYS}
        for delay in DELAYS:
            for v in range(variants):
                records, chain = _records(kind, delay, v)
                for window in WINDOWS:
                    grid[delay][window] += _flagged(records, chain, window)
        out[kind] = grid
    return out


def _table(title: str, grid: dict, n: int) -> list:
    out = [f"### {title}", "", "| First use after | " + " | ".join(f"window {w} min" for w in WINDOWS) + " |",
           "|---|" + "---|" * len(WINDOWS)]
    for delay, row in grid.items():
        cells = " | ".join(f"{row[w]}/{n}" for w in WINDOWS)
        out.append(f"| {delay} min | {cells} |")
    return out + [""]


def render(d: dict) -> str:
    n = d["variants"]
    out = ["# Delayed key use versus the time window (generated logs)", "",
           (f"Each cell: stories flagged by CloudTrace (medium and above) out of {n}. The shipped window is "
            "60 minutes. The same stories are run for every window; only `window_minutes` changes."), ""]
    out += _table("Attack: key made for someone else, first used from a new address", d[ATTACK], n)
    out += _table("Look-alike normal story: key handed to a colleague, first used from a new address",
                  d[LOOKALIKE], n)
    out += ["## How to read this", "",
            ("- A key first used **after** the window is not judged by Check 2, so the attack is not flagged "
             "(Check 1 still leaves a low note). The result is the same for the attack and for the normal "
             "story, because the log shows nothing else that tells them apart."),
            ("- A longer window catches slower attackers, but it also flags a colleague who is slow to use "
             "a key from a new address. In our generated normal stories the first use is always within "
             "40 minutes, so a longer window costs nothing here (see SENSITIVITY.md). Real hand-overs "
             "may be slower; that is an assumption we cannot check without real normal logs."),
            "- A very patient attacker (longer than any window we would accept) cannot be caught by this check.",
            "- Generated logs only. This describes how the setting behaves, not a recommended value.", ""]
    return "\n".join(out)
