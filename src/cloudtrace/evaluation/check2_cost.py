"""What did Check 2 version 2 cost in false alarms, and what did it gain? (Stage 11, T5)

Version 1 judged only the first use of a key. Version 2 judges every different address used with
the key inside the window. Version 2 catches an attacker who first uses the key from the owner's
usual address (attacker-change test M7). The price: a normal person who uses the key from a
second NEW address inside the window now raises an alert too.

This module builds small generated stories for exactly those cases, runs both versions on the same
logs, and counts. Version 1 is a frozen copy (check2_v1.py). All data is made up, and the share of
normal stories that use a key from a second new address is OUR assumption, not a measured rate.
"""
import random
from contextlib import contextmanager

from cloudtrace import __version__, engine
from cloudtrace.evaluation import check2_v1, detectors, generator, metrics
from cloudtrace.evaluation import scenarios as sc

SEEDS = (1, 2, 3, 4, 5)
PER_SEED = 8                  # stories of each kind per seed (40 per kind over five seeds)
EXTRA_PER_SEED = (0, 3, 6, 12)  # extra "second new address" normal stories added to the T2 mix

KINDS = {  # kind: attack?
    "attack_new_first": True,
    "attack_known_then_new": True,
    "benign_one_known_address": False,
    "benign_two_known_addresses": False,
    "benign_known_then_new_address": False,
}
STORY_TEXT = {
    "attack_new_first": "Admin makes a key; first used from a new address (control attack)",
    "attack_known_then_new": ("Admin makes a key; used once from the owner's usual address, "
                              "then from a new address (the M7 attack)"),
    "benign_one_known_address": "Key for a colleague, used only from his usual address (control)",
    "benign_two_known_addresses": ("Key for a colleague, used from his office address, then from "
                                   "his home address (both already in his history)"),
    "benign_known_then_new_address": ("Key for a colleague, used from his usual address, then "
                                      "from a new address (phone, VPN or new network)"),
}


@contextmanager
def using_check2_v1():
    """Run the normal engine with the frozen version-1 Check 2 instead of version 2."""
    saved = engine.check2
    engine.check2 = check2_v1
    try:
        yield
    finally:
        engine.check2 = saved


def _build(kind: str, log: sc.Log, rng: random.Random, ips: list, t0, tag: str) -> sc.Scenario:
    """One story. Names, keys and creator are unique to the story so stories never mix."""
    attack = KINDS[kind]
    owner = {"name": f"cost{tag}", "key": f"AKIAEXAMPLECOSTOLD{tag}",
             "new_key": f"AKIAEXAMPLECOSTNEW{tag}"}
    admin = {"name": f"costadmin{tag}", "key": f"AKIAEXAMPLECOSTADM{tag}", "ip": ips.pop()}
    usual, home, new_ip = ips.pop(), ips.pop(), ips.pop()
    story = sc.Scenario(sid=f"cost-{tag}", kind=kind, attack=attack, in_scope=attack)

    def owner_event(at, ip):
        src, name = rng.choice(sc.READ_ONLY)
        log.add(at, src, name, sc.user_ident(owner["name"], owner["key"]), ip)

    n_base = rng.randint(4, 8)
    for i in range(n_base):
        owner_event(t0 - sc._minutes((n_base - i) * rng.randint(20, 90)), usual)
    if kind == "benign_two_known_addresses":
        for _ in range(rng.randint(1, 2)):
            owner_event(t0 - sc._minutes(rng.randint(100, 400)), home)

    created = log.add(
        t0, "iam.amazonaws.com", "CreateAccessKey", sc.user_ident(admin["name"], admin["key"]),
        admin["ip"], req={"userName": owner["name"]},
        resp={"accessKey": {"accessKeyId": owner["new_key"], "status": "Active",
                            "userName": owner["name"]}})
    chain = [created]

    def use(minutes, ip, ua=sc.UA_CLI):
        chain.append(log.add(t0 + sc._minutes(minutes), "sts.amazonaws.com", "GetCallerIdentity",
                             sc.user_ident(owner["name"], owner["new_key"]), ip, ua=ua))

    first = rng.randint(2, 25)
    second = first + rng.randint(5, 25)  # always inside the 60-minute window
    ua = sc.UA_OTHER if attack else sc.UA_CLI
    if kind == "attack_new_first":
        use(first, new_ip, ua)
    elif kind == "benign_one_known_address":
        use(first, usual)
    elif kind == "benign_two_known_addresses":
        use(first, usual)
        use(second, home)
    else:  # known address first, then a new one
        use(first, usual)
        use(second, new_ip, ua)
    story.event_ids = chain
    return story


def _extra_stories(seed: int, kind: str, count: int, first_tag: int):
    """`count` extra stories of one kind for `seed`, as (records, scenarios)."""
    rng = random.Random(f"cost-{seed}-{kind}-{count}")
    ips = sc.doc_ips()
    rng.shuffle(ips)
    log = sc.Log(prefix=f"c5{seed}{kind[:3]}")
    stories = []
    for i in range(count):
        t0 = sc.BASE_TIME + sc.timedelta(days=1, minutes=rng.randint(0, 14 * 24 * 60))
        stories.append(_build(kind, log, rng, ips, t0, f"{seed}{first_tag + i:03d}"))
    return log.records, stories


def _flags(records: list, stories: list, version: int) -> tuple:
    """Return (flagged at medium+, flagged with any finding) per story for check 2 version 1 or 2."""
    if version == 1:
        with using_check2_v1():
            det = detectors.run_all(records)
    else:
        det = detectors.run_all(records)
    return det, [(bool(det["ct"]["events"] & set(s.event_ids)),
                  bool(det["ct_any"]["events"] & set(s.event_ids))) for s in stories]


def run_stories(seeds=SEEDS, per_seed=PER_SEED) -> dict:
    """Per story kind: how many stories each version flags (medium+ and any finding)."""
    out = {kind: {"n": 0, "v1": 0, "v2": 0, "v1_any": 0, "v2_any": 0} for kind in KINDS}
    for seed in seeds:
        for kind in KINDS:
            records, stories = _extra_stories(seed, kind, per_seed, 0)
            records = sorted(records, key=lambda r: r["eventTime"])
            for version in (1, 2):
                _, flags = _flags(records, stories, version)
                out[kind][f"v{version}"] += sum(1 for f, _ in flags if f)
                out[kind][f"v{version}_any"] += sum(1 for _, a in flags if a)
            out[kind]["n"] += len(stories)
    return out


def run_mix(seeds=SEEDS, extra_per_seed=EXTRA_PER_SEED) -> list:
    """The T2 mix plus extra normal stories that use the key from a second new address."""
    rows = []
    for per_seed_extra in extra_per_seed:
        per = {1: [], 2: []}
        for seed in seeds:
            records, scs = generator.generate(seed)
            more_records, more = _extra_stories(seed, "benign_known_then_new_address",
                                                per_seed_extra, 0)
            records = sorted(records + more_records, key=lambda r: r["eventTime"])
            scs = scs + more
            for version in (1, 2):
                det, _ = _flags(records, scs, version)
                per[version].append(metrics.score_t2(records, scs, det))
        row = {"extra": per_seed_extra * len(seeds)}
        for version in (1, 2):
            pooled = metrics.pool(per[version])["ct"]
            row[f"v{version}"] = {
                "attacks_caught": pooled["tp_in_scope"], "attacks": pooled["n_in_scope"],
                "normal_flagged": pooled["fp_scenarios"], "normal": pooled["n_benign"],
                "precision": pooled["precision"],
                "false_alarms_per_1000": pooled["false_alarms_per_1000_normal_events"]}
        rows.append(row)
    return rows


def run_cost(seeds=SEEDS) -> dict:
    return {"stories": run_stories(seeds), "mix": run_mix(seeds), "seeds": list(seeds)}


def _pct(x) -> str:
    return "n/a" if x is None else f"{round(100 * x)}%"


INTRO = (
    "Check 2 version 1 judged only the first use of a key. Version 2 judges every different "
    "address used with the key inside the window (see docs/CHECK2.md). Version 2 catches an "
    "attacker who first uses the key from the owner's usual address; this file measures what it "
    "costs in false alarms. Version 1 is a frozen copy of the earlier code "
    "(`evaluation/check2_v1.py`). 'Flagged' means CloudTrace (medium and above) raised an alert "
    "on the story."
)
READING = (
    ("- **Gain:** the attack that uses the key once from the owner's usual address and then from "
     "its own address is missed by version 1 and caught by version 2."),
    ("- **Cost:** a normal person who uses the key from their usual address and then from a "
     "second NEW address inside the window is now flagged (high, score 5). Each such story adds "
     "exactly one false alarm. Nothing changes when the second address is already in the "
     "owner's history, or when only one address is used."),
    ("- **From the log alone, the attack and the normal story look the same.** The only "
     "difference is who is really using the key. A reviewer must ask the owner."),
    ("- **The size of the cost depends on how often real people do this.** That rate is our "
     "assumption, not a measurement. The second table shows the scale: each extra normal story "
     "of this kind lowers precision."),
    ("- Generated logs only. The public log has attacks only, so it cannot measure false "
     "alarms. Version 1 is a frozen copy; a test checks that it reproduces the first-run result."),
)


def render(d: dict) -> str:
    n = d["stories"]["attack_new_first"]["n"]
    out = ["# False-alarm cost of Check 2 version 2 (generated logs)", "",
           (f"Tool version {__version__}. Seeds {d['seeds']}, {n} stories of each kind "
            "(all data made up; truth is how each story was built)."), "", INTRO, "",
           "## Story by story", "",
           "| Story | Truth | Version 1 flags | Version 2 flags | Version 2 any finding |",
           "|---|---|---|---|---|"]
    for kind, row in d["stories"].items():
        truth = "attack" if KINDS[kind] else "normal"
        out.append(f"| {STORY_TEXT[kind]} | {truth} | {row['v1']}/{row['n']} | "
                   f"{row['v2']}/{row['n']} | {row['v2_any']}/{row['n']} |")
    out += ["", "## The cost at the scale of the main test mix", "",
            ("The main generated mix (120 in-scope attacks, 270 normal stories) plus extra normal "
             "stories where the key is used from a second new address."), "",
            ("| Extra normal stories of this kind | Version | Attacks caught | Normal flagged | "
             "Precision | False alarms per 1,000 normal events |"), "|---|---|---|---|---|---|"]
    for row in d["mix"]:
        for version in (1, 2):
            r = row[f"v{version}"]
            out.append(f"| {row['extra']} | {version} | {r['attacks_caught']}/{r['attacks']} | "
                       f"{r['normal_flagged']}/{r['normal']} | {_pct(r['precision'])} | "
                       f"{r['false_alarms_per_1000']} |")
    out += ["", "## How to read this", "", *READING, ""]
    return "\n".join(out)
