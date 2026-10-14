"""Builds synthetic CloudTrail-style scenarios with known ground truth.

Everything here is fake: documentation IP ranges only, made-up account, keys that contain EXAMPLE.
Each scenario is labelled by the generator (what it was built to be), never by the detectors.

Scenario kinds
  attack_cross_new_ip        admin makes a key for a user; it is first used from an unknown address
  attack_cross_creator_ip    same, but first used from the admin's own address
  attack_grant_key           admin rights granted to a user, then a key made for them, then used
  attack_self_key            a compromised user makes a key for themselves and uses it from a new
                             address (OUTSIDE CloudTrace's stated scope; included to be fair to B3)
  benign_self_rotation       a user rotates their own key and tests the new one
  benign_handover_usual_ip   key made for a colleague, used from their usual address
  benign_handover_new_ip     key made for a colleague, used first from a new address (lookalike)
  benign_automation          an approved automation role makes the key
  benign_onboarding          new user: rights granted, key made, first used from a new address
                             (lookalike)
  benign_failed              key creation refused by AWS
  benign_unused_key          key made for a colleague and never used in the log

The share of "lookalike" benign cases is OUR assumption, not a measured real-world rate.
"""
import random
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta

ACCOUNT = "123456789012"
BASE_TIME = datetime(2026, 1, 1, 0, 0, 0, tzinfo=UTC)
ADMIN_POLICY = "arn:aws:iam::aws:policy/AdministratorAccess"
APPROVED_ROLE = "ci-deploy"
UA_CLI = "aws-cli/2.15.0 Python/3.11.8 Windows/10"
UA_OTHER = "curl/8.5.0"
READ_ONLY = [("s3.amazonaws.com", "ListBuckets"), ("sts.amazonaws.com", "GetCallerIdentity"),
             ("ec2.amazonaws.com", "DescribeInstances"), ("iam.amazonaws.com", "ListUsers")]

ATTACK_KINDS = ("attack_cross_new_ip", "attack_cross_creator_ip", "attack_grant_key",
                "attack_self_key")
BENIGN_KINDS = ("benign_self_rotation", "benign_handover_usual_ip", "benign_handover_new_ip",
                "benign_automation", "benign_onboarding", "benign_failed", "benign_unused_key")
IN_SCOPE_ATTACKS = ("attack_cross_new_ip", "attack_cross_creator_ip", "attack_grant_key")
ALL_KINDS = ATTACK_KINDS + BENIGN_KINDS


def doc_ips() -> list[str]:
    """All usable addresses in the three documentation ranges (never real addresses)."""
    return [f"{net}.{n}" for net in ("192.0.2", "198.51.100", "203.0.113") for n in range(1, 255)]


@dataclass
class Scenario:
    sid: str
    kind: str
    attack: bool
    in_scope: bool
    event_ids: list = field(default_factory=list)  # the events that make up the key story
    mutation: str | None = None


class Allocator:
    """Hands out unique user names, keys and addresses so scenarios never share them."""

    def __init__(self, rng: random.Random):
        self.rng = rng
        self.ips = doc_ips()
        rng.shuffle(self.ips)
        self.users = 0
        self.admins = [(f"admin{i}", self.ips.pop(), f"AKIAEXAMPLEADMIN{i:04d}") for i in range(1, 5)]

    def ip(self) -> str:
        return self.ips.pop()

    def user(self, name: str | None = None) -> dict:
        self.users += 1
        n = self.users
        return {"name": name or f"user{n:03d}", "ip": self.ip(), "key": f"AKIAEXAMPLEOLD{n:04d}",
                "new_key": f"AKIAEXAMPLENEW{n:04d}"}


class Log:
    """Collects records with unique event IDs."""

    def __init__(self, prefix: str = "g"):
        self.prefix = prefix
        self.records: list = []

    def add(self, when: datetime, source: str, name: str, ident: dict, ip: str | None,
            ua: str | None = UA_CLI, req=None, resp=None, err: str | None = None) -> str:
        event_id = f"{self.prefix}-{len(self.records) + 1:05d}"
        rec = {"eventVersion": "1.08", "userIdentity": ident,
               "eventTime": when.strftime("%Y-%m-%dT%H:%M:%SZ"), "eventSource": source,
               "eventName": name, "awsRegion": "us-east-1", "sourceIPAddress": ip,
               "userAgent": ua, "requestParameters": req, "responseElements": resp,
               "eventID": event_id, "eventType": "AwsApiCall", "recipientAccountId": ACCOUNT}
        if err:
            rec["errorCode"], rec["errorMessage"] = err, "User is not authorized"
        self.records.append(rec)
        return event_id


def user_ident(name: str, key: str) -> dict:
    return {"type": "IAMUser", "principalId": "AIDAEXAMPLE" + name.upper().replace("-", ""),
            "arn": f"arn:aws:iam::{ACCOUNT}:user/{name}", "accountId": ACCOUNT,
            "accessKeyId": key, "userName": name}


def role_ident(role: str, session: str) -> dict:
    return {"type": "AssumedRole", "principalId": f"AROAEXAMPLE:{session}",
            "arn": f"arn:aws:sts::{ACCOUNT}:assumed-role/{role}/{session}", "accountId": ACCOUNT,
            "accessKeyId": "ASIAEXAMPLETEMP0001",
            "sessionContext": {"sessionIssuer": {"type": "Role", "userName": role,
                                                 "arn": f"arn:aws:iam::{ACCOUNT}:role/{role}"}}}


def _minutes(m: float) -> timedelta:
    return timedelta(minutes=m)


def build(kind: str, log: Log, rng: random.Random, alloc: Allocator, t0: datetime,
          opts: dict | None = None, sid: str = "s") -> Scenario:
    """Add one scenario to `log` and return its ground truth.

    `opts` carries the attacker-change settings (see mutations.py): target_in_creator_name,
    use_delay, key_gap, known_first, poison_baseline, via_role, drop_use_source.
    """
    opts = opts or {}
    attack = kind in ATTACK_KINDS
    sc = Scenario(sid=sid, kind=kind, attack=attack, in_scope=kind in IN_SCOPE_ATTACKS)
    onboarding = kind == "benign_onboarding"
    owner = alloc.user()
    creator = rng.choice(alloc.admins)
    creator = {"name": creator[0], "ip": creator[1], "key": creator[2]}
    if opts.get("target_in_creator_name"):  # M1: owner's name sits inside the creator's name
        creator = {"name": f"{owner['name']}-admin", "ip": alloc.ip(), "key": "AKIAEXAMPLEPREFIX01"}
    other_ip = alloc.ip()  # an address the owner never used

    # Earlier activity by the owner (their "usual" addresses). New users have none.
    n_base = 0 if onboarding else rng.randint(4, 8)
    for i in range(n_base):
        when = t0 - _minutes((n_base - i) * rng.randint(20, 90))
        src, name = rng.choice(READ_ONLY)
        log.add(when, src, name, user_ident(owner["name"], owner["key"]), owner["ip"])
    if opts.get("poison_baseline"):  # M8: the attacker's address shows up in the owner's history
        bad = creator["ip"] if kind == "attack_cross_creator_ip" else other_ip
        log.add(t0 - _minutes(rng.randint(5, 25)), "s3.amazonaws.com", "ListBuckets",
                user_ident(owner["name"], owner["key"]), bad, ua=UA_OTHER)

    use_delay = opts.get("use_delay", rng.randint(2, 40))
    chain: list[str] = []
    when = t0

    def caller_ident():
        if kind == "benign_automation" or opts.get("via_role"):
            return role_ident(APPROVED_ROLE, "deploy-session-1")
        return user_ident(creator["name"], creator["key"])

    def create(at: datetime, caller, ip, target: str | None, err: str | None = None) -> str:
        req = {"userName": target} if target else None
        resp = None if err else {"accessKey": {"accessKeyId": owner["new_key"], "status": "Active",
                                               "userName": target or owner["name"],
                                               "createDate": at.strftime("%b %d, %Y %H:%M:%S")}}
        return log.add(at, "iam.amazonaws.com", "CreateAccessKey", caller, ip, req=req, resp=resp,
                       err=err)

    def use(at: datetime, ip: str, ua: str = UA_CLI, drop: bool = False) -> str:
        eid = log.add(at, "sts.amazonaws.com", "GetCallerIdentity",
                      user_ident(owner["name"], owner["new_key"]), ip, ua=ua)
        if drop:
            for rec in log.records:
                if rec["eventID"] == eid:
                    del rec["sourceIPAddress"], rec["userAgent"]
        return eid

    if kind in ("attack_grant_key", "benign_onboarding"):
        chain.append(log.add(when, "iam.amazonaws.com", "AttachUserPolicy",
                             user_ident(creator["name"], creator["key"]), creator["ip"],
                             req={"userName": owner["name"], "policyArn": ADMIN_POLICY}))
        when = when + _minutes(opts.get("key_gap", rng.randint(10, 40)))

    if kind == "attack_self_key":
        bad_ip = other_ip
        cid = create(when, user_ident(owner["name"], owner["key"]), bad_ip,
                     owner["name"] if rng.random() < 0.5 else None)
        chain.append(cid)
        chain.append(use(when + _minutes(use_delay), bad_ip, ua=UA_OTHER))
    elif kind == "benign_self_rotation":
        cid = create(when, user_ident(owner["name"], owner["key"]), owner["ip"],
                     owner["name"] if rng.random() < 0.5 else None)
        chain.append(cid)
        chain.append(use(when + _minutes(rng.randint(1, 30)), owner["ip"]))
    elif kind == "benign_failed":
        chain.append(create(when, caller_ident(), creator["ip"], owner["name"],
                            err="AccessDenied"))
    else:
        chain.append(create(when, caller_ident(), creator["ip"], owner["name"]))
        if kind != "benign_unused_key":
            if kind in ("attack_cross_new_ip", "attack_grant_key", "benign_handover_new_ip",
                        "benign_onboarding"):
                use_ip = other_ip if kind != "benign_onboarding" else owner["ip"]
            elif kind == "attack_cross_creator_ip":
                use_ip = creator["ip"]
            else:  # handover to the usual address, or automation
                use_ip = owner["ip"]
            at = when + _minutes(use_delay)
            if opts.get("known_first"):  # M7: first use from the owner's usual address
                chain.append(use(when + _minutes(1), owner["ip"]))
                at = when + _minutes(rng.randint(5, 20))
            chain.append(use(at, use_ip, ua=UA_OTHER if attack else UA_CLI,
                             drop=bool(opts.get("drop_use_source"))))
            for extra in range(rng.randint(0, 2)):  # a few more uses from the same address
                chain.append(use(at + _minutes(3 * (extra + 1)), use_ip))
    sc.event_ids = chain

    # The owner carries on with their old key as usual (new users have no old key).
    for i in range(0 if onboarding else rng.randint(0, 3)):
        src, name = rng.choice(READ_ONLY)
        log.add(when + _minutes(rng.randint(5, 120)), src, name,
                user_ident(owner["name"], owner["key"]), owner["ip"])
    return sc
