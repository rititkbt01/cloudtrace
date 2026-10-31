"""Key history: who created which access key, for whom, and where it was later used.

This is a small in-memory map built from the cleaned, time-sorted events:

    key id -> created by (event, caller, address) -> made for (target user) -> uses

It only describes what the log shows. It does not judge anything.
"""
from dataclasses import dataclass, field

from cloudtrace.quality import Event, arn_scope

IAM = "iam.amazonaws.com"


def is_create_access_key(e: Event) -> bool:
    return e.source == IAM and e.name == "CreateAccessKey"


def name_from_arn(arn: str | None) -> str | None:
    """'arn:aws:iam::123:user/team/alice' -> 'alice' (IAM users may have a path)."""
    if not arn or ":user/" not in arn:
        return None
    return arn.split(":user/", 1)[1].rsplit("/", 1)[-1] or None


def caller_user_name(e: Event) -> str | None:
    """The IAM user name of the caller, if the caller is an IAM user."""
    if e.identity_type != "IAMUser":
        return None
    return e.identity_user_name or name_from_arn(e.identity_arn)


def resolve_target(e: Event) -> tuple[str | None, str]:
    """Work out which IAM user a CreateAccessKey call was for.

    Returns (target user name or None, how we know), where `how` is one of:
      'request'   the call named the user
      'response'  the call left it out and AWS's reply says who the key is for
      'caller'    the call left it out; AWS uses the caller's own user
      'unknown'   cannot be worked out
    """
    raw_request = e.raw.get("requestParameters")
    if raw_request is not None and not isinstance(raw_request, dict):
        return None, "invalid_request"
    named = e.request.get("userName")
    if named is not None and not isinstance(named, str):
        return None, "invalid_target"
    key = e.response.get("accessKey")
    response_user = key.get("userName") if isinstance(key, dict) else None
    if isinstance(named, str) and named:
        if (isinstance(response_user, str) and response_user
                and not same_user(named, response_user)):
            return None, "conflicting_request_response"
        return named, "request"
    if isinstance(key, dict) and isinstance(key.get("userName"), str) and key["userName"]:
        return key["userName"], "response"
    me = caller_user_name(e)
    if me:
        return me, "caller"
    return None, "unknown"


def same_user(a: str, b: str) -> bool:
    """IAM user names are not case sensitive ('John' and 'john' are the same user)."""
    return a.casefold() == b.casefold()


def owner_matches(e: Event, owner: str, account: str | None, partition: str | None) -> bool:
    """A same-named user in another account or partition is a different identity."""
    name = caller_user_name(e)
    return bool(name and caller_known(e) and account and partition and e.caller_account_id == account
                and e.partition == partition and same_user(name, owner))


def caller_known(e: Event) -> bool:
    partition, account = arn_scope(e.identity_arn)
    if (not partition or not account or e.caller_account_id != account
            or e.identity_type not in {"IAMUser", "AssumedRole", "Root", "FederatedUser"}):
        return False
    if e.identity_type == "IAMUser":
        name = caller_user_name(e)
        arn_name = name_from_arn(e.identity_arn)
        return bool(name and arn_name and same_user(name, arn_name))
    return True


def role_allowed(e: Event, allowed: list[str]) -> bool:
    """Full role ARNs are preferred; legacy names are broad exceptions across supplied accounts."""
    return bool((e.role_arn and e.role_arn in allowed)
                or (e.role_name and e.role_name in allowed))


@dataclass
class KeyUse:
    event_id: str
    time: str
    source_ip: str | None
    user_agent: str | None
    event_name: str


@dataclass
class KeyRecord:
    key_id: str
    created_event_id: str
    created_time: str
    creator_arn: str | None
    creator_ip: str | None
    target_user: str | None
    account_id: str | None = None
    partition: str | None = None
    uses: list[KeyUse] = field(default_factory=list)

    def as_dict(self) -> dict:
        return {
            "key_id": self.key_id,
            "created_event_id": self.created_event_id,
            "created_time": self.created_time,
            "creator_arn": self.creator_arn,
            "creator_ip": self.creator_ip,
            "target_user": self.target_user,
            "account_id": self.account_id,
            "partition": self.partition,
            "uses": [u.__dict__ for u in self.uses],
        }


def _iso(e: Event) -> str:
    return e.time.isoformat().replace("+00:00", "Z")


def created_key_id(e: Event) -> str | None:
    key = e.response.get("accessKey")
    if isinstance(key, dict) and isinstance(key.get("accessKeyId"), str):
        return key["accessKeyId"] or None
    return None


def build(events: list[Event]) -> dict[str, KeyRecord]:
    """Build the key history from time-sorted events. Returns {key id: KeyRecord}."""
    history: dict[str, KeyRecord] = {}
    for e in events:
        record = history.get(e.access_key_id) if e.access_key_id else None
        if (record is not None and record.account_id == e.caller_account_id
                and record.partition == e.partition):
            record.uses.append(KeyUse(e.event_id, _iso(e), e.source_ip, e.user_agent, e.name))
        if is_create_access_key(e) and not e.error_code:
            key_id = created_key_id(e)
            if key_id and key_id not in history:
                target, _ = resolve_target(e)
                history[key_id] = KeyRecord(
                    key_id=key_id, created_event_id=e.event_id, created_time=_iso(e),
                    creator_arn=e.identity_arn, creator_ip=e.source_ip, target_user=target,
                    account_id=e.account_id, partition=e.partition)
    return history
