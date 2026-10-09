"""Key history: who created which access key, for whom, and where it was later used.

This is a small in-memory map built from the cleaned, time-sorted events:

    key id -> created by (event, caller, address) -> made for (target user) -> uses

It only describes what the log shows. It does not judge anything.
"""
from dataclasses import dataclass, field

from cloudtrace.quality import Event

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
    named = e.request.get("userName")
    if isinstance(named, str) and named:
        return named, "request"
    key = e.response.get("accessKey")
    if isinstance(key, dict) and isinstance(key.get("userName"), str) and key["userName"]:
        return key["userName"], "response"
    me = caller_user_name(e)
    if me:
        return me, "caller"
    return None, "unknown"


def same_user(a: str, b: str) -> bool:
    """IAM user names are not case sensitive ('John' and 'john' are the same user)."""
    return a.casefold() == b.casefold()


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
    uses: list[KeyUse] = field(default_factory=list)

    def as_dict(self) -> dict:
        return {
            "key_id": self.key_id,
            "created_event_id": self.created_event_id,
            "created_time": self.created_time,
            "creator_arn": self.creator_arn,
            "creator_ip": self.creator_ip,
            "target_user": self.target_user,
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
        if is_create_access_key(e) and not e.error_code:
            key_id = created_key_id(e)
            if key_id and key_id not in history:
                target, _ = resolve_target(e)
                history[key_id] = KeyRecord(
                    key_id=key_id, created_event_id=e.event_id, created_time=_iso(e),
                    creator_arn=e.identity_arn, creator_ip=e.source_ip, target_user=target)
            continue
        record = history.get(e.access_key_id) if e.access_key_id else None
        if record is not None:  # events are sorted, so this is after creation
            record.uses.append(KeyUse(e.event_id, _iso(e), e.source_ip, e.user_agent, e.name))
    return history
