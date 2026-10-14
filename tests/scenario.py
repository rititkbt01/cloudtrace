"""Tiny builder for custom logs in unit tests (kept separate from the hand-made fixtures)."""
from datetime import UTC, datetime, timedelta

ACC = "123456789012"
NEWKEY = "AKIAEXAMPLENEWKEY01"
T0 = datetime(2026, 1, 1, 9, 0, 0, tzinfo=UTC)
ADMIN_POLICY = "arn:aws:iam::aws:policy/AdministratorAccess"


def stamp(minutes):
    return (T0 + timedelta(minutes=minutes)).strftime("%Y-%m-%dT%H:%M:%SZ")


def user(name, key=None):
    return {"type": "IAMUser", "arn": f"arn:aws:iam::{ACC}:user/{name}", "userName": name,
            "accessKeyId": key if key is not None else f"AKIAEXAMPLE{name.upper()[:8]:0<8}01"}


def event(n, minutes, name, who, ip, source="iam.amazonaws.com", request=None, response=None,
          ua="aws-cli/2.15", error=None, ident=None):
    r = {"eventID": f"s-{n:03d}", "eventTime": stamp(minutes), "eventSource": source,
         "eventName": name, "sourceIPAddress": ip, "userAgent": ua,
         "userIdentity": ident or user(who), "requestParameters": request,
         "responseElements": response, "recipientAccountId": ACC}
    if error:
        r["errorCode"] = error
    return r


def baseline(who, ip, count=3, start_n=1, start_min=0):
    return [event(start_n + i, start_min + i * 10, "ListBuckets", who, ip, source="s3.amazonaws.com")
            for i in range(count)]


def create_key(n, minutes, caller, target, ip, key=NEWKEY):
    return event(n, minutes, "CreateAccessKey", caller, ip, request={"userName": target},
                 response={"accessKey": {"accessKeyId": key, "userName": target,
                                         "status": "Active"}})


def use(n, minutes, who, ip, key=NEWKEY, ua="aws-cli/2.15"):
    return event(n, minutes, "GetCallerIdentity", who, ip, source="sts.amazonaws.com", ua=ua,
                 ident=user(who, key))


def grant(n, minutes, caller, target, ip, policy=ADMIN_POLICY, error=None):
    return event(n, minutes, "AttachUserPolicy", caller, ip,
                 request={"userName": target, "policyArn": policy}, error=error)
