# Check 1: key created for a different identity

**Question:** did one identity create an access key for another identity?
**Why it matters:** this is a known way to keep access after the original login is removed
(MITRE ATT&CK T1098.001, "Additional Cloud Credentials"). It is also what normal key hand-over
and automation look like, so on its own it is only a low note.

## Fields used
`eventSource` = `iam.amazonaws.com`, `eventName` = `CreateAccessKey`, `errorCode`,
`userIdentity` (type, arn, userName, session issuer role), `requestParameters.userName`,
`responseElements.accessKey.{accessKeyId,userName}`.

## Who was the key for? (we do not guess from names alone)
1. The user name in the request, if given.
2. Otherwise the user name in AWS's reply.
3. Otherwise the caller's own user (AWS uses the caller when the name is left out).
4. Otherwise unknown, so the result is `NOT_CHECKED / TARGET_UNKNOWN`.

IAM user names are not case sensitive, so `John` and `john` count as the same user.
A user ARN with a path (`user/team/alice`) is reduced to the name `alice`.

## Decision order (first match wins)
| # | Condition | Verdict | Reason |
|---|---|---|---|
| 1 | The call failed | IGNORED | FAILED_CALL |
| 2 | Target cannot be worked out | NOT_CHECKED | TARGET_UNKNOWN |
| 3 | Target is the caller (name given) | IGNORED | SELF_KEY |
| 3 | Target is the caller (name left out) | IGNORED | SELF_KEY_IMPLICIT |
| 4 | Caller is an approved automation role (`allowed_roles`) | IGNORED | ALLOW_LISTED_ROLE |
| 5 | Anything else | ALERT (low, 1 point) | KEY_FOR_OTHER_ACCOUNT |

Every row also has a plain-language `explanation` and an `evidence` block (time, caller, target,
how the target was known, source address, new key ID).

## Known false positives
Real onboarding, key hand-over, and automation not on the approved list. Use `allowed_roles`.

## Known evasions / limits
- Check 1 alone is a low note, by design.
- An attacker who uses an approved role is not flagged by this check.
- If the logs do not contain the creation event, nothing can be said.

## Key history
`cloudtrace.lineage.build()` links each successfully created key to who made it, who it is for,
and every later event signed with that key (time, address, tool). Check 2 will use it in Stage 5.
