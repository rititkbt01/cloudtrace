# Check 3: strong rights granted, then a key created

**Question:** was an identity given strong rights and then, shortly after, given a new key by someone else?
**Why it matters:** raising an account's power and then adding a way to log in as it is a common way to keep access.
(MITRE ATT&CK T1098 and T1098.001. A clue, not proof; it also looks like normal onboarding.)

## How it works
For every key creation that Check 1 flagged, look back over the window (`window_minutes`, default 60,
inclusive) for a successful `AttachUserPolicy` on the **same user** with a policy listed in
`elevated_policies` (default: AdministratorAccess). If found, the key creation gets an ALERT
`GRANT_THEN_CREDENTIAL`. The most recent matching grant is reported.

Points: cross_identity 1 + elevated_grant 3 = 4 (medium). Check 3 is separate from Check 2; if both
fire on the same key you see both rows.

## Not covered (on purpose, to stay inside scope)
Inline policies, group or role policy attachments, `CreateLoginProfile`, and grants after the key.
