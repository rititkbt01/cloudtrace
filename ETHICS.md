# Ethics and safe use

CloudTrace was built for the CyberFox Society Cybersecurity R&D Internship under its rules: lawful, authorised,
ethical work only.

## What the project does and does not do
- It **reads files** you give it. It never connects to AWS or any live system, never scans anything, and never
  changes permissions, disables accounts or blocks activity.
- No attack tools are run. The attacker-change tests only edit made-up JSON files.
- Findings mean "please review". They are not proof of wrongdoing, and no finding is not proof of safety.

## Data
- **Made-up data:** the test cases and generated logs use a made-up account number, made-up key IDs that contain the
  word EXAMPLE, and addresses only from the three ranges reserved for documentation (192.0.2.x, 198.51.100.x,
  203.0.113.x). Tests enforce this.
- **One public log:** Sigma-AWS by Invictus Incident Response (MIT licence), which records Stratus Red Team attack
  simulations. It is downloaded by the user into `data/public/`, which Git ignores. It is never committed, and
  the result file contains totals only (no account numbers, user names, addresses or event IDs).
- **No real credentials or personal data** are in this repository. `tests/test_repo_hygiene.py` scans every text file
  for credential-like strings and for real-looking addresses and account numbers, and runs on every push.

## If you use this on your own logs
Use only logs you are allowed to analyse. Treat the report as sensitive: it contains names and addresses from your logs.
Any use that involves a live system or a third-party service needs the owner's written approval first.

## Honest limits
Results on generated data do not prove real-world performance (see README and docs/EVALUATION.md).
