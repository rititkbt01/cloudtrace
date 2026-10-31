# Verification for CloudTrace 1.1.1

Verified on 31 October 2026 in a fresh local Git clone of implementation commit 7ef5dcb.
Environment: Linux 6.18.57, Python 3.12.14, pinned development requirements including pytest
9.1.1 and Ruff 0.16.10. A new virtual environment was created and the package was installed
from source. No previous project installation or injected PYTHONPATH was used.

| Check | Result |
|---|---|
| Full automated suite in fresh Git checkout | 316 passed, zero failures, zero skips |
| Ruff | All checks passed |
| Installed CLI entry point | Passed |
| C01 analysis | High finding, score 8, plus low note |
| C01 --fail-on high | Expected exit code 1 |
| C07 tune command | Output matches the saved aggregate guide |
| Synthetic, mutation, sensitivity, delay and cost tables | Regenerated output matches saved files |
| Pinned public dataset | 55 files, 2900 records, 2 labelled key creations |
| Public medium+ / any finding | 1/2 and 2/2, saved output matches |

The fresh-check transcript is in fresh_check_result.txt. Public data was rerun separately
against commit f0d55993fb575f747cee13069adeaa999c940b14 of Invictus IR Sigma-AWS. The MIT licence
was inspected; raw public logs are not included in this source archive.

The corrected suite adds 33 regression cases to the original 283 collected cases, and fixes
the original version-mismatch failure. These regressions are implementation checks, not an
independent real-world accuracy sample. Original synthetic medium+ results remain 120/120
in-scope attacks caught and 50/270 benign stories flagged (71% story precision).

The included source archive omits .git. If tests are run directly after extraction, one Git-only
repository-hygiene check is expected to skip. Copy into the existing Git checkout to run all
316 checks, or initialize a local Git repository before running the suite.

The uploaded final Word report and slides are not modified by this code release. Update their
version to 1.1.1, their test count to the actual final run, their fresh-check evidence and their
repository/release links. Use docs/SUBMISSION.md to reconcile remaining research limitations.

The later evidence-only commit includes this record without changing the tested implementation.
