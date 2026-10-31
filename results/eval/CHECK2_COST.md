# False-alarm cost of Check 2 version 2 (generated logs)

Tool version 1.1.0. Seeds [1, 2, 3, 4, 5], 40 stories of each kind (all data made up; truth is how each story was built).

Check 2 version 1 judged only the first use of a key. Version 2 judges every different address used with the key inside the window (see docs/CHECK2.md). Version 2 catches an attacker who first uses the key from the owner's usual address; this file measures what it costs in false alarms. Version 1 is a frozen copy of the earlier code (`evaluation/check2_v1.py`). 'Flagged' means CloudTrace (medium and above) raised an alert on the story.

## Story by story

| Story | Truth | Version 1 flags | Version 2 flags | Version 2 any finding |
|---|---|---|---|---|
| Admin makes a key; first used from a new address (control attack) | attack | 40/40 | 40/40 | 40/40 |
| Admin makes a key; used once from the owner's usual address, then from a new address (the M7 attack) | attack | 0/40 | 40/40 | 40/40 |
| Key for a colleague, used only from his usual address (control) | normal | 0/40 | 0/40 | 40/40 |
| Key for a colleague, used from his office address, then from his home address (both already in his history) | normal | 0/40 | 0/40 | 40/40 |
| Key for a colleague, used from his usual address, then from a new address (phone, VPN or new network) | normal | 0/40 | 40/40 | 40/40 |

## The cost at the scale of the main test mix

The main generated mix (120 in-scope attacks, 270 normal stories) plus extra normal stories where the key is used from a second new address.

| Extra normal stories of this kind | Version | Attacks caught | Normal flagged | Precision | False alarms per 1,000 normal events |
|---|---|---|---|---|---|
| 0 | 1 | 120/120 | 50/270 | 71% | 13.18 |
| 0 | 2 | 120/120 | 50/270 | 71% | 13.18 |
| 15 | 1 | 120/120 | 50/285 | 71% | 12.72 |
| 15 | 2 | 120/120 | 65/285 | 65% | 16.54 |
| 30 | 1 | 120/120 | 50/300 | 71% | 12.27 |
| 30 | 2 | 120/120 | 80/300 | 60% | 19.63 |
| 60 | 1 | 120/120 | 50/330 | 71% | 11.5 |
| 60 | 2 | 120/120 | 110/330 | 52% | 25.31 |

## How to read this

- **Gain:** the attack that uses the key once from the owner's usual address and then from its own address is missed by version 1 and caught by version 2.
- **Cost:** a normal person who uses the key from their usual address and then from a second NEW address inside the window is now flagged (high, score 5). Each such story adds exactly one false alarm. Nothing changes when the second address is already in the owner's history, or when only one address is used.
- **From the log alone, the attack and the normal story look the same.** The only difference is who is really using the key. A reviewer must ask the owner.
- **The size of the cost depends on how often real people do this.** That rate is our assumption, not a measurement. The second table shows the scale: each extra normal story of this kind lowers precision.
- Generated logs only. The public log has attacks only, so it cannot measure false alarms. Version 1 is a frozen copy; a test checks that it reproduces the first-run result.
