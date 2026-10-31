# Settings guide for a supplied log

Run:

```sh
cloudtrace tune data/fixtures/c07_attack_use_delayed_past_window/events.json
cloudtrace tune data/fixtures/c07_attack_use_delayed_past_window/events.json --out settings_guide.md
cloudtrace tune LOG --config rules/default.toml
```

The guide prints aggregate counts and first-observed-use delays in minutes. It includes no
user names, account IDs, key IDs, source addresses, input paths or absolute event timestamps.
The command only reads the input. An output file is created only when --out is supplied.

One setting changes at a time. Window values are 15, 30, 60, 120, 240, 480 and 1440 minutes;
history requirements are 1, 3, 5, 7 and 9 earlier owner events. A custom current value is also
included. All other settings, including approved roles and elevated policies, remain fixed.

The time window affects Check 2 and Check 3. The history requirement affects Check 2 only.
The columns distinguish finding rows, distinct flagged events, NOT_CHECKED decisions and
Check 2 outside-window decisions. These are observed detector outputs, not ground-truth labels.

For C07, first observed use is 180 minutes after creation. The 60- and 120-minute windows
produce no medium+ finding; 240 minutes includes the use. The committed output is in
results/tune/c07_tune.md and is checked by a regression test.

No linked use means no observed use in the supplied file. The key may be used after the file
ends or in missing data. Timing summaries include all tracked keys; detection counts follow
the implemented cross-identity scope and approved-role exceptions.

Without independently labelled data, this guide cannot calculate false positives, distinguish
attacks from administration, select an optimal value or prove that a setting is safe. Compare
proposed settings against approved workflows and labelled cases before using them operationally.
