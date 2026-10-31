# Log quality check (Stage 2)

Real logs are messy. Before any check runs, `cloudtrace.quality.clean()` tidies the records
and **reports what it found**, so nothing is silently skipped or mis-ordered.

| Step | What happens | Where it shows in the report |
|---|---|---|
| 1. Unusable records | Records with no `eventID`, `eventTime`, `eventName` or `eventSource`, a time that cannot be read, or that are not objects are set aside with a reason code (`MISSING_EVENT_ID`, `MISSING_EVENT_TIME`, `MISSING_EVENT_NAME`, `MISSING_EVENT_SOURCE`, `BAD_EVENT_TIME`, `NOT_AN_OBJECT`) | `unusable` |
| 2. Duplicates | Records with the same `eventID`: first copy kept, others removed. If a copy differs from the first, it is also counted as conflicting (a data problem) | `duplicates_removed`, `conflicting_duplicates` |
| 3. Sorting | Events sorted by time (UTC). Equal times keep file order. `reordered` says whether the file was out of order | `reordered` |
| 4. Missing fields | Counts how many events lack `userIdentity.arn`, `userIdentity.accessKeyId` (empty counts as missing), `sourceIPAddress`, `userAgent` | `missing_fields` |

Also reported: `total_records`, `usable_events`, `time_start`, `time_end`.

Design choices:
- The input is never changed (copies are made; files are only read).
- An empty `accessKeyId` becomes `None`. AWS documents that this field can be empty. Check 2 later
  uses this to say `NOT_CHECKED / MISSING_KEY_ID` instead of guessing.
- Times without a zone are treated as UTC; times with an offset are converted to UTC.
- Optional fields with invalid JSON types are normalized to unavailable values and counted in
  invalid_fields. A malformed errorCode makes the record unusable (INVALID_ERROR_CODE), so it
  cannot be interpreted as a successful call.
- Caller account and partition are resolved from the ARN; contradictory identity account values
  are not trusted. Resource account uses recipientAccountId when provided.

## Three separate measures
- input_usability_percent = usable deduplicated events / input records. The old coverage_percent
  JSON field is a compatibility alias for this measure, not a detection-coverage claim.
- rule_evaluability_percent = decisions other than NOT_CHECKED / all emitted rule decisions.
  Several checks can emit decisions on one event. With no decisions the percentage is null.
- key_creation_resolution_percent = successful creations with a key ID, target, scoped account
  and resolved creator / successful creations. With no creations the percentage is null.
- lineage_break_decisions counts explicit CREATED_KEY_ID_MISSING and MISSING_KEY_ID decisions.
  Key-creation resolution does not imply every later use was observable or linked.

A never-used key emits no Check 2 decision. These measures are not a count of all possible rules
or all attacks that could occur. Equal timestamps retain input order; this offline tool cannot
infer causal order for events with identical timestamps.

Reading files is in `cloudtrace.ingest.load_records(path)`: a `.json` / `.json.gz` file
(`{"Records": [...]}` or a plain list) or a folder of them. Problems raise `IngestError` with a plain-language message.
