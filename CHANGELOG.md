# Changelog

## 1.1.1

Submission correctness and consistency fixes to the uploaded project snapshot:

- Scope owner history, key use and policy-grant correlation by AWS account and partition.
- Treat unknown or inconsistent creator identity as NOT_CHECKED, without cross-identity points.
- Explain missing created-key IDs and conflicting target evidence.
- Record successful CreateAccessKey operations as use of the credential that signed them.
- Attribute public-evaluation detections to creation plus linked-use events, once per key story.
- Normalize invalid optional JSON field types and reject malformed errorCode values safely.
- Separate input usability, emitted-rule evaluability and key-creation resolution metrics.
- Implement the previously advertised tune command, guide and checked C07 example.
- Align package/runtime version, regenerate examples and evaluation results, and add regressions.

Original scoring weights, default window, default history and implemented detection theme remain
unchanged. The first-use-only historical result is preserved as historical evidence. New tests
cover cases discovered during review and do not constitute an untouched performance holdout.

The original snapshot mixed 1.0.0 runtime/package metadata and 1.1.0 documentation/results.
Version 1.1.1 identifies this corrected snapshot without rewriting that history.
