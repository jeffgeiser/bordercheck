# Changelog

All notable changes to bordercheck are listed here. Versions follow [Semantic Versioning](https://semver.org/).

## 0.1.0 (unreleased)

First release on PyPI. Stdlib only, Python 3.11 or newer.

- Seeds a synthetic customer record (canary plus realistic identifier formats) through your AI stack's normal path, then searches every configured store for it: traces, caches, vector stores, logs and egress.
- Fault phases (model down, long prompt, and your own fault commands) show who answers when the local path fails. A public host answering, or egress to one, is a FAIL.
- Verdicts are conservative: PASS only when the evidence supports it. An unplaced failover or an in-border store that kept identifiers (other than the positive control) is inconclusive, exit 3.
- Sources: paths (honoring the run window), commands (`kubectl logs` and similar), and HTTP. Gzip, bzip2, xz and zstd data are read by content. Formats it can't decode (Parquet, ORC, Avro, Snappy, LZ4, ZIP) are reported as errors, never as clean.
- Reports: `report.md`, `summary.json`, and a one-page `summary.html`, with an optional regulatory appendix (DORA, GDPR Chapter V, EBA outsourcing, AI Act Art. 12).
- Evidence: `evidence` bundles a run with a SHA-256 manifest, and `verify` rechecks it. `diff` flags regressions between runs. `rescan --expect-gone` tests retention.
- `run.json`, `summary.json` and the evidence manifest record the bordercheck version.
- Runnable localhost demo in `examples/demo/`.
