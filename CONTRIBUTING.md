# Contributing

Recipes for other parts of the stack are the most useful contribution: a gateway, model server, tracing tool, log platform, vector store or egress source that `docs/enterprise-stacks.md` doesn't cover yet. Fixes and new checks are welcome too.

## Ground rules

- **Standard library only.** No third-party dependencies in `bordercheck/`. Security teams review this before running it, and every dependency makes that harder.
- **Read-only.** Sources only read. A recipe that writes to a store, or needs write credentials, won't be accepted.
- **Never store what was matched.** Hits record where and which pattern, not the content. Error messages must not quote data read from a source.
- **Credentials stay out of command lines.** Use the tool's own credential store (`~/.pgpass`, `REDISCLI_AUTH`, a netrc or curl config file, cloud CLI profiles) or `${VAR}` in `headers`.

## Adding a recipe

1. Run it against a real instance of the tool, and say which version in the PR.
2. Add it to `docs/enterprise-stacks.md` under the matching section, as a `[[sources]]` block with a one-line note on what it reads and anything that's easy to get wrong (default limits, pagination, time windows).
3. Use the run window placeholders (`{{run_started}}`, `{{run_minutes}}`) and `{{page}}` for paged APIs, so the scan covers the run and nothing else.

## Code changes

```bash
python -m unittest discover -s tests      # must pass on Python 3.11, 3.12 and 3.13 (CI runs all three)
python examples/demo/demo_stack.py        # should still end in FAIL with the documented findings
```

Add a test for a bug fix that fails without the fix. Keep changes focused; one PR per fix or feature.

## Reporting a vulnerability

Don't open a public issue. Use a private security advisory on this repository, as described in `SECURITY.md`.

## Sharing output

Run reports can name internal hosts, paths and stores. Use `bordercheck report --redact` before pasting anything into an issue, and never paste `scan.json`, `run.json` or a config from a real environment.
