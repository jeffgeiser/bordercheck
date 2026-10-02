# canarykit

A test harness for data residency in self-hosted AI stacks. It sends a synthetic customer through your real entry point (usually an AI gateway such as LiteLLM), takes the in-country model away so the gateway's failover runs, then searches your logs, traces, caches, vector stores and egress records for that customer. The output is a report organized by residency layer, with a pass, fail or inconclusive verdict and an exit code you can gate on.

Residency is usually argued from architecture diagrams and config: where the GPUs are, which region a deployment is pinned to. canarykit tests behavior instead. In our lab, with the model in Frankfurt, the customer's data still turned up in stores nobody had listed, and in a public API in the US once the local model failed over. No request returned an error.

Standard-library Python 3.11+, no dependencies, read-only against everything it scans.

## How it works

```
 new ──> send baseline ──> fault start ──> send fault ──> fault stop ──> scan ──> report
  │          │                  │               │                         │         │
  │          └─ records who answered each request (status, timing,        │         └─ verdict + exit code
  │             served-by headers/fields); bodies are never stored        │
  │                                             your own commands,        └─ read-only search of
  └─ synthetic customer: CNRY-XXXX-XXXX          shown and confirmed         every source you list
     canary + 14-digit account number            before they run
```

**What it searches for.** The canary exactly and lowercased, its base64 encoding at all three byte alignments (so it's found inside base64-encoded JSON, as tracing exporters and queues often store it), the account number plain and space-grouped, and the harness's own request ids. Request ids go somewhere your stack logs them but away from the identifiers (the OpenAI `user` field works well), which is how the report tells "this store saw the request but redacted the customer" from "this store isn't on the request path."

**What it records.** For each hit: source, file or URL, line and byte offset, and which pattern matched. Never the matching content.

**The four residency layers.** Every source is tagged with one, and a layer with no sources is reported as **not checked**, never as clean:

| Layer | Typical stores |
|---|---|
| Data | system of record, data lake tables fed from the AI stack |
| Processing | local model, fallback endpoints, batch jobs, external guardrail services |
| Model state | semantic/prompt caches, vector stores, KV-cache offload, agent memory |
| Logs and control plane | gateway and app logs, LLM tracing, raw event buckets, SIEM, egress proxy |

## Verdict and exit codes

| Verdict | Exit | Meaning |
|---|---|---|
| **pass** | 0 | No identifiers in sources outside the border, no egress to public model APIs the border doesn't allow, a positive control found the customer, and no source had errors |
| **fail** | 1 | Identifiers were found outside the border, or egress logs show traffic to a disallowed model API. A found leak stands regardless of anything else |
| **inconclusive** | 3 | Nothing crossed the border in what was scanned, but the evidence is incomplete: no positive control, a positive control that found nothing, a source with errors, or a different backend answered during the fault with no egress source to show where it runs |

Config errors exit 2. The reasons are listed at the top of `report.md` and in `summary.json`.

**Positive control.** Mark one source you know stores prompts with `positive_control = true` (with seeded mode, the system of record you loaded the customer into). If it doesn't find the customer, the scan itself is broken: a wrong time window, a missing permission, a log shipper that hasn't flushed. A clean result without a working positive control can't be told apart from a broken scan, so it's never a pass.

## Quick start

Requires Python 3.11 or newer. Nothing to install beyond that.

```bash
git clone <this repo> && cd canarykit
cp canarykit.example.toml canarykit.toml     # edit: target, border, fault commands, sources
                                              # (or start from examples/litellm-langfuse-pgvector.toml)
export GATEWAY_TOKEN=...                      # whatever your config references

python -m canarykit all --dry-run             # sends nothing, runs no fault commands; shows them and
                                              # does a read-only scan to confirm sources are reachable
python -m canarykit all                       # the real run; asks before each fault command
echo $?                                       # 0 pass, 1 fail, 3 inconclusive
```

The report lands in `runs/<run-id>/report.md`, with machine-readable detail in `summary.json` and `scan.json`. Add `--redact` (to `all` or `report`) for a copy you can share outside the team: it leaves out file paths, URLs, internal hostnames and your fault commands, and keeps public API hostnames.

If you'd rather control each step, or can't let a script touch your deployment, run them one at a time and break the model yourself:

```bash
python -m canarykit new                                  # prints the run id and the canary
python -m canarykit send  --run <id> --phase baseline
# ...take the local model down however your team does it...
python -m canarykit send  --run <id> --phase fault
# ...bring it back...
python -m canarykit scan   --run <id>
python -m canarykit report --run <id>                     # add --redact for a shareable copy
```

To gate a release or a change on it (in a pipeline that can reach staging), run `python -m canarykit all --yes --redact` and fail the job on a non-zero exit. `--yes` skips the confirmation before fault commands, so use it only where those commands are reviewed like code.

## Two ways to plant the customer

- **Direct**: the identifiers go straight into the prompt. Fast, and it tests the gateway, logging, tracing and failover path.
- **Seeded**: load `runs/<run-id>/seed_record.json` into your test system of record, then prompt by name only. This also tests retrieval and tool calls, which is where identifiers often enter a prompt without anyone typing them.

## Before you run it

- **Use staging.** canarykit refuses an environment named `prod`, `production` or `live` unless you pass a deliberately awkward flag.
- **Tell your security operations team.** A canary moving through logs may trip DLP or SIEM rules. That's a useful test, just not as a surprise. The `CNRY-` prefix makes the values easy to recognize and allow-list.
- **Give it read-only credentials** for every source. canarykit never writes to your stores, but least privilege is the point.
- **Point it at the real entry point.** Sending requests straight to the model skips the gateway, which is where failover decisions get made.
- **Record who answered.** Set `record_fields` and `record_headers` so the report can tell your local model from a fallback. Many gateways can return the serving backend in a response header; LiteLLM sends `x-litellm-model-api-base`.
- **Say which cloud endpoints are allowed.** If an in-region cloud fallback is part of your design, list it in `[border] allowed_destinations` so the report separates it from traffic that left the border. See `docs/enterprise-stacks.md` for why a hostname alone doesn't always prove where processing happens.

## What it can and can't see

canarykit only knows what you point it at. A clean result means *clean in the sources you listed*.

- **Egress without TLS inspection** shows where requests went (proxy, flow and DNS logs), not what they carried. With inspection, canary hits in egress logs show the content left too.
- **The fallback provider's side** is invisible: their retention, monitoring logs and backups. The harness can show your data reached them, and their data-processing terms tell you the rest.
- **Embeddings**: finding no canary in a vector store doesn't mean the vectors carry no personal data.
- **Timing**: it's one run of one configuration. A hung or overloaded model usually fails over after a timeout rather than instantly. Test that too (see `docs/fault-injection.md`).

This is an engineering test that produces evidence. It isn't a compliance assessment or legal advice.

## Files

| Path | What it is |
|---|---|
| `canarykit.example.toml` | Annotated config to copy |
| `examples/litellm-langfuse-pgvector.toml` | Complete config for LiteLLM, Langfuse, pgvector, Docker and a forward proxy |
| `docs/enterprise-stacks.md` | Recipes for Kubernetes, log platforms, vector stores, egress, and in-region cloud fallback |
| `docs/fault-injection.md` | Safe ways to take a local model away, and how to restore it |
| `docs/where-to-look.md` | Checklist of stores that tend to keep copies |
| `docs/sample-report.md` | What a report looks like, from a mock stack that fails over to a public API |
| `SECURITY.md` | What canarykit runs, reads, sends and stores, and how secrets are handled |
| `canarykit/` | About 1,100 lines of standard-library Python |
| `tests/` | `python -m unittest discover -s tests` (runs in CI on Python 3.11 to 3.13) |

## Design choices you can check

- No third-party dependencies, no telemetry, nothing that calls home. The only network traffic is to the target and the sources you configure.
- Secrets come from environment variables, never the config file. They're substituted into headers and URLs only; `command` strings are expanded by the shell, so a secret is never spliced into a command line.
- Credentials aren't sent over plain `http://` (except to localhost), and redirects aren't followed, so a token can't be forwarded to another host.
- Search results record locations and which pattern matched, never the matching content. Error messages are reduced to ones canarykit wrote; command stderr is shown on your terminal but not saved.
- Run files are created readable by you only, since they name internal hosts and paths.
- Fault commands are yours. The harness shows them, asks, logs when they ran, always attempts the restore command (even after an error or Ctrl-C), and tells you if it failed.

## License

Apache License 2.0. See `LICENSE`.
