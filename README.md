# canarykit

Follow a synthetic customer through your AI stack and find out where their data actually lands, including what happens when your in-country model goes down.

Most residency conversations stop at where the GPU sits. In our lab, the model sat in Germany and the customer's data still turned up in three places we hadn't planned for, plus a public API in the US once the local model failed over. Nobody got an error. canarykit lets you run the same test against your own architecture, in an afternoon, with no third-party dependencies to review.

## What it does

1. **Creates a synthetic customer** with a canary (`CNRY-XXXX-XXXX`) and an account number that exist nowhere else.
2. **Sends requests through your normal entry point**, usually your AI gateway, and records who answered each one: status, timing, and the response fields or headers that identify the backend. Response bodies aren't stored.
3. **Takes your local model away** using commands *you* write, after showing them and asking first, then sends the same requests again.
4. **Searches the stores you list**, read-only: logs, tracing, caches, vector stores, object storage, egress logs. It looks for the canary (including base64-encoded copies), the account number and its own request ids.
5. **Writes a report** organized by the four places residency can break: where the data lives, where it's processed, where model state lives, and where logs and the control plane live.

The report answers questions like these:

- Did requests get answered during the outage, and by whom?
- Which stores kept the customer's identifiers, and which of those are outside the border?
- Did egress logs show traffic to public model APIs?
- Which stores saw the requests but not the identifiers? That suggests redaction is working there.
- Which layers didn't you check at all? Those are listed as **not checked**, never as clean.

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
| `canarykit/` | About 1,000 lines of standard-library Python |
| `tests/` | `python -m unittest discover -s tests` (runs in CI on Python 3.11 to 3.13) |

## Design choices you can check

- No third-party dependencies, no telemetry, nothing that calls home. The only network traffic is to the target and the sources you configure.
- Secrets come from environment variables, never the config file. They're substituted into headers and URLs only; `command` strings are expanded by the shell, so a secret is never spliced into a command line.
- Credentials aren't sent over plain `http://` (except to localhost), and redirects aren't followed, so a token can't be forwarded to another host.
- Search results record locations and which pattern matched, never the matching content. Error messages are reduced to ones canarykit wrote; command stderr is shown on your terminal but not saved.
- Run files are created readable by you only, since they name internal hosts and paths.
- Fault commands are yours. The harness shows them, asks, logs when they ran, and tells you if the restore command failed.
