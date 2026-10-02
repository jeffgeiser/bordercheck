# bordercheck

A test harness that checks whether data in your AI stack stays inside the border you drew for it. It sends a synthetic customer through your real entry point (usually an AI gateway such as LiteLLM), triggers the gateway's fallbacks (with the local model taken away, and with it healthy but given a prompt too long for it or a burst of requests), then searches your logs, traces, caches, vector stores and egress records for that customer. The output is a report organized by residency layer, with a pass, fail or inconclusive verdict and an exit code you can gate on, a one-page summary for non-engineers, and an evidence bundle you can hand to an auditor.

Residency is usually argued from architecture diagrams and config: where the GPUs are, which region a deployment is pinned to. bordercheck tests behavior instead. In our lab, with the model in Frankfurt, the customer's data still turned up in stores nobody had listed, and in a public API in the US once the local model failed over. No request returned an error.

Standard-library Python 3.11+, no dependencies, read-only against everything it scans.

## What counts as a border

Whatever line your data has to stay inside. A country is the common case, but bordercheck only compares labels: you tag each source with a `location`, list the labels that are inside in `[border] allowed_locations`, and anything else is outside. So the border can be:

| Border | `allowed_locations` | Typical driver |
|---|---|---|
| A country | `["DE"]` | National residency rules, a regulator's expectations |
| A bloc | `["EU"]` or `["DE", "FR", "NL", "IE"]` | GDPR transfers outside the EEA |
| A cloud region | `["eu-central-1"]` | A contract or data-processing agreement that names the region |
| Your own infrastructure | `["ONPREM"]` | "No customer data goes to any third-party model", wherever it runs |
| A regulated zone | `["PCI-ZONE"]` or `["CLIENT-A"]` | A cardholder-data segment, or one client's dedicated environment |

Public model API hostnames are always watched in egress evidence and in the gateway's served-by headers. `allowed_destinations` lists the ones that count as inside, such as an approved in-region cloud endpoint.

## How it works

```
 new ──> baseline ──> probes ──> fault start ──> fault ──> fault stop ──> scan ──> report
  │         │           │             │                                  │          │
  │         │           │             └─ your own commands, shown and    │          ├─ report.md, summary.json
  │         │           │                confirmed before they run       │          ├─ summary.html (one page)
  │         │           └─ model healthy: a prompt longer than its       │          └─ manifest.json (SHA-256)
  │         │              context, a burst past its rate limit          │
  │         └─ records who answered each request (status, timing,        └─ read-only search of every
  │            served-by headers); bodies are never stored                  source, over the run's window
  └─ synthetic customer: canary, account number, email, phone, IBAN
```

Later: `rescan` (has it expired?), `diff` (what changed since last time?), `evidence` and `verify` (a hashed bundle for an auditor).

**The synthetic customer.** A canary (`CNRY-XXXX-XXXX`) and a 14-digit account number that exist nowhere else, plus an email, phone number and IBAN in real formats, so the report shows which formats your redaction catches. Each is reserved or impossible: the email is at `example.com` (RFC 2606), the phone number is in Frankfurt's 069 90009 range, which the Bundesnetzagentur keeps unassigned, and the IBAN has a valid checksum but a bank code starting with 9, which no German bank code does.

**What it searches for.** The canary exactly and lowercased, its base64 encoding at all three byte alignments (so it's found inside base64-encoded JSON, as tracing exporters and queues often store it), the account number plain and space-grouped, the email plain and URL-encoded, the phone in international and national forms, the IBAN compact and grouped, and the harness's own request ids. Request ids go somewhere your stack logs them but away from the identifiers (the OpenAI `user` field works well), which is how the report tells "this store saw the request but redacted the customer" from "this store isn't on the request path."

**What it records.** For each hit: source, file or URL, line and byte offset, and which pattern matched. Never the matching content.

**Failover with nothing down.** An outage isn't the only way a gateway reaches for a cloud model. LiteLLM, for example, has `context_window_fallbacks` for prompts the local model can't take, `fallbacks` on rate limits, and `content_policy_fallbacks` when a model or guardrail refuses. The `[probes]` section sends a prompt padded past the local context window, a concurrent burst, and optionally a prompt your guardrail rejects, all with the local model healthy. If the gateway's own response headers (such as `x-litellm-model-api-base`) name a public API, that phase fails.

**Scanning the run, not "the last two hours".** Source commands and URLs can use `{{run_started}}`, `{{run_ended}}`, `{{run_minutes}}` and `{{run_id}}`, so `kubectl logs --since-time={{run_started}}` or Langfuse's `fromTimestamp={{run_started}}` cover exactly the run. An http URL with `{{page}}` is fetched page by page until the API reports the last page, so a busy tracing project can't push the run's traces off the first page and make them look clean.

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
| **fail** | 1 | Identifiers were found outside the border, egress logs show traffic to a disallowed model API, or the gateway's served-by fields say a disallowed public API answered (in the fault or any probe). A found leak stands regardless of anything else |
| **inconclusive** | 3 | Nothing crossed the border in what was scanned, but the evidence is incomplete: no positive control, a positive control that found nothing, a source with errors, or a different backend answered (in the fault or a probe) that neither the served-by fields nor an egress source can place |

Config errors exit 2. The reasons are listed at the top of `report.md` and in `summary.json`.

**Positive control.** Mark one source you know stores prompts with `positive_control = true` (with seeded mode, the system of record you loaded the customer into). If it doesn't find the customer, the scan itself is broken: a wrong time window, a missing permission, a log shipper that hasn't flushed. A clean result without a working positive control can't be told apart from a broken scan, so it's never a pass.

## Evidence, retention and drift

| Command | What it gives you |
|---|---|
| `report` | Also writes `summary.html`, a one-page summary (verdict, a grid of the four layers, who answered under each condition, which identifier formats each store kept). Self-contained, no scripts, prints to one PDF page. `[report] regulatory_appendix = true` adds the regulations the evidence is relevant to (DORA Art. 28/30, GDPR Chapter V, EBA outsourcing guidelines, AI Act Art. 12) |
| `evidence --run <id>` | A zip of the run folder with `manifest.json`: SHA-256 of every file, the bordercheck and Python versions, and the config's hash. Prints the zip's own hash to record in a change or audit ticket, or sign |
| `verify <zip>` | Rechecks every file in a bundle against its manifest. Exit 1 on any mismatch |
| `diff --run <new> --against <old>` | What changed: verdict, places holding the customer, egress destinations, who answered, and stores that now keep an identifier format they used to mask. Exit 1 on a regression, so a scheduled run can alert |
| `rescan --run <id>` | Scans again, days later, over the original run's window, and shows which stores still hold the customer. `--expect-gone` exits 1 if any do: a direct test of your retention settings |

A manifest makes changes detectable, not impossible: anyone who can rewrite the files can rewrite the manifest. Signing the bundle (`cosign sign-blob`, `gpg --detach-sign`) or storing its hash where they can't edit it is what makes it binding.

## Quick start

Requires Python 3.11 or newer. Nothing to install beyond that.

```bash
git clone <this repo> && cd bordercheck
cp bordercheck.example.toml bordercheck.toml     # edit: target, border, fault commands, sources
                                              # (or start from examples/litellm-langfuse-pgvector.toml)
export GATEWAY_TOKEN=...                      # whatever your config references

python -m bordercheck all --dry-run             # sends nothing, runs no fault commands; shows them and
                                              # does a read-only scan to confirm sources are reachable
python -m bordercheck all                       # the real run; asks before each fault command
echo $?                                       # 0 pass, 1 fail, 3 inconclusive
```

The report lands in `runs/<run-id>/report.md`, with machine-readable detail in `summary.json` and `scan.json`. Add `--redact` (to `all` or `report`) for a copy you can share outside the team: it leaves out file paths, URLs, internal hostnames and your fault commands, and keeps public API hostnames.

If you'd rather control each step, or can't let a script touch your deployment, run them one at a time and break the model yourself:

```bash
python -m bordercheck new                                  # prints the run id and the canary
python -m bordercheck send  --run <id> --phase baseline
python -m bordercheck probe --run <id>                     # optional: the [probes] you configured
# ...take the local model down however your team does it...
python -m bordercheck send  --run <id> --phase fault
# ...bring it back...
python -m bordercheck scan   --run <id>
python -m bordercheck report --run <id>                     # add --redact for a shareable copy
```

To gate a release or a change on it (in a pipeline that can reach staging), run `python -m bordercheck all --yes --redact` and fail the job on a non-zero exit. `--yes` skips the confirmation before fault commands, so use it only where those commands are reviewed like code.

## Two ways to plant the customer

- **Direct**: the identifiers go straight into the prompt. Fast, and it tests the gateway, logging, tracing and failover path.
- **Seeded**: load `runs/<run-id>/seed_record.json` into your test system of record, then prompt by name only. This also tests retrieval and tool calls, which is where identifiers often enter a prompt without anyone typing them.

## Before you run it

- **Use staging.** bordercheck refuses an environment named `prod`, `production` or `live` unless you pass a deliberately awkward flag.
- **Tell your security operations team.** A canary moving through logs may trip DLP or SIEM rules. That's a useful test, just not as a surprise. The `CNRY-` prefix makes the values easy to recognize and allow-list.
- **Give it read-only credentials** for every source. bordercheck never writes to your stores, but least privilege is the point.
- **Point it at the real entry point.** Sending requests straight to the model skips the gateway, which is where failover decisions get made.
- **Record who answered.** Set `record_fields` and `record_headers` so the report can tell your local model from a fallback. Many gateways can return the serving backend in a response header; LiteLLM sends `x-litellm-model-api-base`.
- **Say which cloud endpoints are allowed.** If an in-region cloud fallback is part of your design, list it in `[border] allowed_destinations` so the report separates it from traffic that left the border. See `docs/enterprise-stacks.md` for why a hostname alone doesn't always prove where processing happens.

## What it can and can't see

bordercheck only knows what you point it at. A clean result means *clean in the sources you listed*.

- **Egress without TLS inspection** shows where requests went (proxy, flow and DNS logs), not what they carried. With inspection, canary hits in egress logs show the content left too.
- **The fallback provider's side** is invisible: their retention, monitoring logs and backups. The harness can show your data reached them, and their data-processing terms tell you the rest.
- **Embeddings**: finding no canary in a vector store doesn't mean the vectors carry no personal data.
- **Load**: the rate-limit probe sends a concurrent burst. Tell whoever shares the staging environment, or leave `[probes.rate_limit]` out.
- **Timing**: it's one run of one configuration. A hung or overloaded model usually fails over after a timeout rather than instantly. Test that too (see `docs/fault-injection.md`).

This is an engineering test that produces evidence. It isn't a compliance assessment or legal advice.

## Files

| Path | What it is |
|---|---|
| `bordercheck.example.toml` | Annotated config to copy |
| `examples/litellm-langfuse-pgvector.toml` | Complete config for LiteLLM, Langfuse, pgvector, Docker and a forward proxy |
| `docs/enterprise-stacks.md` | Recipes for Kubernetes, log platforms, vector stores, egress, and in-region cloud fallback |
| `docs/fault-injection.md` | Safe ways to take a local model away, and how to restore it |
| `docs/where-to-look.md` | Checklist of stores that tend to keep copies |
| `docs/sample-report.md` | What a report looks like, from a mock stack that fails over to a public API |
| `SECURITY.md` | What bordercheck runs, reads, sends and stores, and how secrets are handled |
| `bordercheck/` | About 1,800 lines of standard-library Python |
| `tests/` | `python -m unittest discover -s tests` (runs in CI on Python 3.11 to 3.13) |

## Design choices you can check

- No third-party dependencies, no telemetry, nothing that calls home. The only network traffic is to the target and the sources you configure.
- Secrets come from environment variables, never the config file. They're substituted into headers and URLs only; `command` strings are expanded by the shell, so a secret is never spliced into a command line.
- Credentials aren't sent over plain `http://` (except to localhost), and redirects aren't followed, so a token can't be forwarded to another host.
- Search results record locations and which pattern matched, never the matching content. Error messages are reduced to ones bordercheck wrote; command stderr is shown on your terminal but not saved.
- Run files are created readable by you only, since they name internal hosts and paths.
- Fault commands are yours. The harness shows them, asks, logs when they ran, always attempts the restore command (even after an error or Ctrl-C), and tells you if it failed.

## License

Apache License 2.0. See `LICENSE`.
