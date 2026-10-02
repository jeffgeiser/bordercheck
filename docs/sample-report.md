<!-- Sample output from a mock stack: a gateway that fails over to a public API when the local model is stopped. -->
# canarykit report: run-20261001-193431-70fd

- Environment: **staging**
- Border: **Germany** (allowed locations: DE)
- Canary: `CNRY-P6JX-9S2J` · synthetic account `99126649441576`
- Run created: 2026-10-01 19:34:31

## Summary

- The synthetic customer's identifiers were found in **3 place(s)**, **1 outside the border**: App logs (DE); Tracing event store (DE); Fallback provider (simulated) (US).
- Baseline: 5 of 5 requests answered.
- During the fault, **5 of 5** requests were still answered.
  - They were served by something different from the baseline: `model=gpt-4o-mini, x-backend=gpt-4o-mini` (5). Confirm where that backend runs.
- The canary came back in **5** model responses: identifiers reached the model unredacted.
- Egress evidence shows traffic to watched public model APIs: Egress proxy: api.openai.com.

## By residency layer

| Layer | Source | Location | Inside border | Identifier hits | Patterns |
|---|---|---|---|---|---|
| Where the data lives | **not checked** (no source configured) | | | | |
| Where it's processed | Fallback provider (simulated) | US | **no** | 10 | account number, canary |
| Where model state lives (caches, embeddings, KV offload) | Vector store export | DE | yes | 0 | - |
| Where logs and the control plane live | App logs | DE | yes | 10 | account number, canary |
| Where logs and the control plane live | Tracing event store | DE | yes | 5 | canary (base64 #2) |
| Where logs and the control plane live | Gateway logs | DE | yes | 0 | - |
| Where logs and the control plane live | Egress proxy | DE | yes | 0 | - |

## Requests by phase

| Phase | Sent | Answered | Median s | Served by | Errors | Canary echoed |
|---|---|---|---|---|---|---|
| baseline | 5 | 5 | 0.001 | model=local-qwen, x-backend=local-qwen (5) | - | 5 |
| fault | 5 | 5 | 0.001 | model=gpt-4o-mini, x-backend=gpt-4o-mini (5) | - | 0 |

## Egress evidence

- **Egress proxy**: api.openai.com (10)

Compare timestamps in these logs with the run timeline below to tie traffic to the fault phase.

## Locations of hits

- **App logs** (DE, logs): /var/log/example/app_logs/app.log
- **Tracing event store** (DE, logs): command output
- **Fallback provider (simulated)** (US, processing): /var/log/example/us_provider/seen.log

Full file, line and offset detail is in `scan.json`. Contents are never copied.

## Coverage check

Each source should at least show the harness's request ids if it sits on the request path.

| Source | Targets scanned | Saw request ids | Saw identifiers | Reading |
|---|---|---|---|---|
| App logs | 1 | yes | yes | holds the customer's identifiers |
| Tracing event store | 1 | yes | yes | holds the customer's identifiers |
| Gateway logs | 1 | yes | no | saw the requests but not the identifiers: redacted, hashed or not stored here |
| Vector store export | 0 | no | no | nothing to scan (empty), so this source was not really checked |
| Fallback provider (simulated) | 1 | no | yes | holds the customer's identifiers |
| Egress proxy | 1 | no | no | egress source (request ids usually aren't visible here) |

## Run timeline

- 2026-10-01 19:34:31: run created
- 2026-10-01 19:34:31: baseline phase started
- 2026-10-01 19:34:31: baseline phase finished
- 2026-10-01 19:34:31: fault start (touch /var/log/example/fault)
- 2026-10-01 19:34:31: fault phase started
- 2026-10-01 19:34:31: fault phase finished
- 2026-10-01 19:34:31: fault stop (rm -f /var/log/example/fault)
- 2026-10-01 19:34:31: scan finished

## Not covered by this run

- What the fallback provider keeps on its side (retention, abuse-monitoring logs, backups). Check their data-processing terms; this harness can only show that data reached them.
- Payload contents on encrypted links you don't inspect. Without TLS inspection, egress evidence shows where requests went, not what they carried.
- Stores you didn't list as sources. A clean result covers only what was scanned.
- Backups, snapshots and replicas made after this run.
- Whether embeddings can be inverted back to text. Finding no canary in a vector store doesn't mean the vectors carry no personal data.

*This is an engineering test, not a compliance assessment or legal advice. One run, one configuration, synthetic data.*
