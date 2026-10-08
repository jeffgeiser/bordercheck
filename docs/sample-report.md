<!-- Sample output from examples/demo/demo_stack.py: a simulated stack on localhost, not a real environment. Generated with --redact. -->
# bordercheck report: run-20261008-162657-796f

- Environment: **demo**
- Border: **Germany** (allowed locations: DE)
- Canary: `CNRY-GRFD-5WFG` · synthetic account `99757609175143`
- Run created: 2026-10-08 16:26:57

## Verdict: FAIL

The synthetic customer's data crossed the border:
- identifiers found in Hosted log analytics (US), outside the border
- egress to api.openai.com, a public model API the border doesn't allow
- Long prompt (model up): the gateway reports api.openai.com answered, a public model API the border doesn't allow
- Local model down: the gateway reports api.openai.com answered, a public model API the border doesn't allow

## What we found

1. **A public model API answered with nothing down, because the prompt was too long for the local model.** The gateway reported api.openai.com for 3 of 3 requests.
2. **A public model API answered while the local model was down.** The gateway reported api.openai.com for 5 of 5 requests.
3. **Requests went to api.openai.com.** Egress logs show the destination; without TLS inspection they can't show the content.
4. **Customer data is stored outside the border.** Found in Hosted log analytics (US).
5. **The answers looked clean. The data behind them wasn't.** None of the 13 answers contained the canary or account number, but the data still left the border.
6. **Tracing events kept the full record.** Every identifier format was stored unmasked: canary, account no., email, phone and IBAN.
7. **Hosted log analytics masked some identifiers but not others.** Masked: email. Kept: canary, account no., phone and IBAN.
8. **Semantic cache kept the full record.** Every identifier format was stored unmasked: canary, account no., email, phone and IBAN.
9. **Some residency layers weren't checked.** No source covers where the data lives.
10. **Gateway logs saw the requests but kept no identifiers.** Redaction, hashing or minimal logging is working there.

## Summary

- The synthetic customer's identifiers were found in **3 place(s)**, **1 outside the border**: Tracing events (DE); Hosted log analytics (US); Semantic cache (DE).
- **Traffic left the border** to public model APIs: api.openai.com (egress evidence, below). Without TLS inspection this shows the destination, not the payload; the served-by fields show which phase was answered from there.
- Baseline: 5 of 5 requests answered.
- Context-window probe (prompt longer than the local model takes), with nothing down: **3 of 3** answered.
  - Answered by **api.openai.com**, according to the served-by fields.
- During the fault, **5 of 5** requests were still answered.
  - Answered by **api.openai.com**, according to the served-by fields.

## By residency layer

| Layer | Source | Location | Inside border | Identifier hits | Patterns |
|---|---|---|---|---|---|
| Where the data lives | **not checked** (no source configured) | | | | |
| Where it's processed | **not checked** (no source configured) | | | | |
| Where model state lives (caches, embeddings, KV offload) | Semantic cache | DE | yes | 65 | IBAN, account number, canary, email, phone (as written) |
| Where model state lives (caches, embeddings, KV offload) | Vector store | DE | yes | 0 | - |
| Where logs and the control plane live | Gateway logs | DE | yes | 0 | - |
| Where logs and the control plane live | Tracing events | DE | yes | 65 | IBAN (base64 #3), account number (base64 #3), canary (base64 #3), email (base64 #3), phone (base64 #3) |
| Where logs and the control plane live | Hosted log analytics | US | **no** | 52 | IBAN, account number, canary, phone (as written) |
| Where logs and the control plane live | Egress proxy | DE | yes | 0 | - |

## Requests by phase

| Phase | Sent | Answered | Median s | Served by | Errors | Canary echoed |
|---|---|---|---|---|---|---|
| baseline | 5 | 5 | 0.002 | model=qwen2.5-32b-instruct, x-litellm-model-api-base=http://(internal host) (5) | - | 0 |
| probe:context_window | 3 | 3 | 0.002 | model=gpt-4o-mini, x-litellm-model-api-base=https://api.openai.com (3) | - | 0 |
| fault | 5 | 5 | 0.002 | model=gpt-4o-mini, x-litellm-model-api-base=https://api.openai.com (5) | - | 0 |

## Which identifier formats each store kept

Stores that saw the requests. A format that's missing where others are present was masked or dropped there, which is what redaction should do.

| Source | canary | account no. | email | phone | IBAN |
|---|---|---|---|---|---|
| Gateway logs | - | - | - | - | - |
| Tracing events | kept | kept | kept | kept | kept |
| Hosted log analytics | kept | kept | - | kept | kept |
| Semantic cache | kept | kept | kept | kept | kept |

Columns are the formats the prompts sent or a store kept. The phone number comes from a reserved range of 1,000, so a match can occasionally be from an earlier run.

## Egress evidence

- **Egress proxy**: api.openai.com (8)

Compare timestamps in these logs with the run timeline below to tie traffic to a phase.

## Locations of hits

- **Tracing events** (DE, logs): paths left out
- **Hosted log analytics** (US, logs): paths left out
- **Semantic cache** (DE, model_state): paths left out

Paths and URLs are left out of this shareable copy. Full file, line and offset detail is in `scan.json`. Contents are never copied.

## Coverage check

Each source should at least show the harness's request ids if it sits on the request path.

| Source | Targets scanned | Saw request ids | Saw identifiers | Reading |
|---|---|---|---|---|
| Gateway logs | 1 | yes | no | saw the requests but not the identifiers: redacted, hashed or not stored here |
| Tracing events | 1 | yes | yes | positive control: found, as expected |
| Hosted log analytics | 1 | yes | yes | holds the customer's identifiers |
| Semantic cache | 1 | no | yes | holds the customer's identifiers |
| Vector store | 1 | no | no | saw neither: off the request path, outside the time window, or not shipping logs |
| Egress proxy | 1 | no | no | egress source (request ids usually aren't visible here) |

## Run timeline

- 2026-10-08 16:26:57: run created
- 2026-10-08 16:26:57: baseline phase started
- 2026-10-08 16:26:57: baseline phase finished
- 2026-10-08 16:26:57: probe:context_window started
- 2026-10-08 16:26:57: probe:context_window finished
- 2026-10-08 16:26:57: fault start
- 2026-10-08 16:26:57: fault phase started
- 2026-10-08 16:26:57: fault phase finished
- 2026-10-08 16:26:57: fault stop
- 2026-10-08 16:26:57: scan finished

## Not covered by this run

- What the fallback provider keeps on its side (retention, abuse-monitoring logs, backups). Check their data-processing terms; this harness can only show that data reached them.
- Payload contents on encrypted links you don't inspect. Without TLS inspection, egress evidence shows where requests went, not what they carried.
- Stores you didn't list as sources. A clean result covers only what was scanned.
- Backups, snapshots and replicas made after this run. `bordercheck rescan` checks retention later.
- Whether embeddings can be inverted back to text. Finding no canary in a vector store doesn't mean the vectors carry no personal data.

*This is an engineering test, not a compliance assessment or legal advice. One run, one configuration, synthetic data.*
