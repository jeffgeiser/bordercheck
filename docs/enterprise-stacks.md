# Pointing bordercheck at a typical enterprise AI stack

Most private-GPU deployments in regulated companies look roughly like this:

```
apps / agents ──> AI gateway ──> local model (vLLM, NVIDIA NIM, TGI, KServe, Triton)
 (RAG, tools)     (LiteLLM,   └─> fallback: cloud model API, in region or not
                   Kong, APIM)
      │               │
      ├─ vector store (pgvector, OpenSearch/Elastic, Qdrant, Milvus)
      ├─ caches (Redis semantic/prompt cache, KV-cache offload)
      └─ telemetry: LLM tracing (Langfuse, Arize, Datadog LLM Observability), OpenTelemetry
         collectors, log platform (Splunk, Elastic, Loki), SIEM, egress proxy (Squid, Zscaler)
```

`examples/litellm-langfuse-pgvector.toml` is a complete config for the Docker version of this. The recipes below cover the Kubernetes and log-platform versions. Each is a `[[sources]]` entry; set `location` to where the store physically runs.

## The questions a residency review will ask

| Question | What answers it in bordercheck |
|---|---|
| Does any request leave the border when the local model fails? | `[fault]` plus `record_headers` (who answered) plus an `egress = true` source (where traffic went) |
| Does any request leave the border with nothing down? | `[probes]`: a prompt past the local context window, a burst past the rate limit, a prompt a guardrail refuses |
| Does redaction catch real identifier formats? | The "which identifier formats each store kept" table: email, phone and IBAN next to the canary |
| Do copies expire as the retention policy says? | `rescan --run <id> --expect-gone`, days later |
| Has anything changed since the last approved run? | `diff --run <new> --against <old>`, exit 1 on a regression |
| What do we hand the auditor? | `evidence --run <id>`: the run, a SHA-256 manifest and the config hash, in one zip; `verify` rechecks it |
| Is a cloud fallback inside the border? | `[border] allowed_destinations` (see below), checked against egress evidence |
| Which stores keep a copy of the customer's data? | One source per store; the report lists every hit by residency layer |
| Is redaction actually working? | The coverage check: a store that saw the request ids but not the identifiers |
| What wasn't checked? | Layers with no source are listed as **not checked**, never as clean |

## In-region cloud fallback

Failing over to a cloud model in the same region can be an approved design. List those endpoints so the report doesn't count them as leaving the border:

```toml
[border]
name = "Germany"
allowed_locations = ["DE"]
allowed_destinations = ["bedrock-runtime.eu-central-1.amazonaws.com", "europe-west3-aiplatform.googleapis.com"]
```

The hostname shows where the request was sent. It doesn't always show where it was processed:

- **AWS Bedrock** cross-region inference profiles (model ids starting `eu.` or `us.`) are called on a regional endpoint but can be served from other regions in that geography. Record the model id (`record_fields = ["model"]`) and check which profile your gateway uses.
- **Azure OpenAI** hostnames (`<resource>.openai.azure.com`) don't name a region. The deployment type does: *Global* deployments can process anywhere, *Data Zone* within the EU or US, *Standard* in the resource's region. List a resource in `allowed_destinations` only if its deployment type keeps processing in the border.
- **Google Vertex AI** regional endpoints (`<region>-aiplatform.googleapis.com`) name the region; the global endpoint (`aiplatform.googleapis.com`) doesn't.

## Gateways

**LiteLLM proxy.** Every response carries `x-litellm-model-api-base` (the backend that answered), `x-litellm-model-id` and `x-litellm-attempted-fallbacks`; put them in `record_headers`. LiteLLM also keeps its own copies in Postgres: `LiteLLM_SpendLogs` (`messages`, `response`, `proxy_server_request`, when `store_prompts_in_spend_logs` is on) and `LiteLLM_ErrorLogs` (`request_kwargs` of every failed call, which is where the local model's failed attempts land during the fault). The example config has queries for both. `litellm_settings.turn_off_message_logging` hides prompts from logging callbacks such as Langfuse; the coverage check shows whether it worked.

LiteLLM's fallbacks aren't only for outages. `context_window_fallbacks` catches prompts too long for the local model, `fallbacks` catches rate-limit errors, `content_policy_fallbacks` catches refusals, and a model group that contains both a local and a cloud deployment is load-balanced across them with no error at all. The `[probes]` section exercises the first three; for the fourth, compare the baseline's served-by column across a few runs.

**Other gateways** (Kong AI Gateway, Azure API Management, Apigee, Portkey, cloud-provider gateways): look for a response header or body field that names the backend, and for request or body logging in their diagnostic settings, which usually ships to a log platform covered below.

## Kubernetes

```toml
# All pods behind a label. kubectl's default with -l is the last 10 lines per pod: --tail=-1 matters.
[[sources]]
name = "Gateway pods"
type = "command"
command = "kubectl -n ai logs -l app.kubernetes.io/name=litellm --all-containers --since=3h --tail=-1 --max-log-requests=50"
layer = "logs"
location = "DE"

# Model server logs. Depending on version and flags, vLLM's request logging prints prompts.
[[sources]]
name = "Model server pods"
type = "command"
command = "kubectl -n ai logs -l app=vllm --all-containers --since=3h --tail=-1 --max-log-requests=50"
layer = "processing"
location = "DE"
```

Fault commands for Kubernetes are in `fault-injection.md`. If an HPA or operator manages the model deployment, scaling to zero may be undone within seconds; pause the operator or use a NetworkPolicy instead.

## Scheduled runs

Running bordercheck on a schedule against staging turns a one-off test into a control:

```bash
python -m bordercheck all --yes --redact; rc=$?
latest=$(basename "$(ls -d runs/run-*/ | tail -1)")
python -m bordercheck diff --run "$latest" --against "$APPROVED_RUN" || echo "residency regression" >&2   # or page someone
python -m bordercheck evidence --run "$latest"
exit $rc
```

`--yes` skips confirmation before fault commands, so use it only where those commands are reviewed like code. A week or a month later, `rescan --expect-gone` on the same run checks that copies expired.

## Log platforms and SIEM

You can't put the run's canary in a static config, but every canary starts with `CNRY`, so search for that and let bordercheck pick out this run. Note that a store which masks the canary but keeps the account number will be missed by a `CNRY` search; add a second search for the account number's `99` prefix if your platform supports wildcards.

```toml
# Splunk: the export endpoint streams results. Credentials from a netrc file, not the command line.
[[sources]]
name = "Splunk (ai indexes)"
type = "command"
command = "curl -sS --fail --netrc-file ~/.netrc-splunk https://splunk.example.internal:8089/services/search/jobs/export --data-urlencode 'search=search index=ai* earliest=-3h CNRY' -d output_mode=raw"
layer = "logs"
location = "DE"

# Elasticsearch / OpenSearch: the standard analyzer splits CNRY-XXXX-XXXX on hyphens.
[[sources]]
name = "Elastic (logs-*)"
type = "http"
url = "https://elastic.example.internal:9200/logs-*/_search?q=CNRY&size=1000"
headers = { Authorization = "ApiKey ${ELASTIC_API_KEY}" }
layer = "logs"
location = "DE"
```

An OpenTelemetry collector with a `file` exporter, or the `debug` exporter at `detailed` verbosity, writes span attributes (including `gen_ai.*` prompt attributes, if your instrumentation records them) to disk or stdout; scan those files or the collector's logs too.

## Vector stores

- **pgvector**: see the example config. Use `concat_ws`, not `||`, or a NULL column hides the row.
- **OpenSearch / Elasticsearch** vector indexes: the same `_search?q=CNRY` recipe against the index.
- **Qdrant, Milvus, Weaviate**: their scroll or query APIs need a POST body, so use a `command` source with `curl`, and give it the API key from a curl config file (`curl -K`) rather than a `-H` argument.

Finding no canary in chunk text or metadata doesn't mean the vectors carry no personal data. The report says so.

## Egress evidence

- **Squid** and most forward proxies log `CONNECT host:443`: a `path` source with `egress = true` is enough.
- **Zscaler, Netskope, Palo Alto**: their logs usually reach your SIEM; search there for the watched hostnames instead of `CNRY`, with `egress = true`.
- **VPC or NSG flow logs** show IP addresses, not hostnames. Pair them with DNS query logs (Route 53 Resolver, Azure DNS, Cloud DNS), which do.
- With TLS inspection, canary hits in egress logs show the content left too. Without it, egress shows the destination only.
