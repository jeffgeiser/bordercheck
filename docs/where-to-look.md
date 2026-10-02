# Where copies of a prompt tend to end up

Add a `[[sources]]` entry for each one that applies. Anything you leave out is reported as not checked. For each, set `location` to where the store physically sits, not where the team that owns it sits.

## Logs and control plane (`layer = "logs"`)

- AI gateway request and response logs, including debug logging someone turned on once
- Application logs from every service on the path (chat service, agent runtime, tool services)
- Container and node logs collected by your log shipper, and the platform they ship to
- LLM tracing and observability tools: query store *and* raw event storage, which is often a separate bucket
- APM and error tracking (exceptions often capture request bodies)
- Message queues and dead-letter queues between services
- Analytics or evaluation exports, and feedback ("thumbs up/down") stores
- Egress proxy, firewall, flow and DNS logs. Mark these `egress = true`.

## Model state (`layer = "model_state"`)

- Semantic and prompt caches
- Vector stores: chunk text and metadata, not just the vectors
- KV-cache offload or prefix-cache storage, if your serving stack spills to disk or remote memory
- Agent memory and conversation history stores

## Processing (`layer = "processing"`)

- Fallback and secondary model endpoints, especially public APIs and other regions. You usually can't scan these; egress evidence is how they show up.
- Batch or async processing jobs that pick up requests later
- Guardrail, moderation or PII-detection services, if they're external

## Data (`layer = "data"`)

- The test system of record, if you used seeded mode. Expected to hold the customer; useful as a positive control that scanning works.
- Data lake or warehouse tables fed from any of the above

## Tips

- Start with one positive control: a source you *know* will contain the canary. If the report doesn't find it there, fix the source before trusting any clean result.
- Set `scan_delay_seconds` so log shippers and tracing exporters have flushed before the scan.
- Keep `command` sources narrow (a time window or a prefix) so you aren't streaming a whole archive.
