# Taking the local model away (and bringing it back)

canarykit never decides how to break your stack. You put a `start` and `stop` command in `[fault]`, or you do it by hand between `send` phases. Pick the option closest to how a real outage would look, and agree it with whoever owns the environment.

Test at least two failure shapes. They exercise different paths in most gateways.

## 1. Hard down: the model is gone

The gateway gets connection refused or 5xx immediately. This is the fastest failover path.

```toml
# Kubernetes
start = "kubectl -n ai-staging scale deployment/local-llm --replicas=0"
stop  = "kubectl -n ai-staging scale deployment/local-llm --replicas=1"

# Docker (or `docker compose stop vllm` / `docker compose start vllm` from the compose directory)
start = "docker stop local-llm"
stop  = "docker start local-llm"

# systemd
start = "sudo systemctl stop vllm"
stop  = "sudo systemctl start vllm"
```

## 2. Hung: the model is there but doesn't answer

This is closer to an overloaded model. Failover happens only after the gateway's timeout, so set the harness's `timeout_seconds` above that.

```toml
# Docker: freeze the process; connections open, nothing comes back
start = "docker pause local-llm"
stop  = "docker unpause local-llm"

# Linux host: delays ALL outbound traffic on that interface, including your SSH session if you
# run it remotely. Only on a dedicated model host; needs root. Check the interface name with `ip link`.
start = "sudo tc qdisc add dev eth0 root netem delay 30000ms"
stop  = "sudo tc qdisc del dev eth0 root"
```

## 3. Blocked: the network path is cut

Useful when you can't touch the model itself. A NetworkPolicy only takes effect if your CNI enforces it (Calico, Cilium and most managed clusters do; plain flannel doesn't), and some CNIs leave connections that are already open alone. Confirm the gateway really loses the model before trusting the fault phase: the baseline and fault "served by" columns should differ, or the fault phase should fail.

```toml
# Kubernetes NetworkPolicy that denies ingress to the model pods (prepare the YAML first)
start = "kubectl -n ai-staging apply -f deny-local-llm.yaml"
stop  = "kubectl -n ai-staging delete -f deny-local-llm.yaml"
```

## 4. Nothing down: the gateway's other fallbacks

Gateways also fail over when the local model is fine. These don't need a fault command; configure them under `[probes]` and they run after the baseline:

- **Context window**: `[probes.context_window]` pads the prompt past `pad_tokens`. Set it above the local model's limit (vLLM's `--max-model-len`). LiteLLM routes these to `context_window_fallbacks`.
- **Rate limit**: `[probes.rate_limit]` sends `requests` with `concurrency` in flight. LiteLLM falls back on rate-limit errors through `fallbacks`, and its router will also spread load onto any cloud deployment that shares the local model's model group.
- **Content policy**: `[probes.content_policy]` sends a prompt you supply that your local model or guardrail refuses. LiteLLM routes those to `content_policy_fallbacks`.

A probe that ends in errors failed closed. One that's answered by a public API is a fail, with the phase named in the verdict.

## Rules of thumb

- Run `python -m canarykit all --dry-run` first. It sends no requests and runs no fault commands, prints every command, and checks that each source is reachable. That check does run your `command` sources, since that's the only way to know they work.
- Make sure `stop` really restores service. Run it once by hand before the test.
- Set `settle_seconds` long enough for the change to take effect (scale-down, health checks, gateway retries).
- `all` runs your `stop` command even if the fault phase fails or you press Ctrl-C (it still asks first, unless you passed `--yes`). If that doesn't complete, it prints `python -m canarykit fault stop --run <id>` to run by hand.
- After the run, confirm the model is healthy and the gateway has gone back to it. Some gateways keep a backend in cooldown for a while after it fails.
