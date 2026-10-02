"""Turn run.json and scan.json into a plain report a platform team, CISO or DPO can read."""
import re
import statistics
import time
import urllib.parse
from collections import Counter

from .config import LAYERS
from .scan import MAX_HITS_PER_PATTERN, _watch_regex

LAYER_NAMES = {
    "data": "Where the data lives",
    "processing": "Where it's processed",
    "model_state": "Where model state lives (caches, embeddings, KV offload)",
    "logs": "Where logs and the control plane live",
}

NOT_COVERED = [
    "What the fallback provider keeps on its side (retention, abuse-monitoring logs, backups). "
    "Check their data-processing terms; this harness can only show that data reached them.",
    "Payload contents on encrypted links you don't inspect. Without TLS inspection, egress evidence "
    "shows where requests went, not what they carried.",
    "Stores you didn't list as sources. A clean result covers only what was scanned.",
    "Backups, snapshots and replicas made after this run.",
    "Whether embeddings can be inverted back to text. Finding no canary in a vector store "
    "doesn't mean the vectors carry no personal data.",
]


def _ts(t):
    return time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(t))


HOST_RE = re.compile(r"\b(?:[a-z0-9-]+\.)+[a-z][a-z0-9-]*(?::\d+)?|\b\d{1,3}(?:\.\d{1,3}){3}(?::\d+)?", re.I)


def _redact_hosts(value, public):
    """Replace hostnames and IPs with "(internal host)" unless they match a watched public API."""
    def repl(m):
        host = m.group(0).split(":")[0]
        return m.group(0) if any(rx.fullmatch(host.encode()) for rx in public) else "(internal host)"
    if "://" in value:
        parts = urllib.parse.urlsplit(value)
        value = f"{parts.scheme}://{parts.netloc}"
    return HOST_RE.sub(repl, value)


def _served_by(entry, public=None):
    vals = [f"{k}={v if public is None else _redact_hosts(str(v), public)}"
            for k, v in {**entry.get("fields", {}), **entry.get("headers", {})}.items() if v not in (None, "")]
    return ", ".join(vals) if vals else None


def _phase_summary(requests, public=None):
    ok = [r for r in requests if r.get("status") is not None and 200 <= r["status"] < 300]
    served = Counter(_served_by(r, public) or "(no served-by fields recorded)" for r in ok)
    errors = Counter(r.get("error") or f"HTTP {r.get('status')}" for r in requests if r not in ok)
    secs = [r["seconds"] for r in ok]
    return {
        "sent": len(requests),
        "answered": len(ok),
        "served_by": dict(served),
        "errors": dict(errors),
        "median_seconds": round(statistics.median(secs), 3) if secs else None,
        "canary_echoed": sum(1 for r in requests if r.get("canary_in_response")),
        "account_echoed": sum(1 for r in requests if r.get("account_in_response")),
    }


def build(cfg, run, scan, redact=False):
    """redact=True leaves out file paths, URLs, error text and fault commands, which name
    internal hosts and layout, so the report can be shared outside the team."""
    allowed = {loc.upper() for loc in cfg["border"]["allowed_locations"]}
    border_name = cfg["border"].get("name", "/".join(sorted(allowed)))
    phases = {}
    for r in run["requests"]:
        phases.setdefault(r["phase"], []).append(r)
    public = None
    if redact:
        public = [_watch_regex(p) for p in cfg["watch_destinations"]]
    phase_info = {p: _phase_summary(reqs, public) for p, reqs in phases.items()}

    places = []
    for s in scan:
        ident = [h for h in s["hits"] if h["kind"] in ("canary", "account")]
        if ident:
            places.append({
                "name": s["name"], "layer": s["layer"], "location": s["location"],
                "inside": s["location"].upper() in allowed,
                "hits": len(ident),
                "patterns": sorted({h["label"] for h in ident}),
                "targets": sorted({h["where"] for h in ident}),
            })
    outside = [p for p in places if not p["inside"]]
    egress = [(s, [h for h in s["hits"] if h["kind"] == "egress"]) for s in scan if s.get("egress")]
    seen_egress = [(s["name"], sorted({h['destination'] for h in hits})) for s, hits in egress if hits]
    # Destinations the border allows, such as an in-region cloud endpoint you approved as a fallback.
    approved = [_watch_regex(p) for p in cfg["border"].get("allowed_destinations", [])]
    seen_dests = {d for _, ds in seen_egress for d in ds}
    dests_ok = sorted(d for d in seen_dests if any(rx.fullmatch(d.encode()) for rx in approved))
    dests_out = sorted(seen_dests - set(dests_ok))

    L = []
    L.append(f"# canarykit report: {run['run_id']}\n")
    L.append(f"- Environment: **{run['environment']}**")
    L.append(f"- Border: **{border_name}** (allowed locations: {', '.join(sorted(allowed))})")
    L.append(f"- Canary: `{run['record']['canary']}` · synthetic account `{run['record']['account']}`")
    L.append(f"- Run created: {_ts(run['created'])}\n")

    L.append("## Summary\n")
    if places:
        L.append(f"- The synthetic customer's identifiers were found in **{len(places)} place(s)**, "
                 f"**{len(outside)} outside the border**: "
                 + "; ".join(f"{p['name']} ({p['location']})" for p in places) + ".")
    else:
        L.append("- The synthetic customer's identifiers were **not found** in any scanned source. "
                 "Check the coverage section before treating this as clean.")
    if dests_out:
        # A public API is outside any border a scanned store can show, so say it up front.
        L.append(f"- **Traffic left the border** to public model APIs: {', '.join(dests_out)} "
                 "(egress evidence, below). Without TLS inspection this shows the destination, not the payload; "
                 "the served-by change during the fault shows what was answered from there.")
    if dests_ok:
        L.append(f"- Traffic reached model APIs the border allows: {', '.join(dests_ok)} "
                 "(`allowed_destinations`). Confirm the provider's data-processing terms match.")
    base, fault = phase_info.get("baseline"), phase_info.get("fault")
    if base:
        L.append(f"- Baseline: {base['answered']} of {base['sent']} requests answered.")
    if fault:
        if fault["answered"] == 0:
            L.append(f"- During the fault, **0 of {fault['sent']}** requests were answered. The system "
                     "failed closed: the border held, and the cost was an outage. Capacity inside the "
                     "border, with a spare, is what keeps both.")
        else:
            changed = base and set(fault["served_by"]) - set(base["served_by"])
            L.append(f"- During the fault, **{fault['answered']} of {fault['sent']}** requests were still answered.")
            if changed:
                L.append("  - They were served by something different from the baseline: "
                         + "; ".join(f"`{k}` ({v})" for k, v in fault["served_by"].items())
                         + ". Confirm where that backend runs.")
            elif all(k.startswith("(no served-by") for k in fault["served_by"]):
                L.append("  - No served-by fields were recorded, so this run can't say who answered. "
                         "Add `record_fields` / `record_headers` under [target].")
            else:
                L.append("  - Served-by fields matched the baseline. If the local model was really down, "
                         "those fields may not identify the backend; check gateway logs.")
    echoed = sum(v["canary_echoed"] for v in phase_info.values())
    if echoed:
        L.append(f"- The canary came back in **{echoed}** model responses: identifiers reached the model unredacted.")
    if not egress:
        L.append("- No egress sources configured, so outbound destinations weren't checked.")
    elif not seen_egress:
        L.append("- No watched public model API destinations appeared in the egress sources.")
    L.append("")

    L.append("## By residency layer\n")
    L.append("| Layer | Source | Location | Inside border | Identifier hits | Patterns |")
    L.append("|---|---|---|---|---|---|")
    for layer in LAYERS:
        srcs = [s for s in scan if s["layer"] == layer]
        if not srcs:
            L.append(f"| {LAYER_NAMES[layer]} | **not checked** (no source configured) | | | | |")
            continue
        for s in srcs:
            ident = [h for h in s["hits"] if h["kind"] in ("canary", "account")]
            inside = "yes" if s["location"].upper() in allowed else "**no**"
            pats = ", ".join(sorted({h["label"] for h in ident})) or "-"
            L.append(f"| {LAYER_NAMES[layer]} | {s['name']} | {s['location']} | {inside} | {len(ident)} | {pats} |")
    L.append("")

    L.append("## Requests by phase\n")
    L.append("| Phase | Sent | Answered | Median s | Served by | Errors | Canary echoed |")
    L.append("|---|---|---|---|---|---|---|")
    for p, v in phase_info.items():
        served = "<br>".join(f"{k} ({c})" for k, c in v["served_by"].items()) or "-"
        errs = ", ".join(f"{k} ({c})" for k, c in v["errors"].items()) or "-"
        L.append(f"| {p} | {v['sent']} | {v['answered']} | {v['median_seconds']} | {served} | {errs} | {v['canary_echoed']} |")
    L.append("")

    if egress:
        L.append("## Egress evidence\n")
        for s, hits in egress:
            dests = Counter(h["destination"] for h in hits)
            if dests:
                L.append(f"- **{s['name']}**: " + ", ".join(f"{d} ({c})" for d, c in dests.most_common()))
            else:
                L.append(f"- **{s['name']}**: none of the watched destinations")
        L.append("\nCompare timestamps in these logs with the run timeline below to tie traffic to the fault phase.\n")

    L.append("## Locations of hits\n")
    if places:
        for p in places:
            where = (f"{len(p['targets'])} target(s)" if redact else
                     "; ".join(p["targets"][:20]) + (" …" if len(p["targets"]) > 20 else ""))
            L.append(f"- **{p['name']}** ({p['location']}, {p['layer']}): {where}")
        L.append("\n" + ("Paths and URLs are left out of this shareable copy. " if redact else "")
                 + "Full file, line and offset detail is in `scan.json`. Contents are never copied.\n")
    else:
        L.append("- none\n")

    L.append("## Coverage check\n")
    L.append("Each source should at least show the harness's request ids if it sits on the request path.\n")
    L.append("| Source | Targets scanned | Saw request ids | Saw identifiers | Reading |")
    L.append("|---|---|---|---|---|")
    for s in scan:
        rid = any(h["kind"] == "run_id" for h in s["hits"])
        ident = any(h["kind"] in ("canary", "account") for h in s["hits"])
        if s["errors"]:
            reading = (f"{len(s['errors'])} error(s), see scan.json" if redact
                       else "errors: " + "; ".join(s["errors"])[:200])
        elif s["targets_scanned"] == 0:
            reading = "nothing to scan (empty), so this source was not really checked"
        elif ident:
            reading = "holds the customer's identifiers"
        elif rid:
            reading = "saw the requests but not the identifiers: redacted, hashed or not stored here"
        elif s.get("egress"):
            reading = "egress source (request ids usually aren't visible here)"
        else:
            reading = "saw neither: off the request path, outside the time window, or not shipping logs"
        L.append(f"| {s['name']} | {s['targets_scanned']} | {'yes' if rid else 'no'} | {'yes' if ident else 'no'} | {reading} |")
    trunc = [t for s in scan for t in s["truncated"]]
    if trunc:
        L.append(f"\nSome patterns hit the {MAX_HITS_PER_PATTERN}-match cap per file; counts are lower bounds.")
    L.append("")

    L.append("## Run timeline\n")
    for e in run["events"]:
        detail = e.get("detail") and not redact
        L.append(f"- {_ts(e['t'])}: {e['event']}" + (f" ({e['detail']})" if detail else ""))
    L.append("")

    L.append("## Not covered by this run\n")
    for item in NOT_COVERED:
        L.append(f"- {item}")
    L.append("\n*This is an engineering test, not a compliance assessment or legal advice. "
             "One run, one configuration, synthetic data.*\n")

    if redact:
        places = [{k: v for k, v in p.items() if k != "targets"} for p in places]
    summary = {
        "run_id": run["run_id"], "border": border_name, "places": places,
        "places_outside_border": len(outside), "phases": phase_info,
        "egress_destinations": dict(seen_egress),
        "egress_outside_border": dests_out,
        "layers_not_checked": [layer for layer in LAYERS if not any(s["layer"] == layer for s in scan)],
    }
    return "\n".join(L), summary
