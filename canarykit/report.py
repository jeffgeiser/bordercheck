"""Turn run.json and scan.json into a plain report a platform team, CISO or DPO can read.

analyze() works out the facts and the verdict once; markdown() and onepager.html() only present
them, so the two can't disagree.
"""
import re
import statistics
import time
import urllib.parse
from collections import Counter

from .canary import IDENTIFIER_KINDS
from .config import LAYERS
from .scan import MAX_HITS_PER_PATTERN, _watch_regex

LAYER_NAMES = {
    "data": "Where the data lives",
    "processing": "Where it's processed",
    "model_state": "Where model state lives (caches, embeddings, KV offload)",
    "logs": "Where logs and the control plane live",
}

KIND_NAMES = {"canary": "canary", "account": "account no.", "email": "email", "phone": "phone", "iban": "IBAN"}

PROBE_NAMES = {
    "probe:context_window": "Context-window probe (prompt longer than the local model takes)",
    "probe:rate_limit": "Rate-limit probe (burst of concurrent requests)",
    "probe:content_policy": "Content-policy probe (prompt the local model or guardrail rejects)",
}

NOT_COVERED = [
    "What the fallback provider keeps on its side (retention, abuse-monitoring logs, backups). "
    "Check their data-processing terms; this harness can only show that data reached them.",
    "Payload contents on encrypted links you don't inspect. Without TLS inspection, egress evidence "
    "shows where requests went, not what they carried.",
    "Stores you didn't list as sources. A clean result covers only what was scanned.",
    "Backups, snapshots and replicas made after this run. `canarykit rescan` checks retention later.",
    "Whether embeddings can be inverted back to text. Finding no canary in a vector store "
    "doesn't mean the vectors carry no personal data.",
]

# Plain names for phases, used in verdict reasons and the one-pager.
PHASE_LABELS = {
    "baseline": "Baseline (model up)",
    "fault": "Local model down",
    "probe:context_window": "Long prompt (model up)",
    "probe:rate_limit": "Burst of requests (model up)",
    "probe:content_policy": "Rejected prompt (model up)",
}

EXIT_CODES = {"pass": 0, "fail": 1, "inconclusive": 3}


def _ts(t):
    return time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(t))


HOST_RE = re.compile(r"\b(?:[a-z0-9-]+\.)+[a-z][a-z0-9-]*(?::\d+)?|\b\d{1,3}(?:\.\d{1,3}){3}(?::\d+)?", re.I)


def _hosts(value):
    return [m.group(0).split(":")[0].lower() for m in HOST_RE.finditer(str(value))]


def _matches(host, regexes):
    return any(rx.fullmatch(host.encode()) for rx in regexes)


def _redact_hosts(value, public):
    """Replace hostnames and IPs with "(internal host)" unless they match a watched public API."""
    def repl(m):
        return m.group(0) if _matches(m.group(0).split(":")[0], public) else "(internal host)"
    if "://" in value:
        parts = urllib.parse.urlsplit(value)
        value = f"{parts.scheme}://{parts.netloc}"
    return HOST_RE.sub(repl, value)


def _served_values(entry):
    return {k: v for k, v in {**entry.get("fields", {}), **entry.get("headers", {})}.items() if v not in (None, "")}


def _served_by(entry, public=None):
    vals = [f"{k}={v if public is None else _redact_hosts(str(v), public)}" for k, v in _served_values(entry).items()]
    return ", ".join(vals) if vals else None


def _ok(r):
    return r.get("status") is not None and 200 <= r["status"] < 300


def _phase_summary(requests, public=None):
    ok = [r for r in requests if _ok(r)]
    served = Counter(_served_by(r, public) or "(no served-by fields recorded)" for r in ok)
    errors = Counter(r.get("error") or f"HTTP {r.get('status')}" for r in requests if not _ok(r))
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


def verdict(sources, outside, dests_out, phases):
    """("pass" | "fail" | "inconclusive", reasons).

    A leak that was found is real whatever else went wrong, so fail wins. A pass needs evidence
    that scanning works (a positive control that found the customer) and no source errors.
    """
    fail = [f"identifiers found in {p['name']} ({p['location']}), outside the border" for p in outside]
    fail += [f"egress to {d}, a public model API the border doesn't allow" for d in dests_out]
    fail += [f"{PHASE_LABELS.get(name, name)}: the gateway reports {', '.join(p['public_hosts'])} answered, "
             "a public model API the border doesn't allow" for name, p in phases.items() if p["public_hosts"]]
    if fail:
        return "fail", fail
    unsure = []
    controls = [s for s in sources if s["positive_control"]]
    if not controls:
        unsure.append("no positive control configured, so a clean scan can't be told from a broken one")
    unsure += [f"positive control {s['name']} didn't find the customer: fix that source before trusting clean results"
               for s in controls if not s["identifiers"]]
    unsure += [f"{s['name']} had errors, so it wasn't fully checked" for s in sources if s["errors"]]
    if not any(s["egress"] for s in sources):
        # Unless the served-by fields name a host we can place, there's no telling where it ran.
        unsure += [f"{PHASE_LABELS.get(name, name)}: a different backend answered and no egress source shows where it runs"
                   for name, p in phases.items() if p["changed_backend"] and not p["allowed_hosts"]]
    return ("inconclusive", unsure) if unsure else ("pass", [])


def analyze(cfg, run, scan, redact=False):
    """Everything the report says, as data. With redact=True, paths, URLs, error text and fault
    commands are left out and internal hostnames are masked, so it can be shared outside the team."""
    allowed = {loc.upper() for loc in cfg["border"]["allowed_locations"]}
    border_name = cfg["border"].get("name", "/".join(sorted(allowed)))
    watched = [_watch_regex(p) for p in cfg["watch_destinations"]]
    # Destinations the border allows, such as an in-region cloud endpoint you approved as a fallback.
    approved = [_watch_regex(p) for p in cfg["border"].get("allowed_destinations", [])]

    by_phase = {}
    for r in run["requests"]:
        by_phase.setdefault(r["phase"], []).append(r)
    phases = {name: _phase_summary(reqs, watched if redact else None) for name, reqs in by_phase.items()}
    base = phases.get("baseline")
    for name, info in phases.items():
        # Hostnames in served-by values (LiteLLM's x-litellm-model-api-base, for one) are the
        # gateway's own word for where a request went.
        hosts = {h for r in by_phase[name] if _ok(r) for v in _served_values(r).values() for h in _hosts(v)}
        info["public_hosts"] = sorted(h for h in hosts if _matches(h, watched) and not _matches(h, approved))
        info["allowed_hosts"] = sorted(h for h in hosts if _matches(h, approved))
        info["changed_backend"] = bool(name != "baseline" and base and info["answered"]
                                       and set(info["served_by"]) - set(base["served_by"]))

    sources, places = [], []
    kinds_planted = [k for k in IDENTIFIER_KINDS if k in run["record"]]
    for s in scan:
        ident = [h for h in s["hits"] if h["kind"] in IDENTIFIER_KINDS]
        src = {
            "name": s["name"], "layer": s["layer"], "location": s["location"],
            "inside": s["location"].upper() in allowed, "egress": s.get("egress", False),
            "positive_control": s.get("positive_control", False),
            "targets_scanned": s["targets_scanned"], "errors": len(s["errors"]),
            "identifiers": bool(ident), "saw_request_ids": any(h["kind"] == "run_id" for h in s["hits"]),
            "kinds_found": sorted({h["kind"] for h in ident}, key=IDENTIFIER_KINDS.index),
            "truncated": bool(s["truncated"]),
        }
        sources.append(src)
        if ident:
            place = {k: src[k] for k in ("name", "layer", "location", "inside")}
            place.update(hits=len(ident), patterns=sorted({h["label"] for h in ident}))
            if not redact:
                place["targets"] = sorted({h["where"] for h in ident})
            places.append(place)
    outside = [p for p in places if not p["inside"]]

    egress = {s["name"]: Counter(h["destination"] for h in s["hits"] if h["kind"] == "egress")
              for s in scan if s.get("egress")}
    seen = {d for c in egress.values() for d in c}
    dests_ok = sorted(d for d in seen if _matches(d, approved))
    dests_out = sorted(seen - set(dests_ok))

    result, reasons = verdict(sources, outside, dests_out, phases)
    events = [{"t": e["t"], "event": e["event"], **({"detail": e["detail"]} if e.get("detail") and not redact else {})}
              for e in run["events"]]
    return {
        "run_id": run["run_id"], "environment": run["environment"], "created": run["created"],
        "verdict": result, "reasons": reasons,
        "border": border_name, "allowed_locations": sorted(allowed),
        "canary": run["record"]["canary"], "account": run["record"]["account"],
        "kinds_planted": kinds_planted,
        "places": places, "places_outside_border": len(outside),
        "sources": sources, "phases": phases,
        "egress_destinations": {n: dict(c) for n, c in egress.items()},
        "egress_outside_border": dests_out, "egress_allowed": dests_ok,
        "layers_not_checked": [layer for layer in LAYERS if not any(s["layer"] == layer for s in scan)],
        "redacted": redact, "events": events,
        "errors_detail": {s["name"]: s["errors"] for s in scan if s["errors"] and not redact},
    }


def _phase_lines(name, p):
    if p["answered"] == 0:
        errs = ", ".join(f"{k} ({c})" for k, c in p["errors"].items())
        if name == "fault":
            return [f"- During the fault, **0 of {p['sent']}** requests were answered ({errs}). The system "
                    "failed closed: the border held, and the cost was an outage. Capacity inside the "
                    "border, with a spare, is what keeps both."]
        return [f"- {PROBE_NAMES.get(name, name)}: **0 of {p['sent']}** answered ({errs}). It failed closed."]
    if name == "fault":
        out = [f"- During the fault, **{p['answered']} of {p['sent']}** requests were still answered."]
    else:
        out = [f"- {PROBE_NAMES.get(name, name)}, with nothing down: **{p['answered']} of {p['sent']}** answered."]
    if p["public_hosts"]:
        out.append(f"  - Answered by **{', '.join(p['public_hosts'])}**, according to the served-by fields.")
    elif p["changed_backend"]:
        out.append("  - Served by something different from the baseline: "
                   + "; ".join(f"`{k}` ({v})" for k, v in p["served_by"].items()) + ". Confirm where that backend runs.")
    elif all(k.startswith("(no served-by") for k in p["served_by"]):
        out.append("  - No served-by fields were recorded, so this run can't say who answered. "
                   "Add `record_fields` / `record_headers` under [target].")
    elif name == "fault":
        out.append("  - Served-by fields matched the baseline. If the local model was really down, "
                   "those fields may not identify the backend; check gateway logs.")
    if p["allowed_hosts"]:
        out.append(f"  - Answered by {', '.join(p['allowed_hosts'])}, which `allowed_destinations` permits.")
    return out


def markdown(r):
    L = [f"# canarykit report: {r['run_id']}\n",
         f"- Environment: **{r['environment']}**",
         f"- Border: **{r['border']}** (allowed locations: {', '.join(r['allowed_locations'])})",
         f"- Canary: `{r['canary']}` · synthetic account `{r['account']}`",
         f"- Run created: {_ts(r['created'])}\n"]

    L.append(f"## Verdict: {r['verdict'].upper()}\n")
    L.append({"pass": "No identifiers outside the border, no traffic to disallowed model APIs, and the "
                      "positive control shows the scan works.",
              "fail": "The synthetic customer's data crossed the border:",
              "inconclusive": "Nothing crossed the border in what was scanned, but the evidence isn't complete:"}[r["verdict"]])
    L.extend(f"- {x}" for x in r["reasons"])
    if "fault" not in r["phases"]:
        L.append("- Note: no fault phase was run, so this says nothing about failover when the model is down.")
    L.append("")

    L.append("## Summary\n")
    places = r["places"]
    if places:
        L.append(f"- The synthetic customer's identifiers were found in **{len(places)} place(s)**, "
                 f"**{r['places_outside_border']} outside the border**: "
                 + "; ".join(f"{p['name']} ({p['location']})" for p in places) + ".")
    else:
        L.append("- The synthetic customer's identifiers were **not found** in any scanned source. "
                 "Check the coverage section before treating this as clean.")
    if r["egress_outside_border"]:
        # A public API is outside any border a scanned store can show, so say it up front.
        L.append(f"- **Traffic left the border** to public model APIs: {', '.join(r['egress_outside_border'])} "
                 "(egress evidence, below). Without TLS inspection this shows the destination, not the payload; "
                 "the served-by fields show which phase was answered from there.")
    if r["egress_allowed"]:
        L.append(f"- Traffic reached model APIs the border allows: {', '.join(r['egress_allowed'])} "
                 "(`allowed_destinations`). Confirm the provider's data-processing terms match.")
    base = r["phases"].get("baseline")
    if base:
        L.append(f"- Baseline: {base['answered']} of {base['sent']} requests answered.")
    for name, p in r["phases"].items():
        if name != "baseline":
            L.extend(_phase_lines(name, p))
    echoed = sum(v["canary_echoed"] for v in r["phases"].values())
    if echoed:
        L.append(f"- The canary came back in **{echoed}** model responses: identifiers reached the model unredacted.")
    if not r["egress_destinations"]:
        L.append("- No egress sources configured, so outbound destinations weren't checked.")
    elif not r["egress_outside_border"] and not r["egress_allowed"]:
        L.append("- No watched public model API destinations appeared in the egress sources.")
    L.append("")

    L.append("## By residency layer\n")
    L.append("| Layer | Source | Location | Inside border | Identifier hits | Patterns |")
    L.append("|---|---|---|---|---|---|")
    for layer in LAYERS:
        srcs = [s for s in r["sources"] if s["layer"] == layer]
        if not srcs:
            L.append(f"| {LAYER_NAMES[layer]} | **not checked** (no source configured) | | | | |")
        for s in srcs:
            place = next((p for p in places if p["name"] == s["name"]), None)
            pats = ", ".join(place["patterns"]) if place else "-"
            L.append(f"| {LAYER_NAMES[layer]} | {s['name']} | {s['location']} | {'yes' if s['inside'] else '**no**'} "
                     f"| {place['hits'] if place else 0} | {pats} |")
    L.append("")

    L.append("## Requests by phase\n")
    L.append("| Phase | Sent | Answered | Median s | Served by | Errors | Canary echoed |")
    L.append("|---|---|---|---|---|---|---|")
    for name, v in r["phases"].items():
        served = "<br>".join(f"{k} ({c})" for k, c in v["served_by"].items()) or "-"
        errs = ", ".join(f"{k} ({c})" for k, c in v["errors"].items()) or "-"
        L.append(f"| {name} | {v['sent']} | {v['answered']} | {v['median_seconds']} | {served} | {errs} | {v['canary_echoed']} |")
    L.append("")

    on_path = [s for s in r["sources"] if s["saw_request_ids"] or s["identifiers"]]
    if on_path and len(r["kinds_planted"]) > 2:
        L.append("## Which identifier formats each store kept\n")
        L.append("Stores that saw the requests. A format that's missing where others are present was "
                 "masked or dropped there, which is what redaction should do.\n")
        L.append("| Source | " + " | ".join(KIND_NAMES[k] for k in r["kinds_planted"]) + " |")
        L.append("|---|" + "---|" * len(r["kinds_planted"]))
        for s in on_path:
            L.append(f"| {s['name']} | " + " | ".join("kept" if k in s["kinds_found"] else "-" for k in r["kinds_planted"]) + " |")
        L.append("\nThe phone number comes from a reserved range of 1,000, so a match can occasionally be "
                 "from an earlier run.\n")

    if r["egress_destinations"]:
        L.append("## Egress evidence\n")
        for name, dests in r["egress_destinations"].items():
            if dests:
                L.append(f"- **{name}**: " + ", ".join(f"{d} ({c})" for d, c in sorted(dests.items(), key=lambda x: -x[1])))
            else:
                L.append(f"- **{name}**: none of the watched destinations")
        L.append("\nCompare timestamps in these logs with the run timeline below to tie traffic to a phase.\n")

    L.append("## Locations of hits\n")
    if places:
        for p in places:
            targets = p.get("targets") or []
            where = "; ".join(targets[:20]) + (" …" if len(targets) > 20 else "") if targets else "paths left out"
            L.append(f"- **{p['name']}** ({p['location']}, {p['layer']}): {where}")
        L.append("\n" + ("Paths and URLs are left out of this shareable copy. " if r["redacted"] else "")
                 + "Full file, line and offset detail is in `scan.json`. Contents are never copied.\n")
    else:
        L.append("- none\n")

    L.append("## Coverage check\n")
    L.append("Each source should at least show the harness's request ids if it sits on the request path.\n")
    L.append("| Source | Targets scanned | Saw request ids | Saw identifiers | Reading |")
    L.append("|---|---|---|---|---|")
    for s in r["sources"]:
        if s["positive_control"] and not s["identifiers"]:
            reading = "**positive control did not find the customer**: this source, or the scan, isn't working"
        elif s["errors"]:
            reading = (f"{s['errors']} error(s), see scan.json" if r["redacted"]
                       else "errors: " + "; ".join(r["errors_detail"][s["name"]])[:200])
        elif s["targets_scanned"] == 0:
            reading = "nothing to scan (empty), so this source was not really checked"
        elif s["identifiers"]:
            reading = "positive control: found, as expected" if s["positive_control"] else "holds the customer's identifiers"
        elif s["saw_request_ids"]:
            reading = "saw the requests but not the identifiers: redacted, hashed or not stored here"
        elif s["egress"]:
            reading = "egress source (request ids usually aren't visible here)"
        else:
            reading = "saw neither: off the request path, outside the time window, or not shipping logs"
        L.append(f"| {s['name']} | {s['targets_scanned']} | {'yes' if s['saw_request_ids'] else 'no'} "
                 f"| {'yes' if s['identifiers'] else 'no'} | {reading} |")
    if any(s["truncated"] for s in r["sources"]):
        L.append(f"\nSome patterns hit the {MAX_HITS_PER_PATTERN}-match cap per file; counts are lower bounds.")
    L.append("")

    L.append("## Run timeline\n")
    for e in r["events"]:
        L.append(f"- {_ts(e['t'])}: {e['event']}" + (f" ({e['detail']})" if e.get("detail") else ""))
    L.append("")

    L.append("## Not covered by this run\n")
    L.extend(f"- {item}" for item in NOT_COVERED)
    L.append("\n*This is an engineering test, not a compliance assessment or legal advice. "
             "One run, one configuration, synthetic data.*\n")
    return "\n".join(L)


def build(cfg, run, scan, redact=False):
    """(report.md text, summary dict). summary.json is the analysis minus error text."""
    r = analyze(cfg, run, scan, redact)
    summary = {k: v for k, v in r.items() if k != "errors_detail"}
    return markdown(r), summary
