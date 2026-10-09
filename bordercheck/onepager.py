"""A one-page HTML summary for people who won't read report.md: verdict, residency layers, who
answered, and what wasn't covered. Self-contained (no scripts, fonts or remote assets), so it
opens offline, passes a strict CSP, and prints to a single PDF page from any browser.

Everything taken from the run (source names, served-by values from responses) is HTML-escaped:
a gateway header is untrusted input.
"""
from html import escape
import time

from .config import LAYERS
from .report import KIND_NAMES, PHASE_LABELS

LAYER_TITLES = {
    "data": ("Data", "where it's stored"),
    "processing": ("Processing", "where it's computed"),
    "model_state": ("Model state", "caches, embeddings"),
    "logs": ("Logs & control plane", "telemetry, tracing"),
}

VERDICT_TEXT = {
    "pass": "Nothing crossed the border, and the scan is shown to work.",
    "fail": "The synthetic customer's data crossed the border.",
    "inconclusive": "Nothing crossed the border in what was scanned, but the evidence is incomplete.",
}

# Only rules we can name precisely. Wording is "relevant to", never "complies with".
FRAMEWORKS = [
    ("EU DORA, Regulation (EU) 2022/2554, Art. 28 and 30",
     "https://eur-lex.europa.eu/eli/reg/2022/2554/oj",
     "Contracts must state where data is processed, and exit strategies must be credible. "
     "This run shows where data was processed, including when the local model failed."),
    ("GDPR, Regulation (EU) 2016/679, Chapter V",
     "https://eur-lex.europa.eu/eli/reg/2016/679/oj",
     "A failover to a model outside the EEA is a transfer of personal data. "
     "This run shows whether one happens, under which conditions."),
    ("EBA Guidelines on outsourcing arrangements (EBA/GL/2019/02)", None,
     "Firms must know where data is stored and processed and test their continuity plans."),
    ("EU AI Act, Regulation (EU) 2024/1689, Art. 12", "https://eur-lex.europa.eu/eli/reg/2024/1689/oj",
     "Required event logs are themselves stores with a residency footprint; scan them too."),
]

CSS = """
:root{--bg:#fff;--fg:#1b1f24;--muted:#5b6470;--line:#d9dde3;--card:#f6f7f9;--link:#0b57d0;
--pass:#1f7a3f;--pass-bg:#e6f4ea;--fail:#b3261e;--fail-bg:#fbe9e7;--warn:#8a5a00;--warn-bg:#fff4dc;
--none:#5b6470;--none-bg:#eef0f3}
@media (prefers-color-scheme:dark){:root{--bg:#14171b;--fg:#e8eaed;--muted:#a0a8b3;--line:#2c3239;
--card:#1c2026;--link:#8ab4f8;--pass:#7fd49a;--pass-bg:#173523;--fail:#ff9a8f;--fail-bg:#3d1a17;--warn:#f2c46b;
--warn-bg:#372a10;--none:#a0a8b3;--none-bg:#242a31}}
*{box-sizing:border-box}
body{margin:0;background:var(--bg);color:var(--fg);font:14px/1.45 system-ui,-apple-system,"Segoe UI",Roboto,sans-serif}
main{max-width:880px;margin:0 auto;padding:28px 16px 40px}
header{display:flex;justify-content:space-between;gap:16px;flex-wrap:wrap;align-items:baseline}
h1{font-size:20px;margin:0}h2{font-size:13px;text-transform:uppercase;letter-spacing:.06em;color:var(--muted);margin:24px 0 8px}
.meta{color:var(--muted);font-size:12.5px}
.verdict{margin:16px 0 4px;padding:14px 16px;border-radius:10px;border:1px solid var(--line)}
.verdict b{font-size:22px;letter-spacing:.04em;display:block}
.v-pass{background:var(--pass-bg);color:var(--pass)}.v-fail{background:var(--fail-bg);color:var(--fail)}
.v-inconclusive{background:var(--warn-bg);color:var(--warn)}
.verdict ul{margin:6px 0 0;padding-left:18px;color:var(--fg)}
.layers{display:grid;grid-template-columns:repeat(4,1fr);gap:10px}
@media (max-width:640px){.layers{grid-template-columns:1fr 1fr}}
.layer{border:1px solid var(--line);border-radius:10px;padding:10px 12px;background:var(--card)}
.layer .t{font-weight:600}.layer .s{color:var(--muted);font-size:12px}
.pill{display:inline-block;margin-top:8px;padding:2px 8px;border-radius:999px;font-size:12px;font-weight:600}
.st-fail{background:var(--fail-bg);color:var(--fail)}.st-warn{background:var(--warn-bg);color:var(--warn)}
.st-pass{background:var(--pass-bg);color:var(--pass)}.st-none{background:var(--none-bg);color:var(--none)}
.layer .why{font-size:12px;margin-top:6px}
table{width:100%;border-collapse:collapse;font-size:13px}
th,td{text-align:left;padding:6px 8px;border-bottom:1px solid var(--line);vertical-align:top}
th{color:var(--muted);font-weight:600;font-size:12px}
td.num{text-align:right;font-variant-numeric:tabular-nums}
a{color:var(--link)}
code{font:12px ui-monospace,SFMono-Regular,Menlo,monospace;overflow-wrap:anywhere}
.small{font-size:12px;color:var(--muted)}
ul.plain{margin:0;padding-left:18px}
ol.findings{margin:0;padding-left:0;list-style:none;display:flex;flex-direction:column;gap:8px}
ol.findings li{padding:8px 12px;border-left:3px solid var(--line);background:var(--card);border-radius:0 8px 8px 0}
ol.findings li b{display:block}
ol.findings li.f-fail{border-left-color:var(--fail)}ol.findings li.f-warn{border-left-color:var(--warn)}
ol.findings li.f-ok{border-left-color:var(--pass)}
@media print{body{font-size:11.5px}main{padding:0}.layer,.verdict{break-inside:avoid}}
"""


def _layer_status(layer, r):
    """(css class, label, why) for one residency layer."""
    srcs = [s for s in r["sources"] if s["layer"] == layer]
    outside = [s["name"] for s in srcs if s["identifiers"] and not s["inside"]]
    if layer == "processing":
        public = sorted({h for p in r["phases"].values() for h in p["public_hosts"]} | set(r["egress_outside_border"]))
        if public:
            return "st-fail", "Outside border", "Answered by or sent to " + ", ".join(public)
    if outside:
        return "st-fail", "Outside border", "Customer data in " + ", ".join(outside)
    if not srcs:
        return "st-none", "Not checked", "No source configured"
    inside = [s["name"] for s in srcs if s["identifiers"]]
    if inside:
        return "st-warn", "Copies inside border", ", ".join(inside)
    if any(s["errors"] for s in srcs):
        return "st-warn", "Incomplete", "A source had errors"
    return "st-pass", "Checked, clean", f"{len(srcs)} source(s) scanned"


def html(r, frameworks=False):
    e = escape
    out = ["<!doctype html><html lang='en'><head><meta charset='utf-8'>",
           "<meta name='viewport' content='width=device-width,initial-scale=1'>",
           f"<title>Residency test: {e(r['verdict'].upper())}</title><style>{CSS}</style></head><body><main>"]
    out.append(f"<header><h1>AI data residency test: {e(r['border'])}</h1>"
               f"<div class='meta'>{e(r['environment'])} · {e(r['run_id'])} · "
               f"{e(time.strftime('%Y-%m-%d', time.localtime(r['created'])))}</div></header>")

    out.append(f"<section class='verdict v-{e(r['verdict'])}'><b>{e(r['verdict'].upper())}</b>"
               f"{e(VERDICT_TEXT[r['verdict']])}")
    if r["reasons"]:
        out.append("<ul>" + "".join(f"<li>{e(x)}</li>" for x in r["reasons"]) + "</ul>")
    out.append("</section>")
    if r.get("findings"):
        out.append("<h2>What we found</h2><ol class='findings'>")
        for f in r["findings"][:6]:
            out.append(f"<li class='f-{e(f['severity'])}'><b>{e(f['headline'])}</b> {e(f['detail'])}</li>")
        out.append("</ol>")
    out.append("<p class='small'>A synthetic customer was sent through the AI gateway; the local model was "
               "taken away and the same requests sent again; then logs, traces, caches, vector stores and "
               "egress records were searched for that customer.</p>")

    out.append("<h2>Residency layers</h2><div class='layers'>")
    for layer in LAYERS:
        cls, label, why = _layer_status(layer, r)
        title, sub = LAYER_TITLES[layer]
        out.append(f"<div class='layer'><div class='t'>{e(title)}</div><div class='s'>{e(sub)}</div>"
                   f"<span class='pill {cls}'>{e(label)}</span><div class='why'>{e(why)}</div></div>")
    out.append("</div>")

    out.append("<h2>Who answered</h2><table><tr><th>Condition</th><th class='num'>Answered</th><th>Served by</th></tr>")
    for name, p in r["phases"].items():
        served = "; ".join(f"{k} ({c})" for k, c in p["served_by"].items()) or ", ".join(p["errors"]) or "-"
        out.append(f"<tr><td>{e(PHASE_LABELS.get(name, name))}</td><td class='num'>{p['answered']} / {p['sent']}</td>"
                   f"<td><code>{e(served)}</code></td></tr>")
    out.append("</table>")

    kinds = r.get("kinds_sent", [])
    on_path = [s for s in r["sources"] if s["saw_request_ids"] or s["identifiers"]]
    if on_path and len(kinds) > 2:
        out.append("<h2>Redaction: which formats each store kept</h2><table><tr><th>Store</th>"
                   + "".join(f"<th>{e(KIND_NAMES[k])}</th>" for k in kinds) + "</tr>")
        for s in on_path:
            out.append(f"<tr><td>{e(s['name'])}</td>" + "".join(
                f"<td>{'kept' if k in s['kinds_found'] else '-'}</td>" for k in kinds) + "</tr>")
        out.append("</table>")

    out.append("<h2>Not covered</h2><ul class='plain small'>"
               "<li>What a fallback provider keeps on its side; their data-processing terms decide that.</li>"
               "<li>Stores not listed as sources, and backups made after the run.</li>"
               "<li>Payload contents on links without TLS inspection (destinations only).</li>"
               + "".join(f"<li>{e(n)}: outside the border and can't show it saw this run, so its clean result is unverified.</li>"
                         for n in r.get("unverified", []))
               + "</ul>")

    if frameworks:
        out.append("<h2>Where this evidence is relevant</h2><table>")
        for name, url, text in FRAMEWORKS:
            ref = f"<a href='{e(url)}'>{e(name)}</a>" if url else e(name)
            out.append(f"<tr><td>{ref}</td><td>{e(text)}</td></tr>")
        out.append("</table><p class='small'>Engineering evidence, not a compliance assessment or legal advice.</p>")
    else:
        out.append("<p class='small'>Engineering evidence from one run with synthetic data. "
                   "Not a compliance assessment or legal advice.</p>")
    out.append("</main></body></html>")
    return "".join(out)
