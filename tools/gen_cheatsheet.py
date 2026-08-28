#!/usr/bin/env python3
"""Generate CHEATSHEET.md from findings.yaml (single source of truth).

Usage: python tools/gen_cheatsheet.py [--check]
  --check : exit non-zero if CHEATSHEET.md is stale (for CI).
"""
import sys, os, io, collections, yaml

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
CATALOG = os.path.join(ROOT, "findings.yaml")
OUT = os.path.join(ROOT, "CHEATSHEET.md")

FAMILY_NAMES = {
    "02-access-control": "Access Control",
    "03-auth-session": "Authentication & Session",
    "04-injection": "Injection",
    "05-deserialization": "Deserialization",
    "06-ssrf-request-layer": "SSRF & Request Layer",
    "07-client-side": "Client-Side",
    "08-file-path": "File & Path",
    "09-business-logic": "Business Logic",
    "10-crypto-data": "Cryptography & Data",
    "11-config-components": "Config & Components",
    "12-api-protocol": "API Protocol",
}
STARS = {1: "①", 2: "②", 3: "③", 4: "④", 5: "⑤", 6: "⑥"}


def load():
    with open(CATALOG) as fh:
        return yaml.safe_load(fh)["findings"]


def esc(s):
    return str(s).replace("|", "\\|")


def render(findings):
    live = [f for f in findings if f["status"] == "live"]
    na = [f for f in findings if f["status"] == "na"]
    o = io.StringIO()
    w = o.write

    w("# SPRKL — Vulnerability Cheat Sheet\n\n")
    w("> **Generated from `findings.yaml` — do not edit by hand.** "
      "Run `python tools/gen_cheatsheet.py`.\n\n")
    w("SPRKL is a deliberately vulnerable sparkling-water storefront. Each finding "
      "below is detected **server-side** by the oracle and recorded as ground truth; "
      "poll it at `GET /oracle/solves` (scoring port). Testers cannot self-report.\n\n")

    # ---- summary tables ----
    w("## Summary\n\n")
    w(f"- **Total findings:** {len(findings)}  ")
    w(f"(**{len(live)} live**, {len(na)} documented-N/A)\n")

    bydiff = collections.Counter(f["difficulty"] for f in live)
    w("- **By difficulty:** "
      + ", ".join(f"{STARS[d]} {bydiff[d]}" for d in sorted(bydiff)) + "\n")
    byfam = collections.Counter(f["family"] for f in live)
    w("- **By family:** "
      + ", ".join(f"{FAMILY_NAMES[k]} {v}" for k, v in sorted(byfam.items())) + "\n")
    byoracle = collections.Counter(f["oracle_type"] for f in live)
    w("- **By oracle type:** "
      + ", ".join(f"{k} {v}" for k, v in sorted(byoracle.items())) + "\n\n")

    w("**Difficulty legend:** ① trivial · ② easy · ③ moderate · ④ intermediate · "
      "⑤ hard · ⑥ expert\n\n")
    w("**Oracle types:** `sink-predicate` (fires at the vulnerable sink when truly "
      "exploited — including blind findings, detected server-side at the point of "
      "execution/storage, so a tester using their own tooling is credited) · "
      "`state-diff` (server invariant violated) · `canary` (planted secret leaves "
      "through the vuln to an unauthorized actor). An internal OAST collector at "
      "`/collab/<token>` also credits blind findings as a bonus path, but no finding "
      "requires it.\n\n")

    # ---- per-family detail ----
    for fam in sorted(byfam):
        fam_findings = [f for f in findings if f["family"] == fam]
        w(f"## {fam} — {FAMILY_NAMES[fam]}\n\n")
        w("| # | ID | Title | Cat | Diff | Tier | Location | Oracle | OWASP | CWE | Skill |\n")
        w("|---|----|-------|-----|:----:|------|----------|--------|-------|-----|-------|\n")
        for i, f in enumerate(fam_findings, 1):
            owasp = " ".join((f.get("owasp_web") or []) + (f.get("owasp_api") or [])) or "—"
            cwe = " ".join(f.get("cwe") or []) or "—"
            diff = STARS[f["difficulty"]] if f["status"] == "live" else "—"
            oracle = f["oracle_type"] if f["status"] == "live" else "N/A"
            title = esc(f["title"]) + ("" if f["status"] == "live" else " *(N/A)*")
            w(f"| {i} | `{f['id']}` | {title} | {esc(f['category'])} | {diff} | "
              f"{f['tier']} | {esc(f['location'])} | {oracle} | {esc(owasp)} | "
              f"{esc(cwe)} | `{f['skill']}` |\n")
        w("\n")

    # ---- N/A appendix ----
    if na:
        w("## Documented as N/A for this build\n\n")
        w("These Ptolemy exploit types are impractical in a Python single-image app; "
          "they are catalogued for coverage completeness but **not** oracle-scored.\n\n")
        w("| ID | Family | Reason |\n|----|--------|--------|\n")
        for f in na:
            w(f"| `{f['id']}` | {f['family']} | {esc(f['description'])} |\n")
        w("\n")

    return o.getvalue()



FAMILY_ORDER = ["02-access-control","03-auth-session","04-injection","05-deserialization",
                "06-ssrf-request-layer","07-client-side","08-file-path","09-business-logic",
                "10-crypto-data","11-config-components","12-api-protocol"]


def render_html(findings):
    live = [f for f in findings if f["status"] == "live"]
    na = [f for f in findings if f["status"] == "na"]
    rows = []
    for fam in FAMILY_ORDER:
        fam_f = [f for f in findings if f["family"] == fam]
        if not fam_f:
            continue
        rows.append(f'<tr class="fam"><td colspan="10">{fam} — {FAMILY_NAMES[fam]}</td></tr>')
        for f in fam_f:
            owasp = " ".join((f.get("owasp_web") or []) + (f.get("owasp_api") or [])) or "—"
            cwe = " ".join(f.get("cwe") or []) or "—"
            diff = f["difficulty"] if f["status"] == "live" else "—"
            badge = "" if f["status"] == "live" else ' <span class="na">N/A</span>'
            rows.append(
                f'<tr data-diff="{diff}" data-oracle="{f["oracle_type"]}" data-tier="{f["tier"]}">'
                f'<td><code>{f["id"]}</code></td><td>{f["title"]}{badge}</td>'
                f'<td>{f["category"]}</td><td class="d d{diff}">{diff}</td>'
                f'<td>{f["tier"]}</td><td class="loc">{f["location"]}</td>'
                f'<td>{f["oracle_type"] if f["status"]=="live" else "—"}</td>'
                f'<td>{owasp}</td><td>{cwe}</td><td><code>{f["skill"]}</code></td></tr>')
    bydiff = {}
    for f in live:
        bydiff[f["difficulty"]] = bydiff.get(f["difficulty"], 0) + 1
    chips = " ".join(f'<span class="chip d{d}">L{d}: {bydiff.get(d,0)}</span>' for d in range(1,7))
    return f"""<!doctype html><html lang=en><head><meta charset=utf-8>
<meta name=viewport content="width=device-width,initial-scale=1">
<title>SPRKL Cheat Sheet</title><style>
:root{{--bg:#eaf6ff;--card:#fff;--ink:#0a2540;--mut:#5a7a99;--line:#cfe4f5}}
*{{box-sizing:border-box}}body{{font-family:system-ui,sans-serif;margin:0;background:var(--bg);color:var(--ink)}}
header{{background:#0a2540;color:#fff;padding:16px 24px}}header b{{letter-spacing:3px;font-size:22px}}
.wrap{{max-width:1200px;margin:0 auto;padding:20px}}
.warn{{background:#ffe8b3;color:#7a5200;padding:8px 24px;font-size:13px}}
.chips{{margin:12px 0}}.chip{{display:inline-block;padding:3px 9px;border-radius:20px;color:#fff;font-size:12px;margin-right:6px}}
.d1{{background:#2e9e5b}}.d2{{background:#5aa02e}}.d3{{background:#b8952e}}.d4{{background:#c8722e}}.d5{{background:#c8452e}}.d6{{background:#8b2ec8}}
table{{width:100%;border-collapse:collapse;background:var(--card);border-radius:10px;overflow:hidden;font-size:13px}}
th,td{{padding:7px 9px;text-align:left;border-bottom:1px solid var(--line);vertical-align:top}}
th{{background:#dcefff;position:sticky;top:0}}
tr.fam td{{background:#0a2540;color:#7fd3ff;font-weight:700;letter-spacing:1px}}
td.d{{text-align:center;color:#fff;font-weight:700;width:30px}}
.loc{{color:var(--mut);font-family:ui-monospace,monospace;font-size:12px}}
code{{background:#f0f4f8;padding:1px 4px;border-radius:4px;font-size:12px}}
.na{{background:#999;color:#fff;padding:1px 5px;border-radius:4px;font-size:11px}}
.controls{{margin:10px 0}}.controls input{{padding:7px;border-radius:6px;border:1px solid var(--line);width:260px}}
</style></head><body>
<header><b>SPRKL</b> &nbsp;Vulnerability Cheat Sheet</header>
<div class=warn>⚠ Intentionally vulnerable. Authorized testing only. Findings are oracle-scored server-side; poll <code>/oracle/solves</code>.</div>
<div class=wrap>
<p><b>{len(live)}</b> live findings + {len(na)} documented-N/A, across 11 families.</p>
<div class=chips>{chips}</div>
<div class=controls><input id=q placeholder="filter by id / title / category / location…" oninput="flt()"></div>
<table id=t><thead><tr><th>ID</th><th>Title</th><th>Category</th><th>Diff</th><th>Tier</th><th>Location</th><th>Oracle</th><th>OWASP</th><th>CWE</th><th>Skill</th></tr></thead>
<tbody>{''.join(rows)}</tbody></table></div>
<script>
function flt(){{var v=document.getElementById('q').value.toLowerCase();
document.querySelectorAll('#t tbody tr').forEach(function(r){{
if(r.classList.contains('fam')){{r.style.display='';return;}}
r.style.display=r.textContent.toLowerCase().includes(v)?'':'none';}});}}
</script></body></html>"""


def main():
    findings = load()
    content = render(findings)
    check = "--check" in sys.argv
    if check:
        current = open(OUT).read() if os.path.exists(OUT) else ""
        if current != content:
            print("CHEATSHEET.md is STALE — run: python tools/gen_cheatsheet.py",
                  file=sys.stderr)
            sys.exit(1)
        print("CHEATSHEET.md is up to date.")
        return
    with open(OUT, "w") as fh:
        fh.write(content)
    html_out = os.path.join(ROOT, "cheatsheet.html")
    with open(html_out, "w") as fh:
        fh.write(render_html(findings))
    print(f"Wrote {OUT} and {html_out} ({len(findings)} findings)")


if __name__ == "__main__":
    main()
