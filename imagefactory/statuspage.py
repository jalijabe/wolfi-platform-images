"""Render status.json as a static site: index.html (the status page), SVG
badges for the README, and status.json itself. No external assets."""

from __future__ import annotations

import html
import json
from pathlib import Path
from typing import Any

from imagefactory.status import summary

GOOD, WARN, CRIT, LABEL = "#0ca30c", "#fab219", "#d03b3b", "#52514e"


def esc(v: object) -> str:
    return html.escape(str(v), quote=True)


# ---------------------------------------------------------------- badges


def badge(label: str, value: str, color: str) -> str:
    """A flat two-part badge. Text is near-black on the warning fill, else white."""
    lw, vw = 6 * len(label) + 12, 6 * len(value) + 12
    ink = "#0b0b0b" if color == WARN else "#ffffff"
    return (
        f'<svg xmlns="http://www.w3.org/2000/svg" width="{lw + vw}" height="20" role="img" '
        f'aria-label="{esc(label)}: {esc(value)}"><title>{esc(label)}: {esc(value)}</title>'
        f'<rect width="{lw}" height="20" rx="3" fill="{LABEL}"/>'
        f'<rect x="{lw}" width="{vw}" height="20" rx="3" fill="{color}"/>'
        f'<rect x="{lw}" width="4" height="20" fill="{color}"/>'
        f'<g font-family="system-ui,-apple-system,Segoe UI,sans-serif" font-size="11" text-anchor="middle">'
        f'<text x="{lw / 2}" y="14" fill="#ffffff">{esc(label)}</text>'
        f'<text x="{lw + vw / 2}" y="14" fill="{ink}" font-weight="600">{esc(value)}</text></g></svg>\n'
    )


def age_text(days: int | None) -> str:
    if days is None:
        return "unknown"
    return "today" if days == 0 else ("1 day ago" if days == 1 else f"{days} days ago")


def image_badges(img: dict[str, Any], fresh_days: int) -> dict[str, str]:
    age, cves, fn = img["ageDays"], img["cves"], img["functional"]
    fresh_ok = age is not None and age <= fresh_days and img["upstream"]["current"]
    blocking = len(cves["blocking"])
    total = fn["passed"] + fn["failed"] + fn["skipped"]
    return {
        f"{img['name']}-built.svg": badge("built", age_text(age), GOOD if fresh_ok else WARN),
        f"{img['name']}-cves.svg": badge(
            "CVEs ≥ high", str(blocking), GOOD if blocking == 0 and img["signature"] == "verified" else CRIT
        ),
        f"{img['name']}-tests.svg": badge(
            "tests", f"{fn['passed']}/{total} passing" if total else "not run", GOOD if fn["ok"] else CRIT
        ),
    }


# ---------------------------------------------------------------- charts


def findings_chart(history: list[dict[str, Any]]) -> str:
    """Emphasis line chart: findings at or above the gate (accent) against all
    findings (de-emphasis gray), summed over images, one point per daily scan."""
    pts = [
        (
            h["date"],
            sum(v["blocking"] for v in h["images"].values()),
            sum(v["total"] for v in h["images"].values()),
        )
        for h in history
    ]
    if not pts:
        return '<p class="muted">No scans yet.</p>'
    w, h_, left, right, top, bottom = 460, 200, 30, 118, 12, 26
    pw, ph = w - left - right, h_ - top - bottom
    ymax = max(5, max(p[2] for p in pts))
    step = 1 if ymax <= 5 else (5 if ymax <= 25 else 10 * (1 + ymax // 50))
    ymax = ((ymax + step - 1) // step) * step

    def x(i: int) -> float:
        return left + (pw * i / (len(pts) - 1) if len(pts) > 1 else pw / 2)

    def y(v: float) -> float:
        return float(top + ph - ph * v / ymax)

    grid = "".join(
        f'<line x1="{left}" x2="{left + pw}" y1="{y(v):.1f}" y2="{y(v):.1f}" class="grid"/>'
        f'<text x="{left - 6}" y="{y(v) + 4:.1f}" class="tick" text-anchor="end">{v}</text>'
        for v in range(0, ymax + 1, step)
    )
    first, last = pts[0][0], pts[-1][0]
    axis = (
        f'<line x1="{left}" x2="{left + pw}" y1="{y(0):.1f}" y2="{y(0):.1f}" class="axis"/>'
        f'<text x="{left}" y="{h_ - 8}" class="tick">{esc(first)}</text>'
        + (
            f'<text x="{left + pw}" y="{h_ - 8}" class="tick" text-anchor="end">{esc(last)}</text>'
            if last != first
            else ""
        )
    )

    def line(idx: int, cls: str) -> str:
        d = " ".join(f"{'M' if i == 0 else 'L'}{x(i):.1f},{y(p[idx]):.1f}" for i, p in enumerate(pts))
        end = pts[-1]
        return (
            f'<path d="{d}" class="{cls}"/>'
            f'<circle cx="{x(len(pts) - 1):.1f}" cy="{y(end[idx]):.1f}" r="4" class="{cls}-dot"/>'
        )

    end = pts[-1]
    labels = (
        f'<text x="{left + pw + 10}" y="{y(end[1]) + 4:.1f}" class="lbl">At or above high: {end[1]}</text>'
        f'<text x="{left + pw + 10}" y="{y(end[2]) + (4 if abs(y(end[2]) - y(end[1])) > 14 else -10):.1f}" '
        f'class="lbl muted">All findings: {end[2]}</text>'
    )
    hits = "".join(
        f'<rect x="{x(i) - max(12, pw / max(1, len(pts) - 1) / 2):.1f}" y="{top}" '
        f'width="{max(24, pw / max(1, len(pts) - 1)):.1f}" height="{ph}" class="hit" tabindex="0" '
        f'data-tip="{esc(d)}&#10;{b} at or above high&#10;{t} findings in all" '
        f'aria-label="{esc(d)}: {b} at or above high, {t} in all"/>'
        for i, (d, b, t) in enumerate(pts)
    )
    return (
        f'<svg viewBox="0 0 {w} {h_}" class="chart" role="img" '
        f'aria-label="CVE findings across all images by daily scan">{grid}{axis}'
        f"{line(2, 'context')}{line(1, 'accent')}{labels}{hits}</svg>"
    )


def age_chart(images: list[dict[str, Any]], fresh_days: int) -> str:
    """Horizontal bars, one hue: days since each published digest was built,
    with the freshness policy marked."""
    rows = [(i["name"], i["ageDays"]) for i in images]
    if not rows:
        return '<p class="muted">Nothing published yet.</p>'
    w, left, right, bar, gap = 460, 168, 48, 16, 12
    hgt = len(rows) * (bar + gap) + 24
    xmax = max(fresh_days, *(a or 0 for _, a in rows))
    pw = w - left - right

    def x(v: float) -> float:
        return left + pw * v / xmax

    out = [
        f'<svg viewBox="0 0 {w} {hgt}" class="chart" role="img" aria-label="Days since each image was built">'
    ]
    for k, (name, age) in enumerate(rows):
        yy = 8 + k * (bar + gap)
        out.append(f'<text x="{left - 10}" y="{yy + 13}" class="lbl" text-anchor="end">{esc(name)}</text>')
        if age is None:
            out.append(f'<text x="{left}" y="{yy + 13}" class="lbl muted">unknown</text>')
            continue
        bw = max(2.0, x(age) - left)
        r = min(4.0, bw / 2)
        out.append(
            f'<path d="M{left},{yy} h{bw - r:.1f} a{r},{r} 0 0 1 {r},{r} v{bar - 2 * r} a{r},{r} 0 0 1 -{r},{r} '
            f'h-{bw - r:.1f} z" class="bar" tabindex="0" data-tip="{esc(name)}&#10;built {age_text(age)}" '
            f'aria-label="{esc(name)}: built {age_text(age)}"/>'
            f'<text x="{left + bw + 6:.1f}" y="{yy + 13}" class="lbl">{age} d</text>'
        )
    px = x(fresh_days)
    out.append(
        f'<line x1="{px:.1f}" x2="{px:.1f}" y1="2" y2="{hgt - 18}" class="policy"/>'
        f'<text x="{px:.1f}" y="{hgt - 4}" class="tick" text-anchor="middle">{fresh_days}-day policy</text></svg>'
    )
    return "".join(out)


# ---------------------------------------------------------------- page

ICON_OK = '<span class="pill ok" role="img" aria-label="Passing">&#10003; Passing</span>'
ICON_BAD = '<span class="pill bad" role="img" aria-label="Needs attention">&#10005; Needs attention</span>'


def pill(ok: bool, good: str, bad: str) -> str:
    cls, mark = ("ok", "&#10003;") if ok else ("bad", "&#10005;")
    return f'<span class="pill {cls}">{mark} {esc(good if ok else bad)}</span>'


def render(status: dict[str, Any]) -> str:
    s = summary(status)
    fresh_days = status["policy"]["freshDays"]
    fr, se, wo = s["fresh"], s["secure"], s["works"]
    n = s["images"]
    oldest = "—" if fr["oldest"] is None else ("today" if fr["oldest"] == 0 else f"{fr['oldest']} d")
    tiles = f"""
<section class="tiles" aria-label="Summary">
  <article class="tile">
    <h2>Recently built</h2>{ICON_OK if fr["ok"] else ICON_BAD}
    <p class="value">{esc(oldest)}</p>
    <p class="caption">age of the oldest published build (policy: {fresh_days} days)</p>
    <p class="detail">{fr["current"]} of {n} on the newest upstream release past a {status["policy"]["cooldownDays"]}-day
    cooldown. Built from pinned Wolfi packages and pinned upstream source commits.</p>
  </article>
  <article class="tile">
    <h2>Secure</h2>{ICON_OK if se["ok"] else ICON_BAD}
    <p class="value">{se["blocking"]}</p>
    <p class="caption">findings at or above {esc(status["policy"]["maxCveSeverity"])}, rescanned daily</p>
    <p class="detail">{se["total"]} lower-severity or accepted findings in all. {se["signed"]} of {n} signatures verified
    against the exact publishing identity. No shell, no package manager.</p>
  </article>
  <article class="tile">
    <h2>Actually works</h2>{ICON_OK if wo["ok"] else ICON_BAD}
    <p class="value">{wo["passed"]}/{wo["passed"] + wo["failed"] + wo["skipped"]}</p>
    <p class="caption">functional tests passing on the published digests</p>
    <p class="detail">Real traffic through HAProxy; SPIRE issuing identities in Docker and on Kubernetes, through the
    controller manager and the CSI driver. Hardened: read-only, no capabilities.</p>
  </article>
</section>"""

    rows = []
    for i in status["images"]:
        up, cv, fn = i["upstream"], i["cves"], i["functional"]
        c = cv["counts"]
        total = fn["passed"] + fn["failed"] + fn["skipped"]
        upstream = (
            pill(True, "current", "")
            if up["current"]
            else pill(False, "", f"{up['latest']} available" if up["latest"] else (up["note"] or "unknown"))
        )
        rows.append(
            f"""<tr>
  <th scope="row"><span class="name">{esc(i["name"])}</span><span class="sub">{esc(i["tag"])} ·
    <code title="{esc(i["digest"])}">{esc(i["digest"][7:19])}</code></span></th>
  <td data-label="Built">{esc(age_text(i["ageDays"]))}<span class="sub nowrap">{esc((i["builtAt"] or "")[:10])}</span></td>
  <td data-label="Upstream">{upstream}<span class="sub">{esc(up["source"])}{(" · " + esc(up["latest"])) if up["latest"] else ""}</span></td>
  <td data-label="CVEs">{pill(not cv["blocking"], "0 at or above high", f"{len(cv['blocking'])} at or above high")}
    <span class="sub num">C {c["critical"]} · H {c["high"]} · M {c["medium"]} · L {c["low"]}
    {f" · {len(cv['accepted'])} accepted" if cv["accepted"] else ""}</span></td>
  <td data-label="Signature">{pill(i["signature"] == "verified", "verified", "not verified")}</td>
  <td data-label="Functional tests">{pill(fn["ok"], f"{fn['passed']}/{total} passing", f"{fn['passed']}/{total} passing")}</td>
</tr>"""
        )
    hist_rows = "".join(
        f"<tr><td>{esc(h['date'])}</td><td class='num'>{sum(v['blocking'] for v in h['images'].values())}</td>"
        f"<td class='num'>{sum(v['total'] for v in h['images'].values())}</td></tr>"
        for h in reversed(status["history"])
    )
    missing = (
        f'<p class="warn">Not published yet: {esc(", ".join(status["missing"]))}.</p>'
        if status.get("missing")
        else ""
    )
    reg, ident, issuer = status["registry"], status["signing"]["identity"], status["signing"]["issuer"]
    example = status["images"][0] if status["images"] else {"name": "haproxy", "tag": "<tag>"}
    return f"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Image Status</title>
<meta name="description" content="Freshness, CVEs and functional test results for each published image, measured daily.">
<style>
:root {{
  color-scheme: light;
  --page: #f9f9f7; --surface: #fcfcfb; --ink: #0b0b0b; --ink-2: #52514e; --muted: #898781;
  --grid: #e1e0d9; --axis: #c3c2b7; --ring: rgba(11,11,11,0.10);
  --accent: #2a78d6; --context: #898781; --good: #0ca30c; --good-text: #006300; --critical: #d03b3b;
}}
@media (prefers-color-scheme: dark) {{
  :root:not([data-theme="light"]) {{
    color-scheme: dark;
    --page: #0d0d0d; --surface: #1a1a19; --ink: #f0efec; --ink-2: #c3c2b7; --muted: #898781;
    --grid: #2c2c2a; --axis: #383835; --ring: rgba(255,255,255,0.10);
    --accent: #3987e5; --good-text: #0ca30c;
  }}
}}
:root[data-theme="dark"] {{
  color-scheme: dark;
  --page: #0d0d0d; --surface: #1a1a19; --ink: #f0efec; --ink-2: #c3c2b7; --muted: #898781;
  --grid: #2c2c2a; --axis: #383835; --ring: rgba(255,255,255,0.10);
  --accent: #3987e5; --good-text: #0ca30c;
}}
* {{ box-sizing: border-box; }}
body {{ margin: 0; background: var(--page); color: var(--ink);
  font: 15px/1.5 system-ui, -apple-system, "Segoe UI", sans-serif; }}
main {{ max-width: 1080px; margin: 0 auto; padding: 32px 16px 48px; }}
h1 {{ font-size: 28px; margin: 0 0 4px; }}
h2 {{ font-size: 16px; margin: 0; }}
h3 {{ font-size: 15px; margin: 0 0 8px; }}
.lede {{ color: var(--ink-2); margin: 0 0 24px; max-width: 70ch; }}
.muted, .sub, .caption, .tick {{ color: var(--muted); }}
.sub {{ display: block; font-size: 13px; }}
.tiles {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(260px, 1fr)); gap: 16px; margin-bottom: 32px; }}
.tile, .card {{ background: var(--surface); border: 1px solid var(--ring); border-radius: 10px; padding: 18px; }}
.tile h2 {{ display: inline; margin-right: 8px; }}
.value {{ font-size: 48px; font-weight: 600; margin: 8px 0 0; line-height: 1.1; }}
.caption {{ margin: 2px 0 10px; font-size: 13px; }}
.detail {{ margin: 0; color: var(--ink-2); font-size: 14px; }}
.pill {{ display: inline-block; font-size: 12px; font-weight: 600; padding: 1px 8px; border-radius: 999px;
  border: 1px solid currentColor; white-space: nowrap; }}
.pill.ok {{ color: var(--good-text); }}
.pill.bad {{ color: var(--critical); }}
.table-wrap {{ overflow-x: auto; background: var(--surface); border: 1px solid var(--ring); border-radius: 10px; }}
table {{ border-collapse: collapse; width: 100%; min-width: 760px; }}
th, td {{ text-align: left; vertical-align: top; padding: 12px 14px; border-top: 1px solid var(--grid); }}
thead th {{ border-top: 0; font-size: 13px; color: var(--ink-2); font-weight: 600; }}
.name {{ font-weight: 600; }}
.num {{ font-variant-numeric: tabular-nums; }}
.nowrap {{ white-space: nowrap; }}
@media (max-width: 720px) {{
  .table-wrap {{ overflow: visible; background: none; border: 0; }}
  .images, .images tbody, .images tr, .images th, .images td {{ display: block; min-width: 0; }}
  .images thead {{ display: none; }}
  .images tr {{ background: var(--surface); border: 1px solid var(--ring); border-radius: 10px; margin-bottom: 12px; padding: 6px 0; }}
  .images th, .images td {{ border-top: 0; padding: 6px 14px; }}
  .images td::before {{ content: attr(data-label); display: block; font-size: 12px; color: var(--muted); }}
}}
code {{ font: 12px ui-monospace, SFMono-Regular, Menlo, monospace; }}
section {{ margin-bottom: 32px; }}
.charts {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(320px, 1fr)); gap: 16px; }}
.chart {{ width: 100%; height: auto; display: block; overflow: visible; }}
.chart text {{ font: 13px system-ui, -apple-system, "Segoe UI", sans-serif; }}
.chart .tick {{ fill: var(--muted); }}
.chart .lbl {{ fill: var(--ink-2); }}
.chart .lbl.muted {{ fill: var(--muted); }}
.chart .grid {{ stroke: var(--grid); stroke-width: 1; }}
.chart .axis {{ stroke: var(--axis); stroke-width: 1; }}
.chart .accent {{ fill: none; stroke: var(--accent); stroke-width: 2; stroke-linejoin: round; stroke-linecap: round; }}
.chart .context {{ fill: none; stroke: var(--context); stroke-width: 2; stroke-linejoin: round; stroke-linecap: round; }}
.chart .accent-dot {{ fill: var(--accent); stroke: var(--surface); stroke-width: 2; }}
.chart .context-dot {{ fill: var(--context); stroke: var(--surface); stroke-width: 2; }}
.chart .bar {{ fill: var(--accent); }}
.chart .bar:hover, .chart .bar:focus {{ opacity: .8; outline: none; }}
.chart .policy {{ stroke: var(--ink-2); stroke-width: 1; }}
.chart .hit {{ fill: transparent; }}
.chart .hit:focus {{ outline: none; fill: var(--grid); opacity: .4; }}
.legend {{ display: flex; gap: 16px; font-size: 13px; color: var(--ink-2); margin: 0 0 8px; }}
.key {{ display: inline-block; width: 14px; height: 2px; vertical-align: middle; margin-right: 6px; }}
details {{ margin-top: 8px; font-size: 13px; }}
details table {{ min-width: 0; }}
pre {{ background: var(--surface); border: 1px solid var(--ring); border-radius: 10px; padding: 14px; overflow-x: auto;
  font: 12.5px/1.5 ui-monospace, SFMono-Regular, Menlo, monospace; }}
.warn {{ color: var(--critical); }}
#tip {{ position: fixed; pointer-events: none; background: var(--surface); color: var(--ink); border: 1px solid var(--ring);
  border-radius: 8px; padding: 6px 10px; font-size: 13px; white-space: pre; box-shadow: 0 4px 16px rgba(0,0,0,.12);
  display: none; z-index: 10; }}
footer {{ color: var(--muted); font-size: 13px; }}
a {{ color: var(--accent); }}
</style>
</head>
<body>
<main>
<h1>wolfi-platform-images</h1>
<p class="lede">Minimal container images built from pinned Wolfi packages and pinned upstream source. Nothing is
published until it passes the CVE gate and its functional tests, and the published digest is exactly the one that was
tested. This page is measured daily against the published images.</p>
{missing}
{tiles}
<section aria-labelledby="images-h">
<h3 id="images-h">Images</h3>
<div class="table-wrap"><table class="images">
<thead><tr><th scope="col">Image</th><th scope="col">Built</th><th scope="col">Upstream</th>
<th scope="col">CVEs (critical · high · medium · low)</th><th scope="col">Signature</th>
<th scope="col">Functional tests</th></tr></thead>
<tbody>{"".join(rows)}</tbody></table></div>
</section>
<section class="charts" aria-label="Trends">
  <div class="card">
    <h3>CVE findings across all images, by daily scan</h3>
    <p class="legend"><span><span class="key" style="background:var(--accent)"></span>At or above high</span>
    <span><span class="key" style="background:var(--context)"></span>All findings</span></p>
    {findings_chart(status["history"])}
    <details><summary>Show data</summary><table><thead><tr><th>Date</th><th>At or above high</th><th>All</th></tr>
    </thead><tbody>{hist_rows}</tbody></table></details>
  </div>
  <div class="card">
    <h3>Days since each published image was built</h3>
    {age_chart(status["images"], fresh_days)}
  </div>
</section>
<section aria-labelledby="verify-h">
<h3 id="verify-h">Verify it yourself</h3>
<pre>cosign verify \\
  --certificate-identity {esc(ident)} \\
  --certificate-oidc-issuer {esc(issuer)} \\
  {esc(reg)}/{esc(example["name"])}:{esc(example["tag"])}</pre>
</section>
<footer>Measured {esc(status["generatedAt"])} by
<a href="{esc(status["source"]["repository"])}/actions/runs/{esc(status["source"]["run"])}">this workflow run</a> ·
<a href="status.json">status.json</a> · <a href="{esc(status["source"]["repository"])}">source</a></footer>
</main>
<div id="tip" role="tooltip"></div>
<script>
(() => {{
  const tip = document.getElementById("tip");
  const show = (el, x, y) => {{
    tip.textContent = el.getAttribute("data-tip");
    tip.style.display = "block";
    const w = tip.offsetWidth;
    tip.style.left = Math.min(x + 12, window.innerWidth - w - 8) + "px";
    tip.style.top = (y + 12) + "px";
  }};
  document.querySelectorAll("[data-tip]").forEach((el) => {{
    el.addEventListener("pointermove", (e) => show(el, e.clientX, e.clientY));
    el.addEventListener("pointerleave", () => (tip.style.display = "none"));
    el.addEventListener("focus", () => {{ const r = el.getBoundingClientRect(); show(el, r.left, r.top); }});
    el.addEventListener("blur", () => (tip.style.display = "none"));
  }});
}})();
</script>
</body>
</html>
"""


def write_site(status: dict[str, Any], out: Path) -> None:
    out.mkdir(parents=True, exist_ok=True)
    (out / "index.html").write_text(render(status))
    (out / "status.json").write_text(json.dumps(status, indent=2) + "\n")
    badges = out / "badges"
    badges.mkdir(exist_ok=True)
    fresh_days = status["policy"]["freshDays"]
    for img in status["images"]:
        for name, svg in image_badges(img, fresh_days).items():
            (badges / name).write_text(svg)
    s = summary(status)
    total = s["works"]["passed"] + s["works"]["failed"] + s["works"]["skipped"]
    oldest = s["fresh"]["oldest"]
    (badges / "fresh.svg").write_text(
        badge("oldest build", age_text(oldest), GOOD if s["fresh"]["ok"] else WARN)
    )
    (badges / "secure.svg").write_text(
        badge("CVEs ≥ high", str(s["secure"]["blocking"]), GOOD if s["secure"]["ok"] else CRIT)
    )
    (badges / "works.svg").write_text(
        badge(
            "functional tests", f"{s['works']['passed']}/{total} passing", GOOD if s["works"]["ok"] else CRIT
        )
    )
