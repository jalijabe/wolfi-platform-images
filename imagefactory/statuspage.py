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


def pill_button(ok: bool, text: str, row: str, section: str, label: str) -> str:
    """A status pill that opens the image's detail row at a section."""
    cls, mark = ("ok", "&#10003;") if ok else ("bad", "&#10005;")
    return (
        f'<button type="button" class="pill {cls} opener" data-row="{esc(row)}" data-section="{esc(section)}" '
        f'aria-controls="{esc(row)}" aria-expanded="false" title="{esc(label)}">{mark} {esc(text)}</button>'
    )


COPY_ICON = (
    '<svg class="i-copy" viewBox="0 0 16 16" width="16" height="16" aria-hidden="true"><path fill="currentColor" '
    'd="M5 1.75C5 .78 5.78 0 6.75 0h7.5C15.22 0 16 .78 16 1.75v7.5c0 .97-.78 1.75-1.75 1.75h-7.5C5.78 11 5 10.22 5 '
    "9.25Zm1.75-.25a.25.25 0 0 0-.25.25v7.5c0 .14.11.25.25.25h7.5a.25.25 0 0 0 .25-.25v-7.5a.25.25 0 0 0-.25-.25ZM2 "
    "5.75C2 5.34 2.34 5 2.75 5h.5a.75.75 0 0 1 0 1.5h-.5a.25.25 0 0 0-.25.25v7.5c0 .14.11.25.25.25h7.5a.25.25 0 0 0 "
    '.25-.25v-.5a.75.75 0 0 1 1.5 0v.5c0 .97-.78 1.75-1.75 1.75h-7.5C1.78 16 1 15.22 1 14.25v-7.5C1 5.78 1.78 5 2.75 5Z"/>'
    '</svg><svg class="i-check" viewBox="0 0 16 16" width="16" height="16" aria-hidden="true"><path fill="currentColor" '
    'd="M13.78 4.22a.75.75 0 0 1 0 1.06l-7.25 7.25a.75.75 0 0 1-1.06 0L2.22 9.28a.75.75 0 0 1 1.06-1.06L6 10.94l6.72-6.72a'
    '.75.75 0 0 1 1.06 0Z"/></svg>'
)


def codebox(text: str, what: str) -> str:
    """A command in a box, with a copy button that appears on hover or focus."""
    return (
        f'<div class="codebox"><pre tabindex="0">{esc(text)}</pre>'
        f'<button type="button" class="copy" aria-label="Copy {esc(what)}" title="Copy">{COPY_ICON}'
        f'<span class="copied" aria-hidden="true">Copied</span></button></div>'
    )


def commands(img: dict[str, Any], status: dict[str, Any]) -> tuple[str, str]:
    ref = f"{img['reference']}@{img['digest']}"
    ident, issuer = status["signing"]["identity"], status["signing"]["issuer"]
    verify = f"cosign verify \\\n  --certificate-identity {ident} \\\n  --certificate-oidc-issuer {issuer} \\\n  {ref}"
    return f"docker pull {ref}", verify


OUTCOME = {
    "passed": ('<span class="mark ok" aria-hidden="true">&#10003;</span>', "Passed"),
    "failed": ('<span class="mark bad" aria-hidden="true">&#10005;</span>', "Failed"),
    "skipped": ('<span class="mark skip" aria-hidden="true">&#8211;</span>', "Skipped"),
}


def tests_panel(fn: dict[str, Any]) -> str:
    suites = fn.get("suites") or []
    if not suites:
        return '<p class="muted">No functional-test results for this digest.</p>'
    out = []
    for suite in suites:
        items = []
        for t in suite["tests"]:
            mark, word = OUTCOME.get(t["outcome"], OUTCOME["skipped"])
            doc = f'<span class="sub">{esc(t["doc"])}</span>' if t["doc"] else ""
            items.append(
                f'<li>{mark}<span class="sr">{word}: </span><span>{esc(t["title"])}'
                f'<code class="testid">{esc(t["name"])}</code>{doc}</span></li>'
            )
        out.append(
            f'<div class="suite"><p class="suite-name"><code>{esc(suite["file"])}</code></p>'
            f'<p class="sub">{esc(suite["summary"])}</p><ul class="tests">{"".join(items)}</ul></div>'
        )
    return "".join(out)


def cves_panel(cv: dict[str, Any]) -> str:
    found = cv.get("findings") or []
    if not found:
        return '<p class="muted">No findings in the latest scan.</p>'
    rows = []
    for f in found:
        vid = f'<a href="{esc(f["url"])}" rel="noopener">{esc(f["id"])}</a>' if f["url"] else esc(f["id"])
        if f["blocking"]:
            state = '<span class="pill bad">&#10005; Blocking</span>'
        elif f["accepted"]:
            state = '<span class="pill note">Accepted</span>'
        else:
            state = '<span class="muted">Below the gate</span>'
        fix = f["fixState"] + (f" ({', '.join(f['fixedIn'])})" if f["fixedIn"] else "")
        reason = (
            f'<tr class="reason"><td colspan="6"><strong>Why it is accepted:</strong> {esc(f["accepted"])}</td></tr>'
            if f["accepted"]
            else ""
        )
        rows.append(
            f'<tr><td data-label="Severity">{esc(f["severity"].capitalize())}</td><td data-label="ID">{vid}</td>'
            f'<td data-label="Package"><code>{esc(f["package"])}</code></td>'
            f'<td data-label="Version" class="num">{esc(f["version"])}</td><td data-label="Fix">{esc(fix)}</td>'
            f'<td data-label="Status">{state}</td></tr>{reason}'
        )
    return (
        '<div class="scroll"><table class="findings"><thead><tr><th>Severity</th><th>ID</th><th>Package</th>'
        f"<th>Version</th><th>Fix</th><th>Status</th></tr></thead><tbody>{''.join(rows)}</tbody></table></div>"
    )


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
        row_id = f"d-{i['name']}"
        pull, verify = commands(i, status)
        blocking = len(cv["blocking"])
        rows.append(
            f"""<tr class="main">
  <th scope="row"><button type="button" class="expand opener" data-row="{esc(row_id)}" data-section="pull"
    aria-controls="{esc(row_id)}" aria-expanded="false" aria-label="Details for {esc(i["name"])}"><span aria-hidden="true">&#9656;</span></button><span
    class="name">{esc(i["name"])}</span><span class="sub">{esc(i["tag"])} ·
    <code title="{esc(i["digest"])}">{esc(i["digest"][7:19])}</code></span></th>
  <td data-label="Built">{esc(age_text(i["ageDays"]))}<span class="sub nowrap">{esc((i["builtAt"] or "")[:10])}</span></td>
  <td data-label="Upstream">{upstream}<span class="sub">{esc(up["source"])}{(" · " + esc(up["latest"])) if up["latest"] else ""}</span></td>
  <td data-label="CVEs">{pill_button(not blocking, "0 at or above high" if not blocking else f"{blocking} at or above high", row_id, "cves", "Show the findings")}
    <span class="sub num">C {c["critical"]} · H {c["high"]} · M {c["medium"]} · L {c["low"]}
    {f" · {len(cv['accepted'])} accepted" if cv["accepted"] else ""}</span></td>
  <td data-label="Signature">{pill(i["signature"] == "verified", "verified", "not verified")}</td>
  <td data-label="Functional tests">{pill_button(fn["ok"], f"{fn['passed']}/{total} passing", row_id, "tests", "Show what was tested")}</td>
</tr>
<tr class="detail" id="{esc(row_id)}"><td colspan="6"><div class="panel">
  <section class="part" data-part="pull" tabindex="-1" aria-label="Pull {esc(i["name"])}">
    <h4>Pull</h4>{codebox(pull, f"the pull command for {i['name']}")}
    <h4>Verify</h4>{codebox(verify, f"the verify command for {i['name']}")}
  </section>
  <section class="part" data-part="cves" tabindex="-1" aria-label="CVE findings for {esc(i["name"])}">
    <h4>CVE findings <span class="muted">· latest scan, gate at {esc(status["policy"]["maxCveSeverity"])}</span></h4>
    {cves_panel(cv)}
  </section>
  <section class="part" data-part="tests" tabindex="-1" aria-label="Functional tests for {esc(i["name"])}">
    <h4>Functional tests <span class="muted">· run against this digest</span></h4>
    {tests_panel(fn)}
  </section>
</div></td></tr>"""
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
<script>document.documentElement.classList.add("js");</script>
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
.pill.note {{ color: var(--ink-2); }}
button.pill {{ font-family: inherit; background: none; cursor: pointer; }}
button.pill:hover {{ background: color-mix(in srgb, currentColor 10%, transparent); }}
button:focus-visible, pre:focus-visible, .part:focus-visible {{ outline: 2px solid var(--accent); outline-offset: 2px; }}
.expand {{ font: inherit; background: none; border: 0; color: var(--ink-2); cursor: pointer; width: 24px; height: 24px;
  margin: -2px 4px 0 -6px; padding: 0; border-radius: 6px; vertical-align: middle; }}
.expand:hover {{ background: var(--grid); }}
.expand span {{ display: inline-block; transition: transform .15s; }}
.expand[aria-expanded="true"] span {{ transform: rotate(90deg); }}
.js tr.detail {{ display: none; }}
.js tr.detail.open {{ display: table-row; }}
tr.detail > td {{ border-top: 0; padding-top: 0; }}
.panel {{ display: grid; grid-template-columns: minmax(0, 1fr); gap: 18px; padding: 14px; background: var(--page); border: 1px solid var(--ring); border-radius: 10px; }}
.part {{ min-width: 0; }}
.part h4 {{ font-size: 14px; margin: 0 0 8px; }}
.part h4 + .codebox + h4 {{ margin-top: 12px; }}
.part.flash {{ animation: flash 1.2s ease-out; }}
@keyframes flash {{ from {{ box-shadow: 0 0 0 3px color-mix(in srgb, var(--accent) 45%, transparent); }} to {{ box-shadow: 0 0 0 3px transparent; }} }}
.codebox {{ position: relative; }}
.codebox pre {{ margin: 0; padding-right: 48px; white-space: pre-wrap; overflow-wrap: anywhere; }}
.copy {{ position: absolute; top: 8px; right: 8px; display: flex; align-items: center; gap: 6px; height: 30px; min-width: 30px;
  justify-content: center; padding: 0 7px; border-radius: 6px; border: 1px solid var(--ring); background: var(--surface);
  color: var(--ink-2); cursor: pointer; opacity: 0; transition: opacity .12s; }}
.codebox:hover .copy, .codebox:focus-within .copy, .copy.done {{ opacity: 1; }}
@media (hover: none) {{ .copy {{ opacity: 1; }} }}
.copy:hover {{ color: var(--ink); background: var(--grid); }}
.copy .i-check, .copy .copied {{ display: none; }}
.copy.done {{ color: var(--good-text); }}
.copy.done .i-copy {{ display: none; }}
.copy.done .i-check, .copy.done .copied {{ display: inline; }}
.copied {{ font-size: 12px; font-weight: 600; }}
.suite + .suite {{ margin-top: 14px; }}
.suite-name {{ margin: 0; }}
.tests {{ list-style: none; margin: 6px 0 0; padding: 0; }}
.tests li {{ display: flex; gap: 8px; padding: 6px 0; border-top: 1px solid var(--grid); }}
.tests li:first-child {{ border-top: 0; }}
.mark {{ width: 16px; flex: none; font-weight: 700; text-align: center; }}
.mark.ok {{ color: var(--good-text); }}
.mark.bad {{ color: var(--critical); }}
.mark.skip {{ color: var(--muted); }}
.testid {{ margin-left: 8px; color: var(--muted); }}
.sr {{ position: absolute; width: 1px; height: 1px; overflow: hidden; clip-path: inset(50%); white-space: nowrap; }}
.scroll {{ overflow-x: auto; }}
table.findings {{ min-width: 640px; font-size: 13px; }}
table.findings th, table.findings td {{ padding: 6px 10px; }}
tr.reason td {{ border-top: 0; color: var(--ink-2); padding-top: 0; }}
.table-wrap {{ overflow-x: auto; background: var(--surface); border: 1px solid var(--ring); border-radius: 10px; }}
table {{ border-collapse: collapse; width: 100%; min-width: 760px; }}
th, td {{ text-align: left; vertical-align: top; padding: 12px 14px; border-top: 1px solid var(--grid); }}
thead th {{ border-top: 0; font-size: 13px; color: var(--ink-2); font-weight: 600; }}
.name {{ font-weight: 600; }}
.num {{ font-variant-numeric: tabular-nums; }}
.nowrap {{ white-space: nowrap; }}
@media (max-width: 720px) {{
  .table-wrap {{ overflow: visible; background: none; border: 0; }}
  .images, .images > tbody, .images > tbody > tr, .images > tbody > tr > th, .images > tbody > tr > td {{ display: block; min-width: 0; }}
  .images > thead {{ display: none; }}
  .images > tbody > tr {{ background: var(--surface); border: 1px solid var(--ring); border-radius: 10px; margin-bottom: 12px; padding: 6px 0; }}
  .images > tbody > tr > th, .images > tbody > tr > td {{ border-top: 0; padding: 6px 14px; }}
  .images > tbody > tr > td::before {{ content: attr(data-label); display: block; font-size: 12px; color: var(--muted); }}
  .images > tbody > tr.detail {{ margin-top: -10px; padding: 0; border-top-left-radius: 0; border-top-right-radius: 0; }}
  .js .images > tbody > tr.detail.open {{ display: block; }}
  .images > tbody > tr.detail > td {{ padding: 0 8px 8px; }}
  .images > tbody > tr.detail > td::before {{ content: none; }}
  table.findings, table.findings tbody, table.findings tr, table.findings td {{ display: block; min-width: 0; }}
  table.findings thead {{ display: none; }}
  table.findings tr {{ border-top: 1px solid var(--grid); padding: 6px 0; }}
  table.findings tr.reason {{ border-top: 0; padding-top: 0; }}
  table.findings td {{ border: 0; padding: 2px 0; overflow-wrap: anywhere; }}
  table.findings td[data-label]::before {{ content: attr(data-label) ": "; color: var(--muted); }}
  .testid {{ display: block; margin-left: 0; overflow-wrap: anywhere; }}
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
{codebox(f"cosign verify \\\n  --certificate-identity {ident} \\\n  --certificate-oidc-issuer {issuer} \\\n  {reg}/{example['name']}:{example['tag']}", "the verify command")}
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
  const controls = (row) => document.querySelectorAll(`.opener[data-row="${{row}}"]`);
  const setOpen = (row, open) => {{
    document.getElementById(row).classList.toggle("open", open);
    controls(row).forEach((c) => c.setAttribute("aria-expanded", String(open)));
  }};
  const reveal = (row, part) => {{
    const el = document.querySelector(`#${{CSS.escape(row)}} [data-part="${{part}}"]`);
    if (!el) return;
    el.scrollIntoView({{ block: "nearest", behavior: "smooth" }});
    el.focus({{ preventScroll: true }});
    el.classList.remove("flash"); void el.offsetWidth; el.classList.add("flash");
  }};
  document.querySelectorAll(".opener").forEach((btn) => {{
    btn.addEventListener("click", () => {{
      const row = btn.dataset.row, part = btn.dataset.section;
      const isOpen = document.getElementById(row).classList.contains("open");
      if (btn.classList.contains("expand")) {{ setOpen(row, !isOpen); return; }}
      if (isOpen && btn.dataset.shown === "1") {{ setOpen(row, false); btn.dataset.shown = ""; return; }}
      controls(row).forEach((c) => (c.dataset.shown = ""));
      setOpen(row, true); btn.dataset.shown = "1"; reveal(row, part);
    }});
  }});
  const copyText = async (text) => {{
    try {{ await navigator.clipboard.writeText(text); return true; }} catch (e) {{
      const ta = document.createElement("textarea");
      ta.value = text; ta.setAttribute("readonly", ""); ta.style.position = "fixed"; ta.style.opacity = "0";
      document.body.appendChild(ta); ta.select();
      const ok = document.execCommand("copy"); ta.remove(); return ok;
    }}
  }};
  document.querySelectorAll(".codebox .copy").forEach((btn) => {{
    const label = btn.getAttribute("aria-label");
    btn.addEventListener("click", async () => {{
      if (!(await copyText(btn.parentElement.querySelector("pre").innerText))) return;
      btn.classList.add("done"); btn.setAttribute("aria-label", "Copied"); btn.title = "Copied";
      clearTimeout(btn._t);
      btn._t = setTimeout(() => {{ btn.classList.remove("done"); btn.setAttribute("aria-label", label); btn.title = "Copy"; }}, 1600);
    }});
  }});
  const hash = location.hash.slice(1);
  if (hash && document.getElementById(hash) && document.getElementById(hash).classList.contains("detail")) setOpen(hash, true);
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
