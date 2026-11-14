"""A local HTML page showing what PR autopilot did and how many tokens it used.

Built from events.jsonl (every log event) and usage.jsonl (one line per Claude
run) after each run. Open it with `python3 reviewer.py --dashboard`; the page
reloads itself every minute while you are not reading a PR's details.
"""
from __future__ import annotations

import collections
import html
import json
import pathlib
import time

DAYS = 30           # how far back the page looks
CHART_DAYS = 14
DECISIONS = ("APPROVED", "BLOCKED", "MANUAL", "GAVE UP", "SKIPPED", "REVIEWING", "ERROR")
LEFT_TO_YOU = ("MANUAL", "GAVE UP")
PROBLEMS = ("ERROR", "WARN", "GAVE UP", "AUDIT MISS", "AUTH", "GAP")
# Reasons the rules give for a full review; any other reason came from the quick review.
# Used for events logged before REVIEWING carried a "route:" line.
RULE_REASONS = ("why: changes GitHub Actions workflows", "why: touches ", "why: diff too large")


def route_of(e: dict) -> str:
    details = e.get("details", [])
    for d in details:
        if d.startswith("route: "):
            return d[len("route: "):]
    why = next((d for d in details if d.startswith("why: ")), "")
    return "rules" if why.startswith(RULE_REASONS) else "quick"


def routing(events: list[dict]) -> dict:
    """How each full review was routed, joined to what the full review decided."""
    pending: dict[str, str] = {}
    out = {r: {"APPROVED": 0, "BLOCKED": 0} for r in ("rules", "quick", "audit")}
    misses = []
    for e in events:
        key, _ = split_subject(e["subject"])
        if e["kind"] == "REVIEWING":
            pending[key] = route_of(e)
        elif e["kind"] in ("APPROVED", "BLOCKED") and key in pending \
                and any(d.startswith("full review") for d in e.get("details", [])):
            route = pending.pop(key)
            out[route][e["kind"]] += 1
            if route == "audit" and e["kind"] == "BLOCKED":
                misses.append(e)
    return {"counts": out, "misses": misses}


def load(path: pathlib.Path | None, since: float) -> list[dict]:
    if path is None or not path.exists():
        return []
    out = []
    for line in path.read_text().splitlines():
        try:
            row = json.loads(line)
        except ValueError:
            continue
        if row.get("ts", 0) >= since:
            out.append(row)
    return out


def split_subject(subject: str) -> tuple[str, str]:
    key, _, title = subject.partition("  ")
    return key.strip(), title.strip()


def tokens(u: dict) -> int:
    return u.get("input", 0) + u.get("output", 0) + u.get("cache_read", 0) + u.get("cache_write", 0)


def fmt_tokens(n: float) -> str:
    return f"{n / 1e6:.1f}M" if n >= 1e6 else f"{n / 1e3:.0f}k" if n >= 1e3 else f"{n:.0f}"


def fmt_cost(c: float) -> str:
    return f"${c:,.2f}"


def ago(ts: float, now: float) -> str:
    s = now - ts
    return ("just now" if s < 60 else f"{s // 60:.0f} min ago" if s < 3600
            else f"{s // 3600:.0f} h ago" if s < 86400 else time.strftime("%b %d", time.localtime(ts)))


def esc(s) -> str:
    return html.escape(str(s))


def badge(kind: str) -> str:
    return f'<span class="badge k-{kind.replace(" ", "-").lower()}">{esc(kind)}</span>'


def write(path: pathlib.Path, events_file: pathlib.Path | None, usage_file: pathlib.Path | None,
          running: int) -> None:
    now = time.time()
    events = load(events_file, now - DAYS * 86400)
    usage = load(usage_file, now - DAYS * 86400)
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(".tmp")
    tmp.write_text(render(events, usage, running, now))
    tmp.replace(path)


def render(events: list[dict], usage: list[dict], running: int, now: float) -> str:
    week = now - 7 * 86400
    today = time.mktime(time.localtime(now)[:3] + (0, 0, 0, 0, 0, -1))

    def count(kinds, since):
        return sum(1 for e in events if e["kind"] in kinds and e["ts"] >= since)

    def spend(since):
        rows = [u for u in usage if u["ts"] >= since]
        return sum(map(tokens, rows)), sum(u.get("cost_usd", 0) for u in rows)

    tok_week, cost_week = spend(week)
    tok_today, cost_today = spend(today)
    tiles = [
        ("Approved", count(("APPROVED",), week), f"{count(('APPROVED',), today)} today", "good"),
        ("Blocked", count(("BLOCKED",), week), f"{count(('BLOCKED',), today)} today", "warn"),
        ("Left to you", count(LEFT_TO_YOU, week), f"{count(LEFT_TO_YOU, today)} today", "warn"),
        ("Errors", count(("ERROR",), week), f"{count(('ERROR',), today)} today", "bad"),
        ("Tokens", fmt_tokens(tok_week), f"{fmt_tokens(tok_today)} today", ""),
        ("API-price equivalent", fmt_cost(cost_week), f"{fmt_cost(cost_today)} today", ""),
    ]
    tiles_html = "".join(
        f'<div class="tile {cls}"><div class="tlabel">{esc(label)}</div>'
        f'<div class="tvalue">{esc(value)}</div><div class="tsub">{esc(sub)}</div></div>'
        for label, value, sub, cls in tiles)

    # Daily spend, split by quick and full reviews.
    days = []
    for i in range(CHART_DAYS - 1, -1, -1):
        start = today - i * 86400
        rows = [u for u in usage if start <= u["ts"] < start + 86400]
        days.append((start, {k: (sum(tokens(u) for u in rows if u.get("kind") == k),
                                 sum(u.get("cost_usd", 0) for u in rows if u.get("kind") == k))
                             for k in ("quick", "full")}))
    top = max([d["quick"][1] + d["full"][1] for _, d in days] + [0.01])
    bars = []
    for start, d in days:
        label = time.strftime("%d", time.localtime(start))
        tip = (f"{time.strftime('%b %d', time.localtime(start))}: quick {fmt_tokens(d['quick'][0])} tokens "
               f"({fmt_cost(d['quick'][1])}), full {fmt_tokens(d['full'][0])} tokens ({fmt_cost(d['full'][1])})")
        segs = "".join(f'<div class="seg {k}" style="height:{d[k][1] / top * 100:.1f}%"></div>'
                       for k in ("full", "quick"))
        bars.append(f'<div class="bar" title="{esc(tip)}"><div class="stack">{segs}</div>'
                    f'<div class="blabel">{label}</div></div>')

    # Spend by kind and model.
    groups: dict[tuple, list[dict]] = collections.defaultdict(list)
    for u in usage:
        kind = u.get("kind", "?") + (" on Datum" if u.get("runner") == "datum" else "")
        groups[(kind, ", ".join(u.get("models") or ["?"]))].append(u)
    usage_rows = []
    for (kind, models), rows in sorted(groups.items(), key=lambda kv: -sum(u.get("cost_usd", 0) for u in kv[1])):
        n = len(rows)
        cost = sum(u.get("cost_usd", 0) for u in rows)
        usage_rows.append(
            f"<tr><td>{esc(kind)}</td><td>{esc(models)}</td><td class=num>{n}</td>"
            f"<td class=num>{fmt_tokens(sum(u.get('input', 0) + u.get('cache_write', 0) for u in rows))}</td>"
            f"<td class=num>{fmt_tokens(sum(u.get('cache_read', 0) for u in rows))}</td>"
            f"<td class=num>{fmt_tokens(sum(u.get('output', 0) for u in rows))}</td>"
            f"<td class=num>{fmt_cost(cost)}</td><td class=num>{fmt_cost(cost / n)}</td>"
            f"<td class=num>{sum(u.get('turns', 0) for u in rows) / n:.0f}</td>"
            f"<td class=num>{sum(u.get('seconds', 0) for u in rows) / n / 60:.1f} min</td></tr>")

    # One row per PR: its latest decision, with the history underneath.
    per_pr: dict[str, list[dict]] = collections.defaultdict(list)
    for e in events:
        key, _ = split_subject(e["subject"])
        if "#" in key and "/" in key:
            per_pr[key].append(e)
    pr_usage: dict[str, list[dict]] = collections.defaultdict(list)
    for u in usage:
        pr_usage[f"{u.get('repo')}#{u.get('pr')}"].append(u)
    def latest(evs: list[dict]) -> dict:
        return ([e for e in evs if e["kind"] in DECISIONS] or evs)[-1]

    datum_tag = ' <span class="badge runner-datum" title="Reviewed in a Kata VM on Datum Compute">Datum</span>'
    pr_rows = []
    for key, evs in sorted(per_pr.items(), key=lambda kv: -latest(kv[1])["ts"]):
        last = latest(evs)
        title = next((split_subject(e["subject"])[1] for e in reversed(evs) if split_subject(e["subject"])[1]), "")
        repo, _, num = key.partition("#")
        url = f"https://github.com/{repo}/pull/{num}"
        detail = "\n".join(d for d in last.get("details", []) if not d.startswith("https://"))
        how, _, rest = detail.partition("\n")
        summary, _, more = rest.partition("\n")
        spent = pr_usage.get(key, [])
        history = "".join(
            f'<div class="hist">{badge(e["kind"])} <span class="muted">'
            f'{esc(time.strftime("%b %d %H:%M", time.localtime(e["ts"])))}</span>'
            f'<pre>{esc(chr(10).join(d for d in e.get("details", []) if not d.startswith("https://")))}</pre></div>'
            for e in evs)
        pr_rows.append(
            f'<tr data-kind="{esc(last["kind"])}"><td class="when" title="'
            f'{esc(time.strftime("%Y-%m-%d %H:%M", time.localtime(last["ts"])))}">{esc(ago(last["ts"], now))}</td>'
            f"<td>{badge(last['kind'])}</td>"
            f'<td><a href="{esc(url)}" target="_blank">{esc(key)}</a> <span class="muted small">{esc(how)}</span>'
            f'{datum_tag if "on Datum" in how else ""}'
            f'<div class="title">{esc(title)}</div><div class="summary">{esc(summary)}</div>'
            f'<details><summary>details and history</summary><pre>{esc(more)}</pre>{history}</details></td>'
            f"<td class=num>{fmt_tokens(sum(map(tokens, spent))) if spent else ''}</td>"
            f"<td class=num>{fmt_cost(sum(u.get('cost_usd', 0) for u in spent)) if spent else ''}</td></tr>")
    kinds_seen = [k for k in DECISIONS if any(latest(r)["kind"] == k for r in per_pr.values())]
    filters = "".join(f'<button data-k="{esc(k)}">{esc(k.title())}</button>' for k in kinds_seen)

    rt = routing(events)
    q, a = rt["counts"]["quick"], rt["counts"]["audit"]
    q_total, a_total = q["APPROVED"] + q["BLOCKED"], a["APPROVED"] + a["BLOCKED"]
    pct = lambda n, d: f"{n / d:.0%}" if d else "–"
    miss_rows = "".join(
        f'<li><a href="https://github.com/{esc(split_subject(e["subject"])[0].replace("#", "/pull/"))}" '
        f'target="_blank">{esc(split_subject(e["subject"])[0])}</a> '
        f'<span class="muted">{esc(time.strftime("%b %d", time.localtime(e["ts"])))}</span></li>'
        for e in rt["misses"][::-1])
    routing_html = (
        f"<tr><td>Quick review escalated to a full review</td><td class=num>{q_total}</td>"
        f"<td class=num>{q['BLOCKED']}</td><td class=num>{q['APPROVED']}</td>"
        f"<td class=muted>{pct(q['APPROVED'], q_total)} were approved anyway: the cost of a cautious quick review</td></tr>"
        f"<tr><td>Quick approvals audited at random</td><td class=num>{a_total}</td>"
        f"<td class=num>{a['BLOCKED']}</td><td class=num>{a['APPROVED']}</td>"
        f"<td class=muted>{pct(a['BLOCKED'], a_total)} misses: blockers the quick review would have approved"
        + (f" (with none found, the miss rate is likely under {3 / a_total:.0%})" if a_total and not a["BLOCKED"] else "")
        + "</td></tr>")

    problems = [e for e in events if e["kind"] in PROBLEMS][-15:][::-1]
    problem_rows = "".join(
        f'<tr><td class="when">{esc(ago(e["ts"], now))}</td><td>{badge(e["kind"])}</td>'
        f'<td>{esc(e["subject"])}<pre>{esc(chr(10).join(e.get("details", [])))}</pre></td></tr>'
        for e in problems) or '<tr><td colspan=3 class="muted">Nothing in the last 30 days.</td></tr>'

    last_event = ago(events[-1]["ts"], now) if events else "never"
    return PAGE.format(
        generated=esc(time.strftime("%Y-%m-%d %H:%M", time.localtime(now))), running=running,
        last_event=esc(last_event), tiles=tiles_html, bars="".join(bars),
        usage_rows="".join(usage_rows) or '<tr><td colspan=10 class="muted">No Claude runs recorded yet.</td></tr>',
        filters=filters, pr_rows="".join(pr_rows) or '<tr><td colspan=5 class="muted">No PRs yet.</td></tr>',
        problem_rows=problem_rows, days=DAYS, routing_rows=routing_html,
        misses=f'<p>Audit misses:</p><ul>{miss_rows}</ul>' if miss_rows else "",
    )


PAGE = """<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>PR autopilot</title>
<style>
:root {{ --bg:#f7f7f5; --card:#fff; --text:#1d1d1b; --muted:#6b6b66; --line:#e4e4df;
  --good:#1f7a4d; --warn:#a15c00; --bad:#b42318; --info:#2557a7; --quick:#8fb3e8; --full:#2557a7;
  --datum-fg:#ffffff; --datum-bg:#a46969; }}
@media (prefers-color-scheme: dark) {{ :root {{ --bg:#161615; --card:#1f1f1d; --text:#ededea; --muted:#9a9a94;
  --line:#33332f; --good:#4cc38a; --warn:#f0a43a; --bad:#ff6b5e; --info:#7aa7ff; --quick:#3d5f96; --full:#7aa7ff;
  --datum-fg:#0c1d31; --datum-bg:#e6f59e; }} }}
* {{ box-sizing:border-box; }}
body {{ margin:0; background:var(--bg); color:var(--text); font:14px/1.45 -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif; }}
main {{ max-width:1200px; margin:0 auto; padding:24px 16px 48px; }}
header {{ display:flex; flex-wrap:wrap; align-items:baseline; gap:8px 16px; margin-bottom:20px; }}
h1 {{ font-size:22px; margin:0; }} h2 {{ font-size:15px; margin:0 0 12px; }}
.muted, .when {{ color:var(--muted); }} .when {{ white-space:nowrap; }}
.tiles {{ display:grid; grid-template-columns:repeat(auto-fit, minmax(160px, 1fr)); gap:12px; margin-bottom:16px; }}
.tile, section {{ background:var(--card); border:1px solid var(--line); border-radius:10px; padding:14px 16px; }}
section {{ margin-bottom:16px; overflow-x:auto; }}
.tlabel {{ color:var(--muted); font-size:12px; }} .tvalue {{ font-size:26px; font-weight:600; }} .tsub {{ color:var(--muted); font-size:12px; }}
.tile.good .tvalue {{ color:var(--good); }} .tile.warn .tvalue {{ color:var(--warn); }} .tile.bad .tvalue {{ color:var(--bad); }}
.chart {{ display:flex; align-items:flex-end; gap:6px; height:160px; }}
.bar {{ flex:1; display:flex; flex-direction:column; height:100%; }}
.stack {{ flex:1; display:flex; flex-direction:column; justify-content:flex-end; }}
.seg.quick {{ background:var(--quick); }} .seg.full {{ background:var(--full); }} .seg {{ border-radius:2px; }}
.blabel {{ text-align:center; font-size:11px; color:var(--muted); margin-top:4px; }}
.legend span {{ display:inline-block; width:10px; height:10px; border-radius:2px; margin:0 4px 0 12px; }}
table {{ width:100%; border-collapse:collapse; }}
th, td {{ text-align:left; padding:8px 6px; border-bottom:1px solid var(--line); vertical-align:top; }}
th {{ font-size:12px; color:var(--muted); font-weight:500; }} td.num, th.num {{ text-align:right; white-space:nowrap; }}
a {{ color:var(--info); text-decoration:none; }} a:hover {{ text-decoration:underline; }}
.title {{ font-weight:500; }} .small {{ font-size:12px; }}
.summary {{ color:var(--muted); margin-top:2px; }}
details summary {{ cursor:pointer; color:var(--muted); }}
pre {{ white-space:pre-wrap; font:12px/1.45 ui-monospace, SFMono-Regular, Menlo, monospace; margin:6px 0; color:var(--muted); }}
.hist {{ border-left:2px solid var(--line); padding-left:8px; margin-top:8px; }}
.badge {{ display:inline-block; font-size:11px; font-weight:600; padding:2px 7px; border-radius:999px; white-space:nowrap;
  border:1px solid currentColor; }}
.k-approved {{ color:var(--good); }} .k-blocked, .k-manual {{ color:var(--warn); }}
.k-error, .k-gave-up, .k-audit-miss, .k-auth, .k-gap {{ color:var(--bad); }} .k-reviewing, .k-notice, .k-posted {{ color:var(--info); }}
.k-skipped, .k-warn {{ color:var(--muted); }}
/* cloud.datum.net's primary button colors (datum-ui alpha theme): Canyon Clay in light mode,
   Aurora Moss in dark mode */
.runner-datum {{ color:var(--datum-fg); background:var(--datum-bg); border-color:var(--datum-bg);
  font-size:10px; padding:1px 6px; margin-left:4px; }}
.filters button {{ font:inherit; font-size:12px; background:none; color:var(--text); border:1px solid var(--line);
  border-radius:999px; padding:3px 10px; margin:0 4px 8px 0; cursor:pointer; }}
.filters button.on {{ background:var(--text); color:var(--bg); }}
</style></head><body><main>
<header><h1>PR autopilot</h1>
<span class="muted">updated {generated} · last event {last_event} · full reviews running: {running}</span></header>
<div class="tiles">{tiles}</div>
<section><h2>Spend per day <span class="legend muted"><span style="background:var(--quick)"></span>quick
<span style="background:var(--full)"></span>full</span></h2>
<div class="chart">{bars}</div>
<p class="muted">Dollar amounts are what the same tokens would cost at API prices. Reviews run on your Claude plan,
so they count against its usage limits rather than being billed.</p></section>
<section><h2>Claude runs, last {days} days</h2><table>
<tr><th>Kind</th><th>Model</th><th class=num>Runs</th><th class=num>Input</th><th class=num>Cache read</th>
<th class=num>Output</th><th class=num>Total $</th><th class=num>$ / run</th><th class=num>Turns / run</th>
<th class=num>Time / run</th></tr>{usage_rows}</table></section>
<section><h2>Pull requests, last {days} days</h2>
<div class="filters"><button data-k="" class="on">All</button>{filters}</div>
<table id="prs"><tr><th>When</th><th>Outcome</th><th>PR</th><th class=num>Tokens</th><th class=num>$</th></tr>
{pr_rows}</table></section>
<section><h2>Quick review routing, last {days} days</h2><table>
<tr><th></th><th class=num>Full reviews</th><th class=num>Blocked</th><th class=num>Approved</th><th></th></tr>
{routing_rows}</table>{misses}</section>
<section><h2>Errors and warnings</h2><table>{problem_rows}</table></section>
</main>
<script>
document.querySelectorAll('.filters button').forEach(b => b.onclick = () => {{
  document.querySelectorAll('.filters button').forEach(x => x.classList.toggle('on', x === b));
  document.querySelectorAll('#prs tr[data-kind]').forEach(r =>
    r.style.display = !b.dataset.k || r.dataset.kind === b.dataset.k ? '' : 'none');
}});
// Reload every minute, unless you are reading details or filtering.
setInterval(() => {{
  if (!document.querySelector('details[open]') && !document.querySelector('.filters button.on').dataset.k)
    location.reload();
}}, 60000);
</script></body></html>
"""
