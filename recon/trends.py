"""Diff trends: finding age, time-to-resolve (MTTR) and the "what changed" summary.

Pure functions over ``findings_history.json`` plus the current run's diff
buckets, so they are unit-testable without a run directory.

History layout (per scope, ``runs/<scope>/findings_history.json``)::

    {"<finding key>": {"first_seen": "YYYY-MM-DD", "seen": [dates], "severity": ..., "title": ...},
     "__runs__": [{"date": "YYYY-MM-DD", "phases": ["1", "2"], "failed_tools": ["nmap"]}]}

``__runs__`` is a reserved top-level key (optional: files written before it
existed simply lack it). Readers that look findings up by key ignore it.

Resolution date. A finding is only known to be gone when a run that actually
checked it did not report it, so ``resolved_at`` is the date of the first run
after its last ``seen`` date whose phase ran (and whose tool did not fail).
That is an upper bound on the real fix date. Runs come from ``__runs__`` and,
for older history, from the union of all ``seen`` dates (phases unknown, so
assumed to have checked everything).
"""
from __future__ import annotations

import datetime
import statistics
from typing import Any, Callable, Iterable

RUNS_KEY = "__runs__"
SEVERITIES = ("critical", "high", "medium", "low", "info")
BUCKET_LABELS = ("<30", "30-90", "90-180", ">180")
MTTR_WINDOW_DAYS = 90
OLDEST_N = 5
BUCKETS = ("new", "reappeared", "resolved", "not_rechecked", "persisting", "reactivated", "suppressed")


def parse_day(value: str) -> datetime.date | None:
    try:
        return datetime.date.fromisoformat(str(value)[:10])
    except ValueError:
        return None


def age_days(first_seen: str, run_date: str) -> int | None:
    a, b = parse_day(first_seen), parse_day(run_date)
    if a is None or b is None:
        return None
    return max((b - a).days, 0)


def age_bucket(days: int) -> str:
    if days < 30:
        return "<30"
    if days <= 90:
        return "30-90"
    if days <= 180:
        return "90-180"
    return ">180"


def _sev(value: str | None) -> str:
    s = (value or "").lower()
    return s if s in SEVERITIES else "info"


def finding_entries(history: dict) -> dict[str, dict]:
    """History minus reserved/malformed entries."""
    return {k: v for k, v in history.items() if k != RUNS_KEY and isinstance(v, dict)}


def known_runs(history: dict) -> list[dict]:
    """Recorded runs plus every date a finding was seen on, sorted by date."""
    by_date: dict[str, dict] = {}
    recorded = history.get(RUNS_KEY, [])
    for d in (r for r in (recorded if isinstance(recorded, list) else []) if isinstance(r, dict)):
        if parse_day(d.get("date", "")):
            by_date[str(d["date"])[:10]] = d
    for h in finding_entries(history).values():
        for s in h.get("seen", []) or []:
            if parse_day(s):
                by_date.setdefault(str(s)[:10], {"date": str(s)[:10]})
    return [by_date[d] for d in sorted(by_date)]


def record_run(history: dict, run_date: str, phases: Iterable[str], failed_tools: Iterable[str]) -> None:
    """Add/replace this run in ``history['__runs__']`` (in place)."""
    day = str(run_date)[:10]
    old = history.get(RUNS_KEY, [])
    runs = [r for r in (old if isinstance(old, list) else []) if isinstance(r, dict) and r.get("date") != day]
    runs.append({"date": day, "phases": sorted(set(phases)), "failed_tools": sorted(set(failed_tools))})
    runs.sort(key=lambda r: r.get("date", ""))
    history[RUNS_KEY] = runs


def _checked(key: str, run: dict, phase_of: Callable[[str], str | None],
             tools_of: Callable[[str], tuple[str, ...]]) -> bool:
    if any(t in (run.get("failed_tools") or []) for t in tools_of(key)):
        return False
    ph = phase_of(key)
    phases = run.get("phases")
    return ph is None or not phases or ph in phases


def _event(key: str, h: dict, resolved_at: str) -> dict:
    first = h.get("first_seen") or (h.get("seen") or [""])[0]
    return {"key": key, "severity": _sev(h.get("severity")), "first_seen": first,
            "resolved_at": resolved_at, "days": age_days(first, resolved_at)}


def resolution_events(history: dict, run_date: str, resolved_now: Iterable[str],
                      phase_of: Callable[[str], str | None] = lambda k: None,
                      tools_of: Callable[[str], tuple[str, ...]] = lambda k: ()) -> list[dict]:
    """Every finding known to be resolved: ``{key, severity, first_seen, resolved_at, days}``.

    Derived from history (last seen -> first run after it that checked it);
    keys in ``resolved_now`` that history cannot place (no later run recorded)
    are resolved on ``run_date``.
    """
    today = str(run_date)[:10]
    runs = known_runs(history)
    events: dict[str, dict] = {}
    for key, h in finding_entries(history).items():
        seen = sorted(str(s)[:10] for s in h.get("seen", []) or [] if parse_day(s))
        if not seen or seen[-1] >= today:
            continue  # still open (seen this run)
        resolved_at = next((r["date"] for r in runs
                            if r["date"] > seen[-1] and _checked(key, r, phase_of, tools_of)), None)
        if resolved_at:
            events[key] = _event(key, h, resolved_at)
    for key in resolved_now:
        if key not in events:
            events[key] = _event(key, history.get(key) or {}, today)
    return [e for e in events.values() if e["days"] is not None]


def _median(values: list[int]) -> float | None:
    return round(float(statistics.median(values)), 1) if values else None


def compute_trends(*, run_date: str, prev_date: str, history: dict, buckets: dict[str, Iterable[str]],
                   curr_sev: dict[str, str], prev_sev: dict[str, str],
                   phase_of: Callable[[str], str | None] = lambda k: None,
                   tools_of: Callable[[str], tuple[str, ...]] = lambda k: (),
                   suppressed_keys: Iterable[str] = ()) -> dict[str, Any]:
    """The trend summary. ``buckets`` maps names in :data:`BUCKETS` to keys
    (missing ones are empty). ``curr_sev``/``prev_sev``: key -> severity of the
    active findings of each run. 'not re-checked' keys are never resolved."""
    b = {name: sorted(set(buckets.get(name, ()))) for name in BUCKETS}
    suppressed_all = sorted(set(suppressed_keys))
    entries = finding_entries(history)

    def sev_of(key: str) -> str:
        return _sev(curr_sev.get(key) or prev_sev.get(key) or (entries.get(key) or {}).get("severity"))

    zero = {s: 0 for s in SEVERITIES}
    counts: dict[str, dict[str, int]] = {n: dict(zero) for n in BUCKETS}
    for name in BUCKETS:
        for k in (suppressed_all if name == "suppressed" else b[name]):
            counts[name][sev_of(k)] += 1
    current, previous = dict(zero), dict(zero)
    for s in curr_sev.values():
        current[_sev(s)] += 1
    for s in prev_sev.values():
        previous[_sev(s)] += 1
    net = {s: current[s] - previous[s] for s in SEVERITIES}

    # Open = active this run; age counts from first_seen
    ages = {k: age_days((entries.get(k) or {}).get("first_seen", ""), run_date) for k in curr_sev}
    by_age = {s: {lbl: 0 for lbl in BUCKET_LABELS} for s in SEVERITIES}
    for k, d in ages.items():
        if d is not None:
            by_age[sev_of(k)][age_bucket(d)] += 1
    oldest = sorted(((k, d) for k, d in ages.items() if d is not None and sev_of(k) in ("critical", "high")),
                    key=lambda kd: (-kd[1], SEVERITIES.index(sev_of(kd[0])), kd[0]))[:OLDEST_N]

    today = parse_day(run_date)
    events = resolution_events(history, run_date, b["resolved"], phase_of, tools_of)
    cutoff = (today - datetime.timedelta(days=MTTR_WINDOW_DAYS)) if today else None
    recent = [e for e in events if cutoff is None or (parse_day(e["resolved_at"]) or cutoff) >= cutoff]
    by_sev = {}
    for s in SEVERITIES:
        d = [e["days"] for e in recent if e["severity"] == s]
        by_sev[s] = {"n": len(d), "median_days": _median(d)}
    all_d = [e["days"] for e in recent]

    return {
        "run_date": str(run_date)[:10],
        "previous_run": str(prev_date)[:10],
        "severities": list(SEVERITIES),
        "counts": counts,
        "totals": {**{n: sum(counts[n].values()) for n in BUCKETS},
                   "current": sum(current.values()), "previous": sum(previous.values()),
                   "net": sum(current.values()) - sum(previous.values())},
        "current": current, "previous": previous, "net": net,
        "age_buckets": by_age,
        "mttr": {"window_days": MTTR_WINDOW_DAYS, "n": len(all_d), "median_days": _median(all_d),
                 "by_severity": by_sev},
        "oldest_open": [{"key": k, "severity": sev_of(k), "title": (entries.get(k) or {}).get("title", k),
                         "first_seen": (entries.get(k) or {}).get("first_seen", ""), "age_days": d}
                        for k, d in oldest],
    }


def signed(n: int) -> str:
    return f"+{n}" if n > 0 else str(n)


def mttr_text(t: dict[str, Any]) -> str:
    m = t["mttr"]
    if not m["n"]:
        return "no data"
    per = ", ".join(f"{s} {v['median_days']}d (n={v['n']})" for s, v in m["by_severity"].items() if v["n"])
    return f"median {m['median_days']} days over {m['n']} finding(s) - {per}"


def render_summary_md(t: dict[str, Any]) -> list[str]:
    """The '## Summary' block for diff.md."""
    tot, c = t["totals"], t["counts"]
    lines = ["", "## Summary", "",
             f"Net change: **{signed(tot['net'])}** active findings ({tot['previous']} -> {tot['current']}) "
             f"since {t['previous_run']}.", "",
             "| Severity | New | Reappeared | Reactivated | Resolved | Persisting | Net |",
             "|---|---|---|---|---|---|---|"]
    for s in t["severities"]:
        lines.append(f"| {s} | {c['new'][s]} | {c['reappeared'][s]} | {c['reactivated'][s]} | "
                     f"{c['resolved'][s]} | {c['persisting'][s]} | {signed(t['net'][s])} |")
    lines.append(f"| **total** | {tot['new']} | {tot['reappeared']} | {tot['reactivated']} | "
                 f"{tot['resolved']} | {tot['persisting']} | {signed(tot['net'])} |")
    extra = []
    if tot["not_rechecked"]:
        extra.append(f"{tot['not_rechecked']} not re-checked (never counted as resolved)")
    if tot["suppressed"]:
        extra.append(f"{tot['suppressed']} suppressed (accepted)")
    if extra:
        lines += ["", "Also: " + "; ".join(extra) + "."]
    lines += ["", f"MTTR (resolved in the last {t['mttr']['window_days']} days; upper bound): {mttr_text(t)}",
              "", "Open findings by age (days since first seen):", "",
              "| Severity | " + " | ".join(BUCKET_LABELS) + " |", "|---|" + "---|" * len(BUCKET_LABELS)]
    for s in t["severities"]:
        row = t["age_buckets"][s]
        if any(row.values()):
            lines.append(f"| {s} | " + " | ".join(str(row[x]) for x in BUCKET_LABELS) + " |")
    lines += ["", "Oldest open critical/high:", ""]
    if t["oldest_open"]:
        lines += [f"{i}. **{o['severity']}** {o['title']} - {o['age_days']} days (since {o['first_seen']}) `{o['key']}`"
                  for i, o in enumerate(t["oldest_open"], 1)]
    else:
        lines.append("_None._")
    return lines
