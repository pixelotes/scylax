"""Expiring finding suppressions: the auditor's recorded decisions.

A suppression says "this candidate was reviewed and accepted (risk accepted,
false positive, compensating control)", with an owner, a reason and an expiry
date. It never deletes a finding: suppressed findings move to their own
visible list (suppressed.md / suppressed.tsv, a "Suppressed" table in the
report) and come back as active automatically once the suppression expires.

File format (TOML, ``scopes/<scope-name>.suppressions.toml`` by default, or the
scope key ``suppressions_file``)::

    [[suppress]]
    key = "cors:https://app.example.com/"   # exact finding key, or:
    rule = "cors"                           # rule id = key prefix before ':' (glob ok)
    target = "*.dev.example.com"            # optional glob on the finding target
    reason = "Accepted: staging, WAF in front"   # required
    owner = "jdoe"                          # required
    expires = 2027-03-31                    # required TOML date (inclusive)
    ticket = "SEC-123"                      # optional

Invalid entries are reported and ignored; nothing here raises.
"""

from __future__ import annotations

import datetime
import fnmatch
import tomllib
import urllib.parse
from dataclasses import dataclass
from pathlib import Path
from typing import Callable, Iterable

Finding = tuple[str, str, str, str]  # (severity, key, title, evidence)

NEAR_EXPIRY_DAYS = 14
MAX_HORIZON_DAYS = 366

SUPPRESSED_TSV = "suppressed.tsv"
SUPPRESSED_MD = "suppressed.md"


@dataclass
class Suppression:
    index: int  # 1-based position in the file, for messages
    reason: str
    owner: str
    expires: datetime.date
    key: str = ""
    rule: str = ""
    target: str = ""
    ticket: str = ""

    @property
    def label(self) -> str:
        if self.key:
            return self.key
        return f"rule={self.rule}" + (f" target={self.target}" if self.target else "")

    def matches(self, key: str, target: str) -> bool:
        if self.key and key != self.key:
            return False
        if self.rule and not fnmatch.fnmatchcase(rule_of(key), self.rule):
            return False
        if self.target:
            pat = self.target.lower()
            return any(fnmatch.fnmatchcase(c, pat) for c in _target_candidates(key, target))
        return True


def rule_of(key: str) -> str:
    """The rule / category id of a finding: its key up to the first ':'."""
    return key.split(":", 1)[0]


def _target_candidates(key: str, target: str) -> list[str]:
    """Strings a target glob is tried against: the target column, its hostname
    when it is a URL, and the key's resource part."""
    out: list[str] = []
    rest = key.split(":", 1)[1] if ":" in key else ""
    for t in (target, rest):
        for part in (p.strip() for p in t.split(",")):
            if not part:
                continue
            out.append(part.lower())
            if "://" in part:
                host = urllib.parse.urlparse(part).hostname or ""
                if host:
                    out.append(host.lower())
            elif ":" in part and part.count(":") == 1:  # host:port / ip:port
                out.append(part.split(":", 1)[0].lower())
    return out


def resolve_path(scope) -> Path | None:
    """The suppressions file for a scope: ``suppressions_file`` (resolved like the
    scope's other files) or ``<scope dir>/<scope name>.suppressions.toml``."""
    explicit = getattr(scope, "suppressions_file", "") or ""
    if explicit:
        return scope.resolve_file(explicit)
    p = Path(scope.path).resolve().parent / f"{scope.name}.suppressions.toml"
    return p if p.is_file() else None


def parse_file(path: Path, today: datetime.date) -> tuple[list[Suppression], list[str]]:
    """Read and validate a suppressions file. Returns (valid entries, warnings).
    Expired entries are returned too (they are reported when applied)."""
    warnings: list[str] = []
    try:
        with Path(path).open("rb") as f:
            raw = tomllib.load(f)
    except (OSError, tomllib.TOMLDecodeError) as exc:
        return [], [f"suppressions file {path} unreadable, no suppression applied: {exc}"]

    entries = raw.get("suppress", [])
    if not isinstance(entries, list):
        return [], [f"suppressions file {path}: 'suppress' must be an array of tables ([[suppress]])"]
    for k in raw:
        if k != "suppress":
            warnings.append(f"suppressions file {path}: unknown top-level key '{k}' ignored")

    out: list[Suppression] = []
    for i, e in enumerate(entries, 1):
        where = f"suppression #{i} in {Path(path).name}"
        if not isinstance(e, dict):
            warnings.append(f"{where} ignored: not a table")
            continue
        unknown = sorted(set(e) - {"key", "rule", "target", "reason", "owner", "expires", "ticket"})
        if unknown:
            warnings.append(f"{where}: unknown field(s) {', '.join(unknown)} ignored")
        key, rule, target = (str(e.get(f) or "").strip() for f in ("key", "rule", "target"))
        reason, owner, ticket = (str(e.get(f) or "").strip() for f in ("reason", "owner", "ticket"))
        missing = [f for f, v in (("reason", reason), ("owner", owner)) if not v]
        if not (key or rule):
            missing.insert(0, "key or rule")
        exp = e.get("expires")
        if isinstance(exp, datetime.datetime):
            exp = exp.date()
        elif isinstance(exp, str):
            try:
                exp = datetime.date.fromisoformat(exp.strip())
            except ValueError:
                warnings.append(f"{where} ignored: bad expires date {exp!r} (use a TOML date, e.g. 2027-03-31)")
                continue
        if exp is None:
            missing.append("expires")
        elif not isinstance(exp, datetime.date):
            warnings.append(f"{where} ignored: bad expires value {exp!r} (use a TOML date, e.g. 2027-03-31)")
            continue
        if missing:
            warnings.append(f"{where} ignored: missing {', '.join(missing)}")
            continue
        s = Suppression(index=i, key=key, rule=rule, target=target, reason=reason,
                        owner=owner, expires=exp, ticket=ticket)
        if (exp - today).days > MAX_HORIZON_DAYS:
            warnings.append(f"suppression for {s.label} expires on {exp}, more than a year ahead: "
                            f"review accepted risks at least yearly")
        out.append(s)
    return out, warnings


@dataclass
class Applied:
    active: list[Finding]
    suppressed: list[tuple[Finding, Suppression]]
    expired_keys: dict[str, Suppression]  # active findings an expired suppression would have hidden


def apply(
    findings: Iterable[Finding],
    sups: list[Suppression],
    target_of: Callable[[str], str],
    today: datetime.date,
    warn: Callable[[str], None],
) -> Applied:
    """Split findings into active and suppressed. Emits warnings for expired,
    near-expiry and stale entries through ``warn``."""
    live = [s for s in sups if s.expires >= today]
    expired = [s for s in sups if s.expires < today]
    used: set[int] = set()
    active: list[Finding] = []
    suppressed: list[tuple[Finding, Suppression]] = []
    expired_keys: dict[str, Suppression] = {}
    for item in findings:
        key = item[1]
        tgt = target_of(key)
        hit = next((s for s in live if s.matches(key, tgt)), None)
        if hit is not None:
            used.add(hit.index)
            suppressed.append((item, hit))
            continue
        active.append(item)
        old = next((s for s in expired if s.matches(key, tgt)), None)
        if old is not None:
            used.add(old.index)
            expired_keys[key] = old
            warn(f"suppression expired on {old.expires} for {key} (owner {old.owner}): finding is active again")
    for s in live:
        if s.index not in used:
            warn(f"stale suppression #{s.index} ({s.label}) matched no finding this run: remove it if fixed")
        else:
            days = (s.expires - today).days
            if days <= NEAR_EXPIRY_DAYS:
                warn(f"suppression for {s.label} expires on {s.expires} (in {days} days, owner {s.owner}): renew or fix")
    for s in expired:
        if s.index not in used:
            warn(f"suppression #{s.index} ({s.label}) expired on {s.expires} and matched nothing: remove it")
    return Applied(active, suppressed, expired_keys)


def _cell(text: str) -> str:
    return str(text).replace("\t", " ").replace("\r", " ").replace("\n", " ")


def write_outputs(run_dir: Path, applied: Applied, target_of: Callable[[str], str], run_date: str) -> None:
    """suppressed.tsv (machine-readable, read by the report and the next run's
    diff) and suppressed.md (for the auditor). Both are always written so a
    stale file from an earlier triage of the same run never lingers."""
    run_dir = Path(run_dir)
    rows = []
    for (sev, key, title, ev), s in applied.suppressed:
        rows.append("\t".join(_cell(x) for x in (
            sev, key, title, ev, target_of(key), s.reason, s.owner, s.expires.isoformat(), s.ticket)) + "\n")
    (run_dir / SUPPRESSED_TSV).write_text("".join(rows), encoding="utf-8")

    md = [
        f"# Suppressed finding candidates - {run_date}",
        "",
        "Still observed this run, hidden from the active list by a recorded auditor decision. "
        "They return as active when the suppression expires.",
        "",
    ]
    if applied.suppressed:
        md += ["| Severity | Finding | Target | Reason | Owner | Expires | Ticket | Key |",
               "|---|---|---|---|---|---|---|---|"]
        for (sev, key, title, _), s in applied.suppressed:
            esc = lambda t: _cell(t).replace("|", "\\|")  # noqa: E731
            md.append(f"| {sev} | {esc(title)} | {esc(target_of(key))} | {esc(s.reason)} | {esc(s.owner)} "
                      f"| {s.expires.isoformat()} | {esc(s.ticket) or '-'} | `{esc(key)}` |")
    else:
        md.append("_No finding suppressed this run._")
    (run_dir / SUPPRESSED_MD).write_text("\n".join(md) + "\n", encoding="utf-8")


def load_suppressed(run_dir: Path) -> list[dict[str, str]]:
    """Rows of a run's suppressed.tsv ([] when absent)."""
    path = Path(run_dir) / SUPPRESSED_TSV
    if not path.is_file():
        return []
    fields = ("severity", "key", "title", "evidence", "target", "reason", "owner", "expires", "ticket")
    out = []
    for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
        parts = line.split("\t")
        if len(parts) >= 8:
            out.append(dict(zip(fields, (p.strip() for p in parts + [""] * (9 - len(parts))))))
    return out


def diff_buckets(
    prev_keys: set[str],
    curr_keys: set[str],
    prev_suppressed: set[str],
    curr_suppressed: set[str],
    expired_now: set[str],
) -> tuple[set[str], set[str]]:
    """(newly suppressed, reactivated) for the run diff.

    Newly suppressed: suppressed now but not in the previous run - it must not
    count as "Resolved" (when it was active before) or "New". Reactivated: active
    now, not active in the previous run, and either suppressed then or matched by
    an expired suppression now. The caller removes both from its other buckets."""
    newly = curr_suppressed - prev_suppressed
    reactivated = (curr_keys - prev_keys) & (prev_suppressed | expired_now)
    return newly, reactivated
