"""Outbound alerting: post to a webhook after a run.

Two kinds of alert, both to the same incoming webhook (Microsoft Teams or any
JSON endpoint), taken from the scope's ``alert_webhook`` or the
``SCYLAX_ALERT_WEBHOOK`` environment variable; nothing is sent when neither is
set:

- **New high/critical findings** — only new and reappeared findings of high or
  critical severity, so a monthly run notifies you of what changed.
- **Run failures** — the run was interrupted (Ctrl-C) or one or more phases
  crashed, so a scheduled/unattended run tells you it did not finish cleanly.
"""

from __future__ import annotations

import json
import os
import urllib.request
from typing import Sequence


def webhook_url(scope) -> str:
    return (getattr(scope, "alert_webhook", "") or os.environ.get("SCYLAX_ALERT_WEBHOOK", "")).strip()


def _card(title: str, scope_name: str, run_date: str, text: str,
          *, theme: str = "D13438") -> dict:
    """A MessageCard (the format Teams incoming webhooks render)."""
    return {
        "@type": "MessageCard",
        "@context": "https://schema.org/extensions",
        "themeColor": theme,
        "summary": title,
        "sections": [{
            "activityTitle": title,
            "activitySubtitle": f"scope {scope_name} · run {run_date}",
            "text": text,
        }],
    }


def _post(url: str, card: dict, timeout: float) -> tuple[bool, str]:
    """POST a card to the webhook. Returns (attempted, message); never raises."""
    payload = json.dumps(card).encode("utf-8")
    req = urllib.request.Request(url, data=payload, headers={"Content-Type": "application/json"})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:  # noqa: S310 (user-provided webhook)
            if 200 <= resp.status < 300:
                return True, "alert sent"
            return True, f"webhook returned HTTP {resp.status}"
    except Exception as exc:  # noqa: BLE001
        return True, f"webhook POST failed: {exc}"


def post_new_findings(
    scope,
    scope_name: str,
    run_date: str,
    findings: Sequence[tuple[str, str, str, str]],
    *,
    timeout: float = 15.0,
) -> tuple[bool, str]:
    """POST the findings to the configured webhook. Returns (attempted, message)."""
    url = webhook_url(scope)
    if not url:
        return False, "no webhook configured"
    if not findings:
        return False, "no new high/critical findings"
    lines = []
    for sev, _key, ftitle, evidence in findings:
        ev = (evidence or "").replace("\n", " ")[:160]
        lines.append(f"- **{sev.upper()}** {ftitle} — {ev}")
    title = f"Scylax: {len(findings)} new high/critical finding(s) for {scope_name}"
    attempted, msg = _post(url, _card(title, scope_name, run_date, "\n\n".join(lines)), timeout)
    if attempted and msg == "alert sent":
        return True, f"alert sent ({len(findings)} finding(s))"
    return attempted, msg


def post_run_failure(
    scope,
    scope_name: str,
    run_date: str,
    *,
    interrupted: bool = False,
    crashed: Sequence[str] = (),
    run_dir: str = "",
    timeout: float = 15.0,
) -> tuple[bool, str]:
    """Alert that a run did not finish cleanly. Returns (attempted, message).

    Sends nothing when no webhook is configured or when the run was neither
    interrupted nor had a crashed phase."""
    url = webhook_url(scope)
    if not url:
        return False, "no webhook configured"
    if not interrupted and not crashed:
        return False, "run completed cleanly"

    if interrupted:
        title = f"Scylax: run INTERRUPTED for {scope_name}"
        lines = ["The run was interrupted (Ctrl-C) before finishing."]
        if crashed:
            lines.append(f"Phases that also crashed: {', '.join(crashed)}.")
    else:
        title = f"Scylax: run finished with {len(crashed)} failed phase(s) for {scope_name}"
        lines = [f"These phases crashed; their findings are not re-checked: {', '.join(crashed)}."]
    if run_dir:
        lines.append(f"Evidence: {run_dir}")
    return _post(url, _card(title, scope_name, run_date, "\n\n".join(lines)), timeout)
