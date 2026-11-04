"""Outbound alerting: post new high/critical findings to a webhook after a run.

Only new and reappeared findings of high or critical severity are sent, so a
monthly run notifies you of what changed instead of resending the whole report.
The webhook is a Microsoft Teams (or any JSON) incoming webhook URL, taken from
the scope's alert_webhook or the SCYLAX_ALERT_WEBHOOK environment variable.
Nothing is sent when neither is set.
"""

from __future__ import annotations

import json
import os
import urllib.request
from typing import Sequence


def webhook_url(scope) -> str:
    return (getattr(scope, "alert_webhook", "") or os.environ.get("SCYLAX_ALERT_WEBHOOK", "")).strip()


def _teams_card(title: str, scope_name: str, run_date: str,
                findings: Sequence[tuple[str, str, str, str]]) -> dict:
    """A MessageCard (the format Teams incoming webhooks render)."""
    lines = []
    for sev, _key, ftitle, evidence in findings:
        ev = (evidence or "").replace("\n", " ")[:160]
        lines.append(f"- **{sev.upper()}** {ftitle} — {ev}")
    return {
        "@type": "MessageCard",
        "@context": "https://schema.org/extensions",
        "themeColor": "D13438",
        "summary": title,
        "sections": [{
            "activityTitle": title,
            "activitySubtitle": f"scope {scope_name} · run {run_date}",
            "text": "\n\n".join(lines),
        }],
    }


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
    title = f"Scylax: {len(findings)} new high/critical finding(s) for {scope_name}"
    payload = json.dumps(_teams_card(title, scope_name, run_date, findings)).encode("utf-8")
    req = urllib.request.Request(url, data=payload, headers={"Content-Type": "application/json"})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:  # noqa: S310 (user-provided webhook)
            if 200 <= resp.status < 300:
                return True, f"alert sent ({len(findings)} finding(s))"
            return True, f"webhook returned HTTP {resp.status}"
    except Exception as exc:  # noqa: BLE001
        return True, f"webhook POST failed: {exc}"
