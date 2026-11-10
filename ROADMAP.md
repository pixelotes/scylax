# Roadmap

Ground rules for everything below:

- **Intrusiveness ceiling.** Nothing goes beyond what phase C already does
  (content discovery plus signature-confirmed path traversal). No fuzzing,
  injection payloads, brute force or higher rate limits.
- **Evidence, not verdicts.** Outputs are candidate findings for a human
  auditor to validate.
- **Stdlib only.** No runtime pip dependencies. Dev tooling (linters, test
  helpers) is fine.

## Done

| Item | Where | PR |
|---|---|---|
| Run independent phases concurrently (`--jobs N`). Phases that send traffic to targets share one lane, so per-target intensity is unchanged. | `recon/scheduler.py` | #17 |
| Resume inside a phase (`--resume`): nmap pass per IP, edge IP, nuclei batch, cloud IP, breach-lookup account, Shodan IP, phase C host. | `recon/checkpoint.py` | #17 |
| SARIF 2.1.0 and CSV exports, built from `report_data.json`. Suppressed findings are exported and marked. | `recon/export_formats.py` | #18 |
| Expiring suppressions with reason, owner and expiry. Suppressed findings stay visible and come back when the suppression expires. | `recon/suppressions.py` | #18 |
| Run-to-run trends: summary in `diff.md`, "What changed" card in the HTML report, MTTR, age buckets, oldest open high/critical findings. | `recon/trends.py` | #18 |
| Ruff lint job in CI (pinned version, `ruff.toml`). | `.github/workflows/ci.yml` | #19, #20 |

## Next

- [ ] **Contract tests for external sources.** Recorded fixtures for crt.sh,
  NVD, HIBP, XposedOrNot and Shodan, so a change in their response format
  fails a test instead of silently producing empty results. Optionally a
  scheduled job that hits the real APIs.
- [ ] **Finish CI.** `pyproject.toml` (tool config only, no packaging yet),
  `mypy` in non-strict mode, coverage report, `pip-audit` for dev tooling,
  Trivy scan of the Docker image.
- [ ] **Gaps left by the resume work.**
  - Phase 7 CPE/CVE lookups are cached in memory only; persist them per unit.
  - Phases 1 and 6 restart from scratch.
  - Phase C with the native probe marks a host done even when the adaptive
    limiter gave up on it; it should be retried on resume.
- [ ] **Gaps left by the scheduler.**
  - A second Ctrl-C while running phases drain should force-exit.
  - If a phase's setup (before the phase function runs) fails in a worker
    thread, the crash is not written to `tool_failures.tsv`.
- [ ] **Per-host parallelism inside phases.** OSINT, DNS, per-IP nmap and the
  cloud annexes still process hosts one by one. Any pool must respect the
  limits in `recon/resilience.py` and the active-traffic lane.

## Later

- [ ] **Split the large modules.** `report.py` (~3.3k lines), `phases/cloud.py`
  (~1.8k), `phases/osint.py` (~1.8k), `phases/triage.py` (~1.4k),
  `saas/github.py` (~1.3k). Move the HTML templates out of `report.py`; one
  module per cloud provider.
- [ ] **More SaaS posture providers.** Okta, Slack, Atlassian admin API,
  following the layout of `recon/saas/`.
- [ ] **Passive asset discovery.** Organisation ranges and ASNs from BGP /
  RIPEstat, certificate and favicon-hash pivots.
- [ ] **Sample report.** `recon/sample_generator.py` has no suppressed
  findings or trends; add them so the samples show the new sections.

## Ideas

- [ ] **Alerts.** Slack and email in `notify.py` (today: Teams and generic
  JSON webhook); a weekly digest of new high/critical findings.
- [ ] **Scheduled CTEM runs.** A cron or GitHub Actions template for the
  monthly run.
- [ ] **Distribution.** `pipx`/PyPI package, Docker image on GHCR with version
  tags, a version constant (SARIF currently omits the tool version),
  `CHANGELOG.md`, `SECURITY.md`.
- [ ] **Report.** PDF export, saved filters in the HTML report, a one-page
  executive summary.
