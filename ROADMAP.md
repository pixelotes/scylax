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
| pip-audit of the Python venvs in the Docker image, on Dockerfile changes and weekly. Fails only on new vulnerabilities that have a fix. | `.github/workflows/deps-audit.yml` | #21 |
| Resume and scheduler gaps: a second Ctrl-C force-exits, setup crashes are recorded, phase C retries hosts the limiter abandoned, phase 7 CPE/CVE lookups are saved as resume units. | `recon/scheduler.py`, `recon/cli.py` | #21 |

## Next

- [ ] **Contract tests for external sources.** Recorded fixtures for crt.sh,
  NVD, HIBP, XposedOrNot and Shodan, so a change in their response format
  fails a test instead of silently producing empty results. Optionally a
  scheduled job that hits the real APIs.
- [ ] **SpiderFoot dependencies.** SpiderFoot master pins `cryptography`
  3.4.8, `lxml` 4.9.4 and `pyopenssl` 21.0.0, with 15 known vulnerabilities
  that have fixes. They are accepted in `.github/pip-audit-ignore.txt` for now.
  Options: pin a SpiderFoot release with newer pins, override the versions in
  the Dockerfile, or drop SpiderFoot from the image.
- [ ] **Finish CI.** `pyproject.toml` (tool config only, no packaging yet),
  `mypy` in non-strict mode, coverage report, Trivy scan of the Docker image.
  Run the dependency audit once against the real image (so far only checked
  against equivalent local venvs).
- [ ] **Resume for phases 1 and 6.** Both still restart from scratch.
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
