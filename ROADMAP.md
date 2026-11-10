# Scylax — Roadmap

Propuesta de mejoras priorizadas. Principio rector: **no superar el techo de intrusividad actual** (content discovery de la fase C + comprobación de path traversal confirmada por firma). Los reportes siguen siendo *evidencia y candidatos para un humano*, no veredictos.

## Prioridad alta

- [ ] **Paralelismo entre fases y hosts.** Hoy solo `phases/active.py` y `phases/content.py` usan `ThreadPoolExecutor`; OSINT, DNS, nmap por IP y cloud son secuenciales. Añadir pools por fase respetando los límites de `resilience.py`.
- [ ] **Reanudación real (`--resume`).** Ampliar `checkpoint.py` para reanudar fase a fase tras un fallo (`nmap`, `nuclei`, timeouts) sin repetir lo ya hecho.
- [ ] **Formatos de salida estándar.** Añadir **SARIF** y **CSV** además de `report_data.json` / `findings.jsonl`, para integrar con Jira, DefectDojo, etc.
- [ ] **Supresiones con caducidad.** Fichero `suppressions.toml` (hallazgo, motivo, fecha de caducidad) para que lo aceptado no reaparezca en cada `diff.md`.
- [ ] **Diff entre runs más útil.** Tendencias (MTTR de resueltos, edad de persistentes) y resumen "qué cambió" en la cabecera de `report.html`, usando `findings_history.json`.

## Prioridad media

- [ ] **Dividir los módulos grandes.** `report.py` (~3.1k líneas), `phases/cloud.py` (~1.8k), `phases/osint.py` (~1.7k), `phases/triage.py` (~1.3k), `saas/github.py` (~1.3k). Separar plantillas HTML y un módulo por proveedor cloud.
- [ ] **Tests de contrato para fuentes externas.** Fixtures grabados de crt.sh, NVD, HIBP y XposedOrNot, más un job nocturno opcional contra las APIs reales para detectar cambios de formato.
- [ ] **CI ampliado.** Añadir `pyproject.toml`, `ruff`, `mypy` (modo suave), cobertura, `pip-audit` y escaneo de la imagen Docker (Trivy).
- [ ] **Más proveedores SSPM.** Okta, Slack y API de administración de Atlassian, siguiendo la estructura de `recon/saas/`.
- [ ] **Descubrimiento de assets pasivo.** Rangos y ASN del cliente vía BGP/RIPEstat, pivotes por certificado y por hash de favicon.

## Prioridad baja / pulido

- [ ] **Alertas más ricas.** Slack y email además de Teams/JSON en `notify.py`; resumen semanal de nuevos críticos.
- [ ] **Programación CTEM.** `--schedule` o plantilla de cron / GitHub Action para el run mensual con comparación automática.
- [ ] **Distribución.** Publicar con `pipx`/PyPI y la imagen en GHCR con tags por versión; añadir `CHANGELOG.md` y `SECURITY.md`.
- [ ] **Reportes.** Exportación a PDF, filtros guardados en el HTML y un modo ejecutivo de una página.

## Orden sugerido

1. SARIF/CSV + supresiones con caducidad (máximo valor para el auditor, bajo coste).
2. Paralelismo + `--resume` (mayor beneficio operativo).
3. Tests de contrato + `pyproject.toml` con lint (evita roturas silenciosas).
