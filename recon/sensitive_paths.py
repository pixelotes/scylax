"""Curated sensitive-path probe: the native fallback when nuclei is missing or fails.

This is not a fuzzer. Every entry is a well-known path paired with a signature
that must appear in the response (status alone is never enough), so catch-all
"200 for everything" sites do not produce findings. Only a few KB of each
response are read, nothing is ever submitted, and the probe only runs against
assets the ownership allowlist says we own.
"""

from __future__ import annotations

import re
import time
from dataclasses import dataclass
from typing import Callable, Iterable


@dataclass(frozen=True)
class SensitivePath:
    path: str
    category: str
    severity: str  # critical / high / medium / low / info
    signature: str  # regex matched against "headers + body" (multiline)
    title: str
    statuses: tuple[int, ...] = (200, 206)


SENSITIVE_PATHS: tuple[SensitivePath, ...] = (
    # Source control and secrets in the web root
    SensitivePath("/.git/config", "vcs", "high", r"^\[core\]", "Git repository exposed"),
    SensitivePath("/.git/HEAD", "vcs", "high", r"^ref:\s+refs/heads/", "Git repository exposed"),
    SensitivePath("/.svn/entries", "vcs", "high", r"^(\d+\s*$|dir$)", "Subversion metadata exposed"),
    SensitivePath("/.hg/hgrc", "vcs", "high", r"^\[paths\]", "Mercurial repository exposed"),
    SensitivePath("/.env", "secrets", "critical", r"^(APP_KEY|DB_PASSWORD|DATABASE_URL|SECRET_KEY|AWS_SECRET_ACCESS_KEY|[A-Z0-9_]*(PASSWORD|SECRET|TOKEN|KEY))\s*=", "Environment file with secrets exposed"),
    SensitivePath("/.env.local", "secrets", "critical", r"^[A-Z0-9_]*(PASSWORD|SECRET|TOKEN|KEY)\s*=", "Environment file with secrets exposed"),
    SensitivePath("/.env.production", "secrets", "critical", r"^[A-Z0-9_]*(PASSWORD|SECRET|TOKEN|KEY)\s*=", "Environment file with secrets exposed"),
    SensitivePath("/.aws/credentials", "secrets", "critical", r"aws_access_key_id\s*=", "AWS credentials file exposed"),
    SensitivePath("/.docker/config.json", "secrets", "critical", r'"auths"\s*:', "Docker registry credentials exposed"),
    SensitivePath("/.npmrc", "secrets", "high", r"_authToken\s*=", "npm token exposed"),
    SensitivePath("/.htpasswd", "secrets", "high", r"^[^:\s]+:(\$apr1\$|\$2[aby]\$|\{SHA\}|[./A-Za-z0-9]{13}$)", "htpasswd file exposed"),
    SensitivePath("/id_rsa", "secrets", "critical", r"BEGIN (OPENSSH|RSA|EC|DSA) PRIVATE KEY", "Private SSH key exposed"),
    SensitivePath("/.ssh/id_rsa", "secrets", "critical", r"BEGIN (OPENSSH|RSA|EC|DSA) PRIVATE KEY", "Private SSH key exposed"),
    SensitivePath("/.vscode/sftp.json", "secrets", "high", r'"(password|privateKeyPath)"\s*:', "Editor SFTP config with credentials exposed"),
    SensitivePath("/wp-config.php.bak", "secrets", "critical", r"DB_PASSWORD", "WordPress config backup exposed"),
    SensitivePath("/wp-config.php~", "secrets", "critical", r"DB_PASSWORD", "WordPress config backup exposed"),
    SensitivePath("/config.php.bak", "secrets", "high", r"(password|passwd|db_pass)", "PHP config backup exposed"),
    SensitivePath("/web.config", "config", "medium", r"<configuration[\s>]", "IIS web.config exposed"),
    SensitivePath("/docker-compose.yml", "config", "medium", r"^services\s*:", "docker-compose file exposed"),
    SensitivePath("/.gitlab-ci.yml", "config", "low", r"^(stages|script|image)\s*:", "CI pipeline definition exposed"),
    SensitivePath("/.DS_Store", "config", "low", r"Bud1", "macOS .DS_Store file listing exposed"),
    # Database dumps and backups (signature from the first KB only)
    SensitivePath("/backup.sql", "backup", "critical", r"(CREATE TABLE|INSERT INTO|-- MySQL dump|PostgreSQL database dump)", "Database dump exposed"),
    SensitivePath("/dump.sql", "backup", "critical", r"(CREATE TABLE|INSERT INTO|-- MySQL dump|PostgreSQL database dump)", "Database dump exposed"),
    SensitivePath("/db.sql", "backup", "critical", r"(CREATE TABLE|INSERT INTO|-- MySQL dump|PostgreSQL database dump)", "Database dump exposed"),
    SensitivePath("/database.sql", "backup", "critical", r"(CREATE TABLE|INSERT INTO|-- MySQL dump|PostgreSQL database dump)", "Database dump exposed"),
    SensitivePath("/backup.zip", "backup", "high", r"(?i)content-type:\s*application/(zip|x-zip)|^PK\x03\x04", "Backup archive exposed"),
    SensitivePath("/backup.tar.gz", "backup", "high", r"(?i)content-type:\s*application/(gzip|x-gzip|x-tar)", "Backup archive exposed"),
    # Metrics, debug and runtime introspection
    SensitivePath("/metrics", "telemetry", "medium", r"^# (HELP|TYPE) \w+", "Prometheus metrics exposed"),
    SensitivePath("/actuator/prometheus", "telemetry", "medium", r"^# (HELP|TYPE) \w+", "Spring Boot Prometheus metrics exposed"),
    SensitivePath("/actuator", "telemetry", "medium", r'"_links"\s*:\s*\{.*"self"', "Spring Boot Actuator exposed"),
    SensitivePath("/actuator/env", "telemetry", "high", r'"(activeProfiles|propertySources)"', "Spring Boot Actuator environment exposed"),
    SensitivePath("/actuator/configprops", "telemetry", "high", r'"contexts"\s*:', "Spring Boot configuration properties exposed"),
    SensitivePath("/actuator/mappings", "telemetry", "medium", r'"contexts"\s*:.*"mappings"', "Spring Boot route mappings exposed"),
    SensitivePath("/actuator/heapdump", "telemetry", "critical", r"(?i)content-type:\s*application/octet-stream|JAVA PROFILE", "Spring Boot heap dump downloadable"),
    SensitivePath("/env", "telemetry", "high", r'"(activeProfiles|propertySources)"', "Spring Boot (1.x) environment exposed"),
    SensitivePath("/jolokia", "telemetry", "high", r'"agent"\s*:|"jolokia"', "Jolokia JMX bridge exposed"),
    SensitivePath("/debug/pprof/", "telemetry", "high", r"Types of profiles available|/debug/pprof/goroutine", "Go pprof debug endpoints exposed"),
    SensitivePath("/debug/vars", "telemetry", "medium", r'"(cmdline|memstats)"\s*:', "Go expvar debug data exposed"),
    SensitivePath("/server-status", "telemetry", "medium", r"Apache Server Status for", "Apache server-status exposed"),
    SensitivePath("/server-info", "telemetry", "medium", r"Apache Server Information", "Apache server-info exposed"),
    SensitivePath("/nginx_status", "telemetry", "low", r"Active connections:\s*\d+", "nginx stub_status exposed"),
    SensitivePath("/stub_status", "telemetry", "low", r"Active connections:\s*\d+", "nginx stub_status exposed"),
    SensitivePath("/phpinfo.php", "telemetry", "medium", r"PHP Version|phpinfo\(\)", "phpinfo() exposed"),
    SensitivePath("/info.php", "telemetry", "medium", r"PHP Version|phpinfo\(\)", "phpinfo() exposed"),
    SensitivePath("/elmah.axd", "telemetry", "high", r"Error Log for", "ELMAH error log exposed"),
    SensitivePath("/trace.axd", "telemetry", "high", r"Application Trace", "ASP.NET trace exposed"),
    SensitivePath("/storage/logs/laravel.log", "telemetry", "high", r"\]\s+\w+\.(ERROR|WARNING|INFO):", "Laravel log file exposed"),
    SensitivePath("/telescope", "telemetry", "high", r"Laravel Telescope|telescope", "Laravel Telescope exposed"),
    SensitivePath("/_profiler", "telemetry", "high", r"Symfony Profiler", "Symfony profiler exposed"),
    SensitivePath("/wp-content/debug.log", "telemetry", "high", r"PHP (Notice|Warning|Fatal error|Deprecated)", "WordPress debug log exposed"),
    # API documentation and schemas (FastAPI, Swagger, GraphQL)
    SensitivePath("/docs", "api-docs", "low", r"swagger-ui|SwaggerUIBundle", "Swagger UI / FastAPI docs exposed"),
    SensitivePath("/redoc", "api-docs", "low", r"<redoc|Redoc\.init", "ReDoc API docs exposed"),
    SensitivePath("/openapi.json", "api-docs", "low", r'"openapi"\s*:\s*"3', "OpenAPI schema exposed"),
    SensitivePath("/swagger.json", "api-docs", "low", r'"swagger"\s*:\s*"2', "Swagger schema exposed"),
    SensitivePath("/swagger-ui.html", "api-docs", "low", r"swagger-ui|SwaggerUIBundle", "Swagger UI exposed"),
    SensitivePath("/swagger-ui/index.html", "api-docs", "low", r"swagger-ui|SwaggerUIBundle", "Swagger UI exposed"),
    SensitivePath("/api/docs", "api-docs", "low", r"swagger-ui|SwaggerUIBundle|<redoc", "API docs exposed"),
    SensitivePath("/api/swagger.json", "api-docs", "low", r'"(swagger|openapi)"\s*:', "API schema exposed"),
    SensitivePath("/v2/api-docs", "api-docs", "low", r'"swagger"\s*:', "Springfox API schema exposed"),
    SensitivePath("/v3/api-docs", "api-docs", "low", r'"openapi"\s*:', "springdoc API schema exposed"),
    SensitivePath("/graphql?query=%7B__typename%7D", "api-docs", "low", r'"__typename"', "GraphQL endpoint answers unauthenticated queries"),
    # Admin consoles and login pages
    SensitivePath("/wp-admin/", "admin", "low", r"(?i)location:\s*\S*wp-login\.php|wp-login\.php", "WordPress admin reachable", (200, 301, 302)),
    SensitivePath("/wp-login.php", "admin", "low", r'name="log"|id="user_login"|wp-submit', "WordPress login page exposed"),
    SensitivePath("/xmlrpc.php", "admin", "medium", r"XML-RPC server accepts POST requests only", "WordPress XML-RPC enabled (brute-force and pingback abuse)", (200, 405)),
    SensitivePath("/wp-json/wp/v2/users", "admin", "medium", r'"slug"\s*:.*"name"\s*:', "WordPress user enumeration via REST API"),
    SensitivePath("/readme.html", "admin", "info", r"WordPress", "WordPress readme discloses version"),
    SensitivePath("/phpmyadmin/", "admin", "high", r"phpMyAdmin", "phpMyAdmin exposed"),
    SensitivePath("/adminer.php", "admin", "high", r"Adminer|adminer\.org", "Adminer database console exposed"),
    SensitivePath("/manager/html", "admin", "high", r"(?i)Tomcat Manager|www-authenticate:.*Tomcat Manager Application", "Tomcat Manager exposed", (200, 401)),
    SensitivePath("/console/", "admin", "high", r"H2 Console|WebLogic Server Administration Console", "Database or application server console exposed"),
    SensitivePath("/h2-console/", "admin", "high", r"H2 Console", "H2 database console exposed"),
    SensitivePath("/solr/admin/", "admin", "high", r"Solr Admin|solr\.js", "Solr admin UI exposed"),
    SensitivePath("/jenkins/login", "admin", "medium", r"Jenkins", "Jenkins exposed"),
    SensitivePath("/login?from=%2F", "admin", "medium", r"Sign in \[Jenkins\]|Welcome to Jenkins", "Jenkins exposed"),
    SensitivePath("/grafana/login", "admin", "low", r"<title>Grafana</title>|grafanaBootData", "Grafana login exposed"),
    SensitivePath("/app/kibana", "admin", "medium", r"kbn-name|kibana", "Kibana exposed"),
    SensitivePath("/crossdomain.xml", "config", "low", r'allow-access-from\s+domain="\*"', "Permissive Flash crossdomain policy"),
)


@dataclass
class SensitiveHit:
    url: str
    category: str
    severity: str
    title: str
    snippet: str


def probe_sensitive_paths(
    base_urls: Iterable[str],
    http_get: Callable[..., object],
    *,
    paths: Iterable[SensitivePath] = SENSITIVE_PATHS,
    delay: float = 0.1,
    max_bytes: int = 4096,
    workers: int = 8,
    dead_after: int = 3,
    progress: Callable[[int, int], None] | None = None,
) -> list[SensitiveHit]:
    """GET each path on each base URL (no redirects followed) and keep the ones
    whose response matches the entry's signature.

    Hosts are probed in parallel (``workers``) but each host is walked sequentially
    with ``delay`` between requests, so no single host sees more load than before.
    A host that fails to answer ``dead_after`` requests in a row (timeout / connection
    error) is treated as unreachable and left alone instead of paying every timeout."""
    from concurrent.futures import ThreadPoolExecutor

    entries = tuple(paths)
    bases = [b.rstrip("/") for b in base_urls]
    done = 0

    def probe_base(base: str) -> list[SensitiveHit]:
        hits: list[SensitiveHit] = []
        failures = 0
        for entry in entries:
            url = f"{base}{entry.path}"
            resp = http_get(url, timeout=8.0, verify_ssl=False, follow_redirects=False, max_bytes=max_bytes)
            status = getattr(resp, "status", 0)
            failures = failures + 1 if status == 0 else 0
            if status in entry.statuses:
                headers = getattr(resp, "headers", {}) or {}
                text = "\n".join(f"{k}: {v}" for k, v in headers.items()) + "\n" + (getattr(resp, "body", "") or "")
                m = re.search(entry.signature, text, re.MULTILINE)
                if m:
                    snippet = m.group(0).strip().replace("\t", " ").replace("\r", " ").replace("\n", " ")[:120]
                    hits.append(SensitiveHit(url, entry.category, entry.severity, entry.title, snippet))
            if failures >= dead_after:
                break
            if delay:
                time.sleep(delay)
        return hits

    results: list[list[SensitiveHit]] = []
    with ThreadPoolExecutor(max_workers=max(1, workers)) as pool:
        for hits in pool.map(probe_base, bases):  # keeps the input order
            results.append(hits)
            done += 1
            if progress:
                progress(done, len(bases))
    return [h for hits in results for h in hits]
