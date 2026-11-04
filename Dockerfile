# syntax=docker/dockerfile:1.7
#
# Scylax with every external tool preinstalled, so a run needs nothing on the
# host but Docker. Two targets:
#
#   core  network and OSINT tooling for phases 1-9 and T      (~1.5 GB)
#   full  core + cloud and SaaS CLIs for annexes A/G/W and S  (default)
#
#   docker build -t scylax .                  # full
#   docker build -t scylax:core --target core .
#
# Usage: see "Docker image" in README.md.

ARG PYTHON_VERSION=3.12
ARG DEBIAN_RELEASE=bookworm
# trufflehog's go.mod uses replace directives (no "go install"): take the
# binary from its official multi-arch image instead
# Pinned versions (override with --build-arg to bump). Last verified in CI 2026-11-04.
ARG TRUFFLEHOG_VERSION=3.99.8
ARG GITLEAKS_VERSION=v8.30.1

FROM trufflesecurity/trufflehog:${TRUFFLEHOG_VERSION} AS trufflehog
# gitleaks: lighter secret scanner, official multi-arch image
FROM zricethezav/gitleaks:${GITLEAKS_VERSION} AS gitleaks

# ---------------------------------------------------------------------------
# Go tools (ProjectDiscovery + amass), built for the target architecture
# ---------------------------------------------------------------------------
FROM golang:1-${DEBIAN_RELEASE} AS gotools
ARG SUBFINDER_VERSION=v2.17.0
ARG DNSX_VERSION=v1.3.1
ARG HTTPX_VERSION=v1.12.0
ARG NUCLEI_VERSION=v3.11.1
# Scylax calls "amass enum -passive" and "amass intel -whois": v4 still has both
ARG AMASS_VERSION=v4.2.0
ARG GOBUSTER_VERSION=v3.8.2
ENV CGO_ENABLED=0 GOBIN=/out
RUN --mount=type=cache,target=/root/go/pkg/mod --mount=type=cache,target=/root/.cache/go-build \
    go install -ldflags="-s -w" github.com/projectdiscovery/subfinder/v2/cmd/subfinder@${SUBFINDER_VERSION} \
 && go install -ldflags="-s -w" github.com/projectdiscovery/dnsx/cmd/dnsx@${DNSX_VERSION} \
 && go install -ldflags="-s -w" github.com/projectdiscovery/httpx/cmd/httpx@${HTTPX_VERSION} \
 && go install -ldflags="-s -w" github.com/projectdiscovery/nuclei/v3/cmd/nuclei@${NUCLEI_VERSION} \
 && go install -ldflags="-s -w" github.com/owasp-amass/amass/v4/...@${AMASS_VERSION} \
 && go install -ldflags="-s -w" github.com/OJ/gobuster/v3@${GOBUSTER_VERSION}

# ---------------------------------------------------------------------------
# core: Scylax + network / OSINT tooling
# ---------------------------------------------------------------------------
FROM python:${PYTHON_VERSION}-slim-${DEBIAN_RELEASE} AS core
ARG THEHARVESTER_REF=master
ARG SPIDERFOOT_REF=master

ENV DEBIAN_FRONTEND=noninteractive \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    NO_VENV=1 \
    PATH=/opt/tools/bin:$PATH

RUN apt-get update \
 && apt-get install -y --no-install-recommends \
      nmap dnsutils whois whatweb ca-certificates curl git jq unzip gnupg \
 && rm -rf /var/lib/apt/lists/*

COPY --from=gotools /out/ /usr/local/bin/
COPY --from=trufflehog /usr/bin/trufflehog /usr/local/bin/trufflehog
COPY --from=gitleaks /usr/bin/gitleaks /usr/local/bin/gitleaks
COPY --from=ghcr.io/astral-sh/uv:latest /uv /usr/local/bin/uv

# Python tools live in their own virtualenvs, each with the Python it needs
# (uv fetches it): Scylax itself stays stdlib-only on the base interpreter.
ENV UV_PYTHON_INSTALL_DIR=/opt/python UV_NO_CACHE=1 UV_LINK_MODE=copy
RUN mkdir -p /opt/tools/bin \
 && uv venv --python 3.14 /opt/venvs/theharvester \
 && uv pip install --python /opt/venvs/theharvester/bin/python "git+https://github.com/laramies/theHarvester.git@${THEHARVESTER_REF}" \
 && ln -s /opt/venvs/theharvester/bin/theHarvester /opt/tools/bin/theHarvester \
 && theHarvester -h >/dev/null
RUN git clone --depth 1 --branch "${SPIDERFOOT_REF}" https://github.com/smicallef/spiderfoot.git /opt/spiderfoot \
 && rm -rf /opt/spiderfoot/.git \
 && uv venv --python 3.11 /opt/venvs/spiderfoot \
 && uv pip install --python /opt/venvs/spiderfoot/bin/python -r /opt/spiderfoot/requirements.txt \
 && printf '#!/bin/sh\ncd /opt/spiderfoot && exec /opt/venvs/spiderfoot/bin/python sf.py "$@"\n' > /opt/tools/bin/spiderfoot \
 && chmod +x /opt/tools/bin/spiderfoot \
 && spiderfoot -h >/dev/null

# Bake the nuclei templates so phase 8 works offline and does not spend its
# timeout downloading them (refresh with: docker run ... --entrypoint nuclei scylax -update-templates)
RUN nuclei -update-templates -silent \
 && nuclei -version

COPY scylax.py LICENSE README.md /opt/scylax/
COPY recon /opt/scylax/recon
COPY scopes/example.toml /opt/scylax/scopes/example.toml
RUN python -m compileall -q /opt/scylax/recon \
 && ln -s /opt/scylax/scylax.py /opt/tools/bin/scylax

# Scopes and runs are read and written relative to the working directory:
# mount the folder that holds scopes/ and runs/ here.
WORKDIR /work
VOLUME ["/work"]

# Runs as root on purpose: nmap's UDP scan of VPN ports (phase 4) needs raw
# sockets, which Scylax only attempts as root. Use --user to drop it.
ENTRYPOINT ["python", "/opt/scylax/scylax.py"]
CMD ["--help"]

# ---------------------------------------------------------------------------
# full: core + cloud (A/G/W) and SaaS (S) CLIs
# ---------------------------------------------------------------------------
FROM core AS full
ARG TARGETARCH

RUN set -eux; \
    install -d -m 0755 /etc/apt/keyrings; \
    # Azure CLI
    curl -fsSL https://packages.microsoft.com/keys/microsoft.asc | gpg --dearmor -o /etc/apt/keyrings/microsoft.gpg; \
    echo "deb [signed-by=/etc/apt/keyrings/microsoft.gpg] https://packages.microsoft.com/repos/azure-cli/ bookworm main" > /etc/apt/sources.list.d/azure-cli.list; \
    # Google Cloud CLI
    curl -fsSL https://packages.cloud.google.com/apt/doc/apt-key.gpg | gpg --dearmor -o /etc/apt/keyrings/google-cloud.gpg; \
    echo "deb [signed-by=/etc/apt/keyrings/google-cloud.gpg] https://packages.cloud.google.com/apt cloud-sdk main" > /etc/apt/sources.list.d/google-cloud-sdk.list; \
    # GitHub CLI
    curl -fsSL https://cli.github.com/packages/githubcli-archive-keyring.gpg -o /etc/apt/keyrings/githubcli.gpg; \
    echo "deb [signed-by=/etc/apt/keyrings/githubcli.gpg] https://cli.github.com/packages stable main" > /etc/apt/sources.list.d/github-cli.list; \
    apt-get update; \
    apt-get install -y --no-install-recommends azure-cli google-cloud-cli gh; \
    rm -rf /var/lib/apt/lists/*; \
    az extension add --name resource-graph --only-show-errors; \
    # AWS CLI v2
    case "${TARGETARCH:-amd64}" in arm64) awsarch=aarch64 ;; *) awsarch=x86_64 ;; esac; \
    curl -fsSL "https://awscli.amazonaws.com/awscli-exe-linux-${awsarch}.zip" -o /tmp/awscli.zip; \
    unzip -q /tmp/awscli.zip -d /tmp; \
    /tmp/aws/install; \
    rm -rf /tmp/aws /tmp/awscli.zip; \
    az version --output none; gcloud --version >/dev/null; aws --version; gh --version

# Prowler (optional deep CSPM with --prowler). Some of its dependencies have no
# wheels for every architecture, so a compiler is present only for this step.
RUN set -eux; \
    apt-get update; \
    apt-get install -y --no-install-recommends build-essential; \
    uv venv --python 3.12 /opt/venvs/prowler; \
    uv pip install --python /opt/venvs/prowler/bin/python prowler; \
    ln -s /opt/venvs/prowler/bin/prowler /opt/tools/bin/prowler; \
    apt-get purge -y --auto-remove build-essential; \
    rm -rf /var/lib/apt/lists/*; \
    prowler -v
