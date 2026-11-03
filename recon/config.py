"""Configuration and TOML scope loader."""

from __future__ import annotations

import datetime
import re
import tomllib
from dataclasses import dataclass, field
from pathlib import Path
from typing import List


DEFAULT_PHASES: List[str] = ["1", "2", "3", "4", "4b", "5", "6", "7", "8", "9", "A", "G", "W", "S", "T"]
ACTIVE_PHASES: set[str] = {"3", "4", "4b", "5", "8", "A", "G", "W"}


def _split_list(val: object) -> List[str]:
    """Accept either a TOML list of strings or a whitespace/comma-separated string."""
    if val is None:
        return []
    if isinstance(val, list):
        return [str(x).strip() for x in val if str(x).strip()]
    if isinstance(val, str):
        return [x.strip() for x in re.split(r"[\s,]+", val) if x.strip()]
    raise ValueError(f"Expected list or string, got {type(val).__name__}")


def _ports_csv(val: object, default: str) -> str:
    if val is None:
        return default
    if isinstance(val, list):
        return ",".join(str(x).strip() for x in val if str(x).strip())
    if isinstance(val, (str, int)):
        s = str(val).strip()
        return s if s else default
    raise ValueError(f"Invalid ports specification: {val!r}")


DEFAULT_SKIP_PORTSCAN_ORGS: List[str] = [
    "Cloudflare",
    "Fastly",
    "Akamai",
    "Amazon CloudFront",
    "HubSpot",
    "GitHub",
    "Vercel",
    "Netlify",
    "Squarespace",
    "Wix",
]


@dataclass
class ScopeConfig:
    path: Path
    name: str
    engagement: str
    scope_owner: str = ""
    authorised_by: str = ""
    authorisation_ref: str = ""
    domains: List[str] = field(default_factory=list)
    www_url: str = ""
    hvt_ips: List[str] = field(default_factory=list)
    edge_ips: List[str] = field(default_factory=list)
    edge_ports: str = "21,22,23,53,80,443,8291"
    exclude_ips: List[str] = field(default_factory=list)
    auto_discover_targets: bool = True
    skip_portscan_orgs: List[str] = field(
        default_factory=lambda: [
            "Cloudflare",
            "Fastly",
            "Akamai",
            "Amazon CloudFront",
            "HubSpot",
            "GitHub",
            "Vercel",
            "Netlify",
            "Squarespace",
            "Wix",
        ]
    )
    apex_trusted_orgs: List[str] = field(default_factory=list)
    azure_subscriptions: List[str] = field(default_factory=list)
    azure_inventory_file: str = ""
    gcp_projects: List[str] = field(default_factory=list)
    gcp_inventory_file: str = ""
    aws_profiles: List[str] = field(default_factory=list)
    aws_regions: List[str] = field(default_factory=list)
    aws_inventory_file: str = ""
    shodan_api_key: str = ""
    hibp_api_key: str = ""
    cloud_posture: bool = False
    use_prowler: bool = False
    saas_posture: bool = False
    saas_providers: List[str] = field(default_factory=lambda: ["m365", "github", "google"])
    nmap_max_rate: int = 400
    edge_max_rate: int = 40
    nuclei_rate: int = 50
    httpx_rate: int = 50
    use_amass: bool = True
    amass_timeout_min: int = 10
    quick_scan: bool = False
    top_ports: int | None = None
    min_apache: str = "2.4.65"
    min_nginx: str = "1.26.0"
    min_routeros: str = "7.15"

    @property
    def apex_trusted_orgs_regex(self) -> str:
        if not self.apex_trusted_orgs:
            return r"^$"
        return "|".join(self.apex_trusted_orgs)

    @property
    def skip_portscan_orgs_regex(self) -> str:
        if not self.skip_portscan_orgs:
            return r"^$"
        return "|".join(self.skip_portscan_orgs)

    @classmethod
    def load(cls, path: Path) -> "ScopeConfig":
        if not path.is_file():
            raise FileNotFoundError(
                f"Scope file not found: {path} (copy scopes/example.toml)"
            )

        with path.open("rb") as f:
            raw = tomllib.load(f)

        # Support both flat keys and optional section tables ([engagement], [targets], [azure], [gcp], [limits], [thresholds])
        flat: dict[str, object] = {}
        for k, v in raw.items():
            if isinstance(v, dict):
                for sk, sv in v.items():
                    flat[sk.lower()] = sv
                    flat[f"{k.lower()}_{sk.lower()}"] = sv
            else:
                flat[k.lower()] = v

        name = path.stem
        domains = _split_list(flat.get("domains"))
        if not domains:
            raise ValueError(f"{path}: 'domains' is required and cannot be empty")

        www_url = str(flat.get("www_url") or "").strip()
        if not www_url:
            www_url = f"https://www.{domains[0]}/"

        auto_discover_raw = flat.get("auto_discover_targets")
        if auto_discover_raw is None:
            auto_discover_raw = flat.get("targets_auto_discover")
        if auto_discover_raw is None:
            auto_discover_raw = flat.get("auto_discover", True)
        if isinstance(auto_discover_raw, (int, bool)):
            auto_discover_targets = bool(auto_discover_raw)
        else:
            auto_discover_targets = str(auto_discover_raw).strip().lower() not in ("0", "false", "no")

        skip_portscan_val = flat.get("skip_portscan_orgs")
        if skip_portscan_val is None:
            skip_portscan_val = flat.get("targets_skip_portscan_orgs")
        if skip_portscan_val is None:
            skip_portscan_orgs_list = list(DEFAULT_SKIP_PORTSCAN_ORGS)
        elif isinstance(skip_portscan_val, list):
            skip_portscan_orgs_list = [str(x).strip() for x in skip_portscan_val if str(x).strip()]
        elif isinstance(skip_portscan_val, str):
            skip_portscan_orgs_list = [x.strip() for x in re.split(r"[|,\n]+", skip_portscan_val) if x.strip()]
        else:
            skip_portscan_orgs_list = _split_list(skip_portscan_val)

        use_amass_raw = flat.get("use_amass", True)
        if isinstance(use_amass_raw, (int, bool)):
            use_amass = bool(use_amass_raw)
        else:
            use_amass = str(use_amass_raw).strip().lower() not in ("0", "false", "no")

        apex_orgs = flat.get("apex_trusted_orgs", ["HubSpot", "Cloudflare", "Microsoft", "Amazon"])
        if isinstance(apex_orgs, str):
            # Support regex-style "HubSpot|Cloudflare" or space/comma lists
            apex_orgs_list = [x.strip() for x in re.split(r"[|,\s]+", apex_orgs) if x.strip()]
        else:
            apex_orgs_list = _split_list(apex_orgs)

        gcp_projects_val = flat.get("gcp_projects")
        if gcp_projects_val is None and "gcp" in raw and isinstance(raw["gcp"], dict):
            gcp_projects_val = raw["gcp"].get("projects")
        gcp_projects = _split_list(gcp_projects_val)

        gcp_inv_val = flat.get("gcp_inventory_file")
        if not gcp_inv_val and "gcp" in raw and isinstance(raw["gcp"], dict):
            gcp_inv_val = raw["gcp"].get("inventory_file")
        gcp_inventory_file = str(gcp_inv_val or "").strip()

        azure_subs_val = flat.get("azure_subscriptions")
        if azure_subs_val is None and "azure" in raw and isinstance(raw["azure"], dict):
            azure_subs_val = raw["azure"].get("subscriptions")
        azure_subscriptions = _split_list(azure_subs_val)

        azure_inv_val = flat.get("azure_inventory_file")
        if not azure_inv_val and "azure" in raw and isinstance(raw["azure"], dict):
            azure_inv_val = raw["azure"].get("inventory_file")
        azure_inventory_file = str(azure_inv_val or "").strip()

        aws_profiles_val = flat.get("aws_profiles")
        if aws_profiles_val is None and "aws" in raw and isinstance(raw["aws"], dict):
            aws_profiles_val = raw["aws"].get("profiles")
        aws_profiles = _split_list(aws_profiles_val)

        aws_regions_val = flat.get("aws_regions")
        if aws_regions_val is None and "aws" in raw and isinstance(raw["aws"], dict):
            aws_regions_val = raw["aws"].get("regions")
        aws_regions = _split_list(aws_regions_val)

        aws_inv_val = flat.get("aws_inventory_file")
        if not aws_inv_val and "aws" in raw and isinstance(raw["aws"], dict):
            aws_inv_val = raw["aws"].get("inventory_file")
        aws_inventory_file = str(aws_inv_val or "").strip()

        cloud_posture_raw = flat.get("cloud_posture")
        if cloud_posture_raw is None:
            cloud_posture_raw = flat.get("cloud_cloud_posture")
        if cloud_posture_raw is None:
            cloud_posture_raw = flat.get("cloud_posture_cloud_posture")
        if cloud_posture_raw is None:
            cloud_posture_raw = flat.get("cloud_posture_enabled")
        if cloud_posture_raw is None:
            cloud_posture_raw = flat.get("posture")
        if cloud_posture_raw is None and "cloud_posture" in raw and isinstance(raw["cloud_posture"], dict):
            cloud_posture_raw = raw["cloud_posture"].get("cloud_posture", raw["cloud_posture"].get("enabled"))
        if cloud_posture_raw is None and "cloud" in raw and isinstance(raw["cloud"], dict):
            cloud_posture_raw = raw["cloud"].get("posture", raw["cloud"].get("cloud_posture"))

        if cloud_posture_raw is None:
            cloud_posture = False
        elif isinstance(cloud_posture_raw, (int, bool)):
            cloud_posture = bool(cloud_posture_raw)
        else:
            cloud_posture = str(cloud_posture_raw).strip().lower() in ("1", "true", "yes", "on")

        use_prowler_raw = flat.get("use_prowler")
        if use_prowler_raw is None:
            use_prowler_raw = flat.get("prowler")
        if use_prowler_raw is None:
            use_prowler_raw = flat.get("cloud_use_prowler")
        if use_prowler_raw is None:
            use_prowler_raw = flat.get("cloud_posture_use_prowler")
        if use_prowler_raw is None:
            use_prowler_raw = flat.get("cloud_posture_prowler")
        if use_prowler_raw is None and "cloud_posture" in raw and isinstance(raw["cloud_posture"], dict):
            use_prowler_raw = raw["cloud_posture"].get("use_prowler", raw["cloud_posture"].get("prowler"))
        if use_prowler_raw is None and "cloud" in raw and isinstance(raw["cloud"], dict):
            use_prowler_raw = raw["cloud"].get("use_prowler", raw["cloud"].get("prowler"))

        if use_prowler_raw is None:
            use_prowler = False
        elif isinstance(use_prowler_raw, (int, bool)):
            use_prowler = bool(use_prowler_raw)
        else:
            use_prowler = str(use_prowler_raw).strip().lower() in ("1", "true", "yes", "on")

        saas_posture_raw = flat.get("saas_posture")
        if saas_posture_raw is None:
            saas_posture_raw = flat.get("saas_saas_posture")
        if saas_posture_raw is None and "saas" in raw and isinstance(raw["saas"], dict):
            saas_posture_raw = raw["saas"].get("saas_posture", raw["saas"].get("posture", raw["saas"].get("enabled")))

        if saas_posture_raw is None:
            saas_posture = False
        elif isinstance(saas_posture_raw, (int, bool)):
            saas_posture = bool(saas_posture_raw)
        else:
            saas_posture = str(saas_posture_raw).strip().lower() in ("1", "true", "yes", "on")

        saas_prov_raw = flat.get("saas_providers")
        if saas_prov_raw is None:
            saas_prov_raw = flat.get("providers")
        if saas_prov_raw is None and "saas" in raw and isinstance(raw["saas"], dict):
            saas_prov_raw = raw["saas"].get("providers", raw["saas"].get("saas_providers"))
        if saas_prov_raw is not None:
            saas_providers = _split_list(saas_prov_raw)
        else:
            saas_providers = ["m365", "github", "google"]

        return cls(
            path=path,
            name=name,
            engagement=str(flat.get("engagement") or name),
            scope_owner=str(flat.get("scope_owner") or ""),
            authorised_by=str(flat.get("authorised_by") or "").strip(),
            authorisation_ref=str(flat.get("authorisation_ref") or "").strip(),
            domains=domains,
            www_url=www_url,
            hvt_ips=_split_list(flat.get("hvt_ips")),
            edge_ips=_split_list(flat.get("edge_ips")),
            edge_ports=_ports_csv(flat.get("edge_ports"), "21,22,23,53,80,443,8291"),
            exclude_ips=_split_list(flat.get("exclude_ips")),
            auto_discover_targets=auto_discover_targets,
            skip_portscan_orgs=skip_portscan_orgs_list,
            apex_trusted_orgs=apex_orgs_list,
            azure_subscriptions=azure_subscriptions,
            azure_inventory_file=azure_inventory_file,
            gcp_projects=gcp_projects,
            gcp_inventory_file=gcp_inventory_file,
            aws_profiles=aws_profiles,
            aws_regions=aws_regions,
            aws_inventory_file=aws_inventory_file,
            shodan_api_key=str(flat.get("shodan_api_key") or flat.get("shodan_key") or "").strip(),
            hibp_api_key=str(flat.get("hibp_api_key") or flat.get("hibp_key") or "").strip(),
            cloud_posture=cloud_posture,
            use_prowler=use_prowler,
            saas_posture=saas_posture,
            saas_providers=saas_providers,
            nmap_max_rate=int(flat.get("nmap_max_rate", 400)),
            edge_max_rate=int(flat.get("edge_max_rate", 40)),
            nuclei_rate=int(flat.get("nuclei_rate", 50)),
            httpx_rate=int(flat.get("httpx_rate", 50)),
            use_amass=use_amass,
            amass_timeout_min=int(flat.get("amass_timeout_min", 10)),
            quick_scan=bool(flat.get("quick_scan", False) or flat.get("quick", False)),
            top_ports=int(flat["top_ports"]) if flat.get("top_ports") else None,
            min_apache=str(flat.get("min_apache", "2.4.65")),
            min_nginx=str(flat.get("min_nginx", "1.26.0")),
            min_routeros=str(flat.get("min_routeros", "7.15")),
        )


@dataclass
class RunContext:
    root: Path
    scope: ScopeConfig
    run_date: str
    phases: List[str]
    skip_active: bool = False
    skip_azure: bool = False
    skip_cloud: bool = False
    use_docker: bool = False
    yes: bool = False
    shodan_api_key: str = ""
    hibp_api_key: str = ""
    cloud_posture: bool = False
    use_prowler: bool = False
    saas_posture: bool = False
    quick_scan: bool = False
    top_ports: int | None = None

    def __post_init__(self) -> None:
        if self.skip_cloud:
            self.skip_azure = True
        if not self.quick_scan and getattr(self.scope, "quick_scan", False):
            self.quick_scan = True
        if self.top_ports is None and getattr(self.scope, "top_ports", None) is not None:
            self.top_ports = self.scope.top_ports
        if not self.cloud_posture and getattr(self.scope, "cloud_posture", False):
            self.cloud_posture = self.scope.cloud_posture
        if not self.use_prowler and getattr(self.scope, "use_prowler", False):
            self.use_prowler = self.scope.use_prowler
        if not self.saas_posture and getattr(self.scope, "saas_posture", False):
            self.saas_posture = self.scope.saas_posture
        if not self.shodan_api_key and getattr(self.scope, "shodan_api_key", ""):
            self.shodan_api_key = self.scope.shodan_api_key
        if not self.hibp_api_key and getattr(self.scope, "hibp_api_key", ""):
            self.hibp_api_key = self.scope.hibp_api_key

    @property
    def today(self) -> str:
        return datetime.date.today().isoformat()

    @property
    def run_dir(self) -> Path:
        return self.root / "runs" / self.scope.name / self.run_date

    @property
    def raw_dir(self) -> Path:
        return self.run_dir / "raw"

    @property
    def web_dir(self) -> Path:
        return self.run_dir / "web"

    @property
    def scan_dir(self) -> Path:
        return self.run_dir / "scan"

    @property
    def osint_dir(self) -> Path:
        return self.run_dir / "osint"

    @property
    def azure_dir(self) -> Path:
        return self.run_dir / "azure"

    @property
    def gcp_dir(self) -> Path:
        return self.run_dir / "gcp"

    @property
    def aws_dir(self) -> Path:
        return self.run_dir / "aws"

    @property
    def saas_dir(self) -> Path:
        return self.run_dir / "saas"

    @property
    def console_dir(self) -> Path:
        return self.run_dir / "console"

    @property
    def prev_run_dir(self) -> Path | None:
        scope_runs = self.root / "runs" / self.scope.name
        if not scope_runs.is_dir():
            return None
        candidates = sorted(
            d for d in scope_runs.iterdir() if d.is_dir() and d.name < self.run_date
        )
        return candidates[-1] if candidates else None

    def ensure_dirs(self) -> None:
        for d in (
            self.raw_dir,
            self.web_dir,
            self.scan_dir,
            self.osint_dir,
            self.azure_dir,
            self.gcp_dir,
            self.aws_dir,
            self.saas_dir,
            self.console_dir,
        ):
            d.mkdir(parents=True, exist_ok=True)
