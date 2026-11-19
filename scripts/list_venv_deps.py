#!/usr/bin/env python3
"""List installed distributions as pinned requirements for one environment.

uv venvs ship without pip, so this reads installed metadata with
importlib.metadata instead. Stdlib-only; run it with the interpreter of the
environment to inspect:

    /opt/venvs/spiderfoot/bin/python list_venv_deps.py OUT_DIR spiderfoot

Writes OUT_DIR/NAME.txt (name==version, index installs only) and
OUT_DIR/NAME.unauditable.txt (distributions installed from a VCS URL or local
path per PEP 610, which have no PyPI release to match against).
"""
import importlib.metadata as md
import json
import sys
from pathlib import Path


def source_of(dist):
    """Return None for index installs, else a description of the direct URL."""
    raw = dist.read_text("direct_url.json")
    if not raw:
        return None
    try:
        info = json.loads(raw)
    except ValueError:
        return "direct url"
    url = info.get("url", "?")
    vcs = info.get("vcs_info", {}).get("vcs")
    return f"{vcs}+{url}" if vcs else url


def main(argv):
    if len(argv) != 3:
        sys.exit(__doc__)
    out_dir, name = Path(argv[1]), argv[2]
    out_dir.mkdir(parents=True, exist_ok=True)
    pinned, skipped = {}, {}
    for dist in md.distributions():
        pkg, ver = dist.metadata["Name"], dist.version
        if not pkg or not ver:
            continue
        src = source_of(dist)
        if src is None:
            pinned[pkg.lower()] = f"{pkg}=={ver}"
        else:
            skipped[pkg.lower()] = f"{pkg}=={ver} ({src})"
    (out_dir / f"{name}.txt").write_text(
        "".join(f"{pinned[k]}\n" for k in sorted(pinned)))
    (out_dir / f"{name}.unauditable.txt").write_text(
        "".join(f"{skipped[k]}\n" for k in sorted(skipped)))
    print(f"{name}: {len(pinned)} auditable, {len(skipped)} not auditable")


if __name__ == "__main__":
    main(sys.argv)
