#!/usr/bin/env python3
"""Entry point for the External Attack Surface Assessment & Reconnaissance Pipeline."""
import sys
from pathlib import Path

_repo_root = Path(__file__).resolve().parent
if str(_repo_root) not in sys.path:
    sys.path.insert(0, str(_repo_root))

from recon.venv_manager import ensure_venv

if __name__ == "__main__":
    ensure_venv(_repo_root)
    from recon.cli import main
    sys.exit(main())
