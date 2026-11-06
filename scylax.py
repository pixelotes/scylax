#!/usr/bin/env python3
"""Entry point for the External Attack Surface Assessment & Reconnaissance Pipeline."""
import sys

if sys.version_info < (3, 11):
    sys.exit(f"Scylax requires Python 3.11 or newer (found {sys.version.split()[0]}).")

from pathlib import Path

_repo_root = Path(__file__).resolve().parent
if str(_repo_root) not in sys.path:
    sys.path.insert(0, str(_repo_root))

from recon.venv_manager import ensure_venv

if __name__ == "__main__":
    ensure_venv(_repo_root)
    from recon.cli import main
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        # An interrupt outside a running phase (preflight, a prompt, setup). The
        # phase loop handles its own interrupts and still salvages a report.
        sys.stderr.write("\nInterrupted.\n")
        sys.exit(130)
