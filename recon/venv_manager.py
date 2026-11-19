"""Virtual environment management and auto-bootstrap for the recon pipeline."""

from __future__ import annotations

import os
import sys
from pathlib import Path
from typing import Sequence


def in_venv() -> bool:
    """Check if the current Python interpreter is running inside a virtual environment."""
    return (sys.prefix != getattr(sys, "base_prefix", sys.prefix)) or ("VIRTUAL_ENV" in os.environ)


def get_venv_python(venv_dir: Path) -> Path:
    """Locate the Python executable inside a virtual environment directory."""
    if sys.platform == "win32":
        return venv_dir / "Scripts" / "python.exe"
    py3 = venv_dir / "bin" / "python3"
    if py3.exists():
        return py3
    return venv_dir / "bin" / "python"


def ensure_venv(
    repo_root: Path,
    argv: Sequence[str] | None = None,
    interactive_prompt: bool | None = None,
) -> bool:
    """Ensure execution runs inside a virtual environment unless explicitly bypassed.

    Args:
        repo_root: Path to the repository root where .venv is located or created.
        argv: Command-line arguments to preserve upon re-exec.
        interactive_prompt: Override tty detection for prompting (useful in tests).

    Returns:
        True if already in venv or successfully switched, False if bypassed.
    """
    args = list(sys.argv[1:] if argv is None else argv)

    # 1. Skip if already in venv
    if in_venv():
        return True

    # 2. Skip if explicitly bypassed via flag or environment variable
    if "--no-venv" in args or os.environ.get("NO_VENV") == "1":
        return False

    # 3. Allow informational commands (--help, --check-deps, --report-only) to display without prompting
    if any(h in args for h in ("-h", "--help", "--check-deps", "--check-config", "--doctor", "--report-only")):
        return False

    venv_dir = repo_root / ".venv"
    venv_python = get_venv_python(venv_dir)

    entry_script = repo_root / "scylax.py"
    if not entry_script.is_file():
        entry_script = repo_root / "recon_pipeline.py"
    clean_args = [a for a in args if a != "--no-venv"]

    # Case A: .venv already exists
    if venv_python.is_file():
        os.environ["VIRTUAL_ENV"] = str(venv_dir)
        sys.stderr.write(f"[*] Detected existing virtual environment at {venv_dir.name}, switching...\n")
        sys.stderr.flush()
        try:
            os.execv(str(venv_python), [str(venv_python), str(entry_script), *clean_args])
        except Exception as exc:
            sys.stderr.write(f"[!] Failed to re-exec into {venv_python}: {exc}\n")
            return False
        return True

    # Case B: .venv does not exist
    is_tty = (sys.stdin.isatty() and sys.stdout.isatty()) if interactive_prompt is None else interactive_prompt
    auto_yes = ("-y" in args) or ("--yes" in args) or (os.environ.get("YES") == "1")

    should_create = False
    if auto_yes:
        should_create = True
    elif is_tty:
        sys.stderr.write(
            "\n[?] No active Python virtual environment detected.\n"
            "    Running inside a virtual environment prevents host system pollution.\n"
            "    Create and switch to .venv now? [Y/n] "
        )
        sys.stderr.flush()
        try:
            choice = sys.stdin.readline().strip().lower()
            should_create = choice in ("", "y", "yes")
        except Exception:
            should_create = False

    if should_create:
        sys.stderr.write(f"\n[*] Creating virtual environment at {venv_dir}...\n")
        sys.stderr.flush()
        try:
            import venv
            venv.create(venv_dir, with_pip=True)
            venv_python = get_venv_python(venv_dir)
            sys.stderr.write("[+] Virtual environment created successfully.\n")
            sys.stderr.write("[*] Launching pipeline inside .venv...\n\n")
            sys.stderr.flush()

            os.environ["VIRTUAL_ENV"] = str(venv_dir)
            os.execv(str(venv_python), [str(venv_python), str(entry_script), *clean_args])
        except Exception as exc:
            sys.stderr.write(f"[!] Failed to create virtual environment: {exc}\n")
            sys.stderr.write("[!] Continuing with current Python interpreter...\n\n")
            sys.stderr.flush()
            return False
    else:
        if is_tty:
            sys.stderr.write("[!] Continuing with current Python environment (use --no-venv to suppress this check).\n\n")
            sys.stderr.flush()

    return False

