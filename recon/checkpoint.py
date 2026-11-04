"""Per-phase checkpoints so an interrupted run can resume (--resume).

A phase is marked done only when it finished without raising and without any
tool failure; a phase that is missing results is never skipped on resume. The
mark records a hash of the scope file, so editing the scope invalidates it.
"""

from __future__ import annotations

import datetime
import hashlib
import json
from pathlib import Path

DIR_NAME = ".checkpoints"


def scope_signature(scope_path: Path) -> str:
    try:
        return hashlib.sha256(scope_path.read_bytes()).hexdigest()[:16]
    except OSError:
        return ""


def _file(run_dir: Path, phase: str) -> Path:
    return run_dir / DIR_NAME / f"{phase}.json"


def mark_done(run_dir: Path, phase: str, signature: str) -> None:
    f = _file(run_dir, phase)
    f.parent.mkdir(parents=True, exist_ok=True)
    f.write_text(
        json.dumps({
            "phase": phase,
            "scope_sha": signature,
            "finished": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        }),
        encoding="utf-8",
    )


def is_done(run_dir: Path, phase: str, signature: str) -> bool:
    f = _file(run_dir, phase)
    if not f.is_file():
        return False
    try:
        data = json.loads(f.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return False
    return data.get("scope_sha") == signature


def clear(run_dir: Path, phase: str) -> None:
    try:
        _file(run_dir, phase).unlink()
    except FileNotFoundError:
        pass
