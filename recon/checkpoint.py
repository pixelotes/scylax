"""Per-phase checkpoints so an interrupted run can resume (--resume).

A phase is marked done only when it finished without raising and without any
tool failure; a phase that is missing results is never skipped on resume. The
mark records a hash of the scope file, so editing the scope invalidates it.

Inside a phase, finished units of work (one IP's nmap pass, one nuclei batch,
one account lookup...) are recorded as one small file each under
``.checkpoints/<phase>.units/``. On --resume a phase that did not finish skips
its finished units and runs only the rest. A unit is marked only after its
command succeeded and its output is fully written, and the mark carries the
same scope hash, so a scope edit invalidates it. One file per unit (atomic
replace, no shared index) keeps it safe for concurrent threads/phases without
locks. Units are kept after the phase completes (a phase-done mark makes them
moot; a later fresh run clears them).
"""

from __future__ import annotations

import datetime
import hashlib
import json
import os
from pathlib import Path
from typing import Any

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


# --- unit-level checkpoints ------------------------------------------------

def _units_dir(run_dir: Path, phase: str) -> Path:
    return run_dir / DIR_NAME / f"{phase}.units"


def _unit_file(run_dir: Path, phase: str, key: str) -> Path:
    return _units_dir(run_dir, phase) / (hashlib.sha256(key.encode("utf-8")).hexdigest()[:32] + ".json")


def mark_unit(run_dir: Path, phase: str, key: str, signature: str, data: Any = None) -> None:
    """Record a finished unit; ``data`` (JSON-able) is kept so aggregates can be rebuilt on resume."""
    f = _unit_file(run_dir, phase, key)
    f.parent.mkdir(parents=True, exist_ok=True)
    tmp = f.with_name(f.name + f".{os.getpid()}.tmp")
    tmp.write_text(
        json.dumps({
            "key": key,
            "scope_sha": signature,
            "finished": datetime.datetime.now(datetime.timezone.utc).isoformat(),
            "data": data,
        }),
        encoding="utf-8",
    )
    os.replace(tmp, f)


def _load_unit(run_dir: Path, phase: str, key: str, signature: str) -> dict | None:
    f = _unit_file(run_dir, phase, key)
    try:
        rec = json.loads(f.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return None
    if not isinstance(rec, dict) or rec.get("key") != key or rec.get("scope_sha") != signature:
        return None
    return rec


def unit_done(run_dir: Path, phase: str, key: str, signature: str) -> bool:
    return _load_unit(run_dir, phase, key, signature) is not None


def unit_data(run_dir: Path, phase: str, key: str, signature: str) -> Any:
    rec = _load_unit(run_dir, phase, key, signature)
    return rec.get("data") if rec else None


def clear_units(run_dir: Path, phase: str) -> None:
    d = _units_dir(run_dir, phase)
    if d.is_dir():
        for f in d.iterdir():
            try:
                f.unlink()
            except OSError:
                pass


class Units:
    """Unit checkpoints of one phase for one run context.

    ``done``/``get`` are True/non-None only when the run was started with
    --resume; ``mark`` always records (a no-op in --dry-run) so a later
    --resume can use it.
    """

    def __init__(self, ctx: Any, phase: str) -> None:
        self.ctx = ctx
        self.phase = phase
        scope_path = getattr(getattr(ctx, "scope", None), "path", None)
        self.sig = scope_signature(Path(scope_path)) if scope_path else ""

    def done(self, key: str) -> bool:
        return bool(getattr(self.ctx, "resume", False)) and unit_done(self.ctx.run_dir, self.phase, key, self.sig)

    def get(self, key: str) -> Any:
        """Payload stored by mark(); None if the unit is not done (or resume is off)."""
        if not getattr(self.ctx, "resume", False):
            return None
        return unit_data(self.ctx.run_dir, self.phase, key, self.sig)

    def mark(self, key: str, data: Any = None) -> None:
        from recon.runner import dry_run_active  # local: avoid import cycle at module load

        if dry_run_active():
            return
        mark_unit(self.ctx.run_dir, self.phase, key, self.sig, data)
