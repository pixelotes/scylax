"""Pipeline phases package."""

from __future__ import annotations

from typing import Callable

from recon.config import RunContext
from recon.deps import DependencyManager
from recon.runner import Logger

from recon.phases.active import phase3, phase4, phase4b, phase5, phase8
from recon.phases.cloud import phaseA, phaseG, phaseW
from recon.phases.content import phaseC
from recon.phases.osint import phase1, phase2, phase6, phase7, phase9
from recon.phases.saas import phaseS
from recon.phases.triage import phaseT

PhaseFunc = Callable[[RunContext, DependencyManager, Logger], None]

PHASE_MAP: dict[str, PhaseFunc] = {
    "1": phase1,
    "2": phase2,
    "3": phase3,
    "4": phase4,
    "4b": phase4b,
    "5": phase5,
    "6": phase6,
    "7": phase7,
    "8": phase8,
    "9": phase9,
    "A": phaseA,
    "G": phaseG,
    "W": phaseW,
    "C": phaseC,
    "S": phaseS,
    "T": phaseT,
}

__all__ = [
    "PHASE_MAP",
    "PhaseFunc",
    "phaseC",
    "phase1",
    "phase2",
    "phase3",
    "phase4",
    "phase4b",
    "phase5",
    "phase6",
    "phase7",
    "phase8",
    "phase9",
    "phaseA",
    "phaseG",
    "phaseW",
    "phaseS",
    "phaseT",
]
