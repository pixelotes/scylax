"""Run independent phases concurrently (``--jobs N``) without raising traffic.

Phases form a small DAG (``PHASE_DEPS``): a phase starts only once every phase
it reads from has finished - among the phases actually running in this run (an
unselected or skipped phase imposes no wait). A phase that crashed still counts
as finished, so its dependents run on whatever evidence exists, as they do in a
sequential run.

Intrusiveness ceiling: parallelism must never increase the intensity of the
traffic sent to the client's targets. Every phase that sends traffic to them
belongs to the **active traffic lane** (``ACTIVE_LANE``) and at most ONE lane
phase runs at a time, so the targets see exactly the per-tool rates of a
sequential run. Only passive / third-party API / offline phases (1, 2, 6, 7, 9,
S) run alongside the lane phase. Triage (T) always runs last, alone.

``jobs=1`` is the historical behaviour: phases run in the main thread, in the
order given, one after the other.
"""

from __future__ import annotations

from concurrent.futures import FIRST_COMPLETED, Future, ThreadPoolExecutor, wait
from typing import Callable, Iterable, Mapping, Sequence

# phase -> phases whose outputs it reads (T: every other phase, handled below)
PHASE_DEPS: dict[str, frozenset[str]] = {
    "1": frozenset(),
    "2": frozenset({"1"}),
    "3": frozenset({"1", "2"}),
    "4": frozenset({"1", "2"}),
    "4b": frozenset(),
    "5": frozenset({"3"}),
    "6": frozenset(),
    "7": frozenset({"2", "4", "4b", "A", "G"}),
    "8": frozenset({"2", "3"}),
    "9": frozenset({"2", "6"}),
    "A": frozenset(),
    "G": frozenset(),
    "W": frozenset(),
    "E": frozenset(),
    "S": frozenset(),
    "C": frozenset({"3"}),
}

LAST_PHASE = "T"

# Phases that send traffic to the client's own targets: probes, port scans
# (A/G/W run nmap against cloud public IPs), nuclei, content discovery and the
# anonymous tenant requests of E. Never two at once.
ACTIVE_LANE: frozenset[str] = frozenset({"3", "4", "4b", "5", "8", "C", "A", "G", "W", "E"})

OK, FAILED, CRASHED, INTERRUPTED = "ok", "failed", "crashed", "interrupted"

_POLL_S = 0.2  # main thread wakes this often so Ctrl-C is handled promptly


def effective_deps(
    phases: Sequence[str],
    deps: Mapping[str, Iterable[str]] = PHASE_DEPS,
    last: str = LAST_PHASE,
) -> dict[str, set[str]]:
    """Dependencies restricted to the phases that will actually run."""
    selected = list(dict.fromkeys(phases))
    out: dict[str, set[str]] = {}
    for p in selected:
        if p == last:
            out[p] = {q for q in selected if q != last}
        else:
            out[p] = {q for q in deps.get(p, ()) if q in selected and q != p}
    return out


def run_phases(
    phases: Sequence[str],
    run_one: Callable[[str], str],
    *,
    jobs: int = 1,
    runnable: Callable[[str], bool] | None = None,
    deps: Mapping[str, Iterable[str]] = PHASE_DEPS,
    lane: Iterable[str] = ACTIVE_LANE,
    last: str = LAST_PHASE,
    on_interrupt: Callable[[], None] | None = None,
) -> tuple[dict[str, str], bool]:
    """Run ``phases`` via ``run_one(phase) -> outcome``; return (outcomes, interrupted).

    ``runnable(phase)`` filters out phases that will not run (it may log why).
    With ``jobs == 1`` it is evaluated lazily, right before each phase, so the
    output is identical to a plain loop; with ``jobs > 1`` it is evaluated for
    every phase upfront. ``run_one`` returning ``INTERRUPTED`` stops the run:
    no new phase starts. With ``jobs > 1`` a ``run_one`` that raises counts as
    ``CRASHED`` (sequentially the exception propagates, as it always did).

    With ``jobs > 1`` a KeyboardInterrupt in the main thread stops new phases
    from starting, calls ``on_interrupt`` (which should make running phases
    stop at their next command), and waits for the running phases to return.
    """
    runnable = runnable or (lambda _p: True)
    order = list(dict.fromkeys(phases))
    outcomes: dict[str, str] = {}

    if jobs <= 1:
        for p in order:
            if not runnable(p):
                continue
            outcomes[p] = run_one(p)
            if outcomes[p] == INTERRUPTED:
                return outcomes, True
        return outcomes, False

    todo = [p for p in order if runnable(p)]
    need = effective_deps(todo, deps, last)
    lane_set = frozenset(lane)
    finished: set[str] = set()
    running: dict[Future[str], str] = {}
    lane_busy = False
    stop = False
    interrupted = False

    def _interrupt() -> None:
        nonlocal stop, interrupted
        if not interrupted and on_interrupt is not None:
            on_interrupt()
        stop = interrupted = True

    pool = ThreadPoolExecutor(max_workers=jobs, thread_name_prefix="scylax-phase")
    try:
        while True:
            if not stop:
                for p in list(todo):
                    if len(running) >= jobs:
                        break
                    if not need[p] <= finished:
                        continue
                    if p in lane_set and lane_busy:
                        continue
                    if p == last and running:
                        continue
                    todo.remove(p)
                    if p in lane_set:
                        lane_busy = True
                    running[pool.submit(run_one, p)] = p
                    if p == last:
                        break  # T runs alone
            if not running:
                if todo and not stop:
                    # Unsatisfiable dependencies (a cycle in a custom table):
                    # release them rather than hang.
                    need[todo[0]] = set()
                    continue
                break
            try:
                done, _ = wait(list(running), timeout=_POLL_S, return_when=FIRST_COMPLETED)
            except KeyboardInterrupt:
                _interrupt()
                continue
            for fut in done:
                p = running.pop(fut)
                try:
                    outcomes[p] = fut.result()
                except BaseException:
                    outcomes[p] = CRASHED
                finished.add(p)
                if p in lane_set:
                    lane_busy = False
                if outcomes[p] == INTERRUPTED:
                    _interrupt()
    finally:
        # Interrupted (again) while draining: still wait for running phases,
        # their threads cannot be killed and the report must see their files.
        while True:
            try:
                pool.shutdown(wait=True)
                break
            except KeyboardInterrupt:
                _interrupt()
    return outcomes, interrupted


__all__ = [
    "ACTIVE_LANE", "CRASHED", "FAILED", "INTERRUPTED", "LAST_PHASE", "OK", "PHASE_DEPS",
    "effective_deps", "run_phases",
]
