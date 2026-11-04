"""Politeness and failure containment for the pipeline's own network calls.

- CircuitBreaker: stop hammering a source (Wayback, an amass that keeps timing
  out) after N consecutive failures instead of paying the timeout every time.
- AdaptiveLimiter: per-host backoff. A host that answers 429/503 or times out
  gets an extra delay that doubles on every signal and decays on success; after
  too many consecutive signals the host is left alone for the rest of the run.
- http_get_retry: retries transient failures with backoff / Retry-After.

All three are deterministic and injectable (``sleep``, ``fetch``) so they are
testable without the network.
"""

from __future__ import annotations

import threading
import time
import urllib.parse
from typing import Any, Callable

from recon.runner import DRY_RUN, HttpResponse, http_get

THROTTLE_STATUSES = frozenset({0, 429, 502, 503, 504})


class CircuitBreaker:
    def __init__(self, threshold: int = 3) -> None:
        self.threshold = threshold
        self._fails: dict[str, int] = {}
        self._lock = threading.Lock()

    def allow(self, source: str) -> bool:
        with self._lock:
            return self._fails.get(source, 0) < self.threshold

    def success(self, source: str) -> None:
        with self._lock:
            self._fails[source] = 0

    def failure(self, source: str) -> bool:
        """Record a failure; True when this one opened the circuit."""
        with self._lock:
            n = self._fails.get(source, 0) + 1
            self._fails[source] = n
            return n == self.threshold

    def reset(self) -> None:
        with self._lock:
            self._fails.clear()


BREAKERS = CircuitBreaker()


class AdaptiveLimiter:
    def __init__(
        self,
        *,
        base_delay: float = 0.0,
        max_delay: float = 10.0,
        give_up_after: int = 8,
        sleep: Callable[[float], None] = time.sleep,
    ) -> None:
        self.base_delay = base_delay
        self.max_delay = max_delay
        self.give_up_after = give_up_after
        self._sleep = sleep
        self._extra: dict[str, float] = {}
        self._streak: dict[str, int] = {}
        self._lock = threading.Lock()

    @staticmethod
    def _host(url: str) -> str:
        return urllib.parse.urlsplit(url).netloc.lower()

    def delay_for(self, host: str) -> float:
        with self._lock:
            return self.base_delay + self._extra.get(host, 0.0)

    def gave_up(self, host: str) -> bool:
        with self._lock:
            return self._streak.get(host, 0) >= self.give_up_after

    def report(self, host: str, status: int) -> None:
        with self._lock:
            if status in THROTTLE_STATUSES:
                self._streak[host] = self._streak.get(host, 0) + 1
                cur = self._extra.get(host, 0.0)
                self._extra[host] = min(self.max_delay, max(0.25, cur * 2))
            else:
                self._streak[host] = 0
                cur = self._extra.get(host, 0.0) * 0.9
                self._extra[host] = cur if cur >= 0.05 else 0.0

    def wrap(self, fetch: Callable[..., Any] = http_get) -> Callable[..., Any]:
        """Same signature as http_get; slows down, then abandons, throttling hosts."""

        def limited(url: str, **kw: Any) -> Any:
            if DRY_RUN.active:  # nothing real happens: no backoff, just record the request
                return fetch(url, **kw)
            host = self._host(url)
            if self.gave_up(host):
                return HttpResponse(status=0, body="", headers={}, final_url=url, redirect_url="")
            d = self.delay_for(host)
            if d > 0:
                self._sleep(d)
            resp = fetch(url, **kw)
            self.report(host, getattr(resp, "status", 0))
            return resp

        return limited


def _retry_after(resp: Any) -> float:
    try:
        return min(60.0, float((getattr(resp, "headers", {}) or {}).get("retry-after", "")))
    except (TypeError, ValueError):
        return 0.0


def http_get_retry(
    url: str,
    *,
    source: str = "",
    delays: tuple[float, ...] = (0, 5, 15, 30),
    breaker: CircuitBreaker = BREAKERS,
    fetch: Callable[..., Any] = http_get,
    sleep: Callable[[float], None] = time.sleep,
    on_retry: Callable[[int, int, Any], None] | None = None,
    **kw: Any,
) -> Any:
    """GET with retries on transient failures (timeouts, 429, 5xx). Other 4xx are final.
    When ``source`` is given the outcome feeds the circuit breaker."""
    resp: Any = None
    if DRY_RUN.active:
        return fetch(url, **kw)
    for attempt, delay in enumerate(delays, start=1):
        wait = max(delay, _retry_after(resp)) if resp is not None else delay
        if wait:
            sleep(wait)
        resp = fetch(url, **kw)
        status = getattr(resp, "status", 0)
        if status == 200 or (400 <= status < 500 and status != 429):
            break
        if on_retry and attempt < len(delays):
            on_retry(attempt, len(delays), resp)
    if source:
        if getattr(resp, "status", 0) == 200:
            breaker.success(source)
        else:
            breaker.failure(source)
    return resp
