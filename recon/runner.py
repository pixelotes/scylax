"""Execution helpers: logging, subprocess with timeout, HTTP requests, version comparison."""

from __future__ import annotations

import datetime
import json
import re
import shlex
import shutil
import ssl
import subprocess
import sys
import threading
import time
import urllib.error
import urllib.request
from dataclasses import dataclass
from pathlib import Path
from typing import Any, List, Sequence

from recon.redact import redact


class PipelineError(Exception):
    """Raised when a fatal pipeline condition is encountered."""


class _DryRun:
    """Plan recorder for --dry-run: commands and HTTP requests are listed, never executed."""

    def __init__(self) -> None:
        self.active = False
        self.phase = ""
        self.root = ""  # temp runs dir, shown as <run> in the plan
        self.commands: list[tuple[str, str]] = []
        self.requests: list[tuple[str, str]] = []

    def reset(self) -> None:
        self.__init__()  # type: ignore[misc]


DRY_RUN = _DryRun()

# Phases may run concurrently (--jobs, see recon/scheduler.py) and some phases
# use their own thread pools, so every read-modify-write of a shared run file
# goes through one of these locks.
_STDERR_LOCK = threading.Lock()   # one log line at a time on stderr
_GAPS_LOCK = threading.Lock()     # gaps.txt read-dedupe-append
CONSOLE_LOCK = threading.RLock()  # console/commands.jsonl and console/<phase>.log
TOOL_FAILURES_LOCK = threading.RLock()  # tool_failures.tsv

# Set by the scheduler when the operator pressed Ctrl-C while phases run in
# worker threads (only the main thread receives KeyboardInterrupt): the next
# command or request a worker would start raises KeyboardInterrupt instead.
STOP = threading.Event()

# Commands run_cmd is running right now (any thread), for terminate_children().
_LIVE_PROCS: set[subprocess.Popen[str]] = set()
_LIVE_PROCS_LOCK = threading.Lock()

_LOG_CTX = threading.local()


def set_log_phase(phase: str) -> None:
    """Prefix this thread's log lines with '[phase X]' ('' to stop). Used only
    when phases run concurrently, so a sequential run prints exactly as before."""
    _LOG_CTX.phase = phase


def _check_stop() -> None:
    if STOP.is_set():
        raise KeyboardInterrupt


def dry_run_active() -> bool:
    return DRY_RUN.active


class Logger:
    def __init__(self, gaps_file: Path | None = None) -> None:
        self.gaps_file = gaps_file

    def _c(self, code: str, msg: str) -> None:
        if DRY_RUN.active and DRY_RUN.phase:
            return  # phase results are empty in a dry run: their messages would only mislead
        msg = redact(msg)
        tag = getattr(_LOG_CTX, "phase", "")
        if tag:
            msg = f"[phase {tag}] {msg}"
        with _STDERR_LOCK:
            if sys.stderr.isatty():
                sys.stderr.write(f"\033[{code}m{msg}\033[0m\n")
            else:
                sys.stderr.write(f"{msg}\n")
            sys.stderr.flush()

    def info(self, msg: str) -> None:
        self._c("36", f"[*] {msg}")

    def ok(self, msg: str) -> None:
        self._c("32", f"[+] {msg}")

    def warn(self, msg: str) -> None:
        if DRY_RUN.active and DRY_RUN.phase:
            return
        msg = redact(msg)
        self._c("33", f"[!] {msg}")
        if self.gaps_file is not None:
            with _GAPS_LOCK:
                self.gaps_file.parent.mkdir(parents=True, exist_ok=True)
                existing = (
                    self.gaps_file.read_text(encoding="utf-8", errors="replace").splitlines()
                    if self.gaps_file.is_file() else []
                )
                if msg not in existing:
                    with self.gaps_file.open("a", encoding="utf-8") as f:
                        f.write(f"{msg}\n")

    def error(self, msg: str) -> None:
        self._c("31", f"[-] {msg}")


@dataclass
class CmdResult:
    args: List[str]
    returncode: int
    stdout: str
    stderr: str
    timed_out: bool = False

    @property
    def combined(self) -> str:
        if self.stdout and self.stderr:
            return f"{self.stdout.rstrip()}\n{self.stderr}"
        return self.stdout or self.stderr


def have(binary: str) -> bool:
    return shutil.which(binary) is not None


def run_cmd(
    args: Sequence[str],
    *,
    timeout: int | float | None = None,
    cwd: Path | None = None,
) -> CmdResult:
    cmd_list = [str(a) for a in args]
    _check_stop()
    if DRY_RUN.active:
        DRY_RUN.commands.append((DRY_RUN.phase, shlex.join(cmd_list)))
        return CmdResult(args=cmd_list, returncode=0, stdout="", stderr="")
    try:
        proc = subprocess.Popen(
            cmd_list,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            errors="replace",
            cwd=cwd,
        )
    except OSError as exc:
        return CmdResult(
            args=cmd_list,
            returncode=127,
            stdout="",
            stderr=str(exc),
            timed_out=False,
        )
    with _LIVE_PROCS_LOCK:
        _LIVE_PROCS.add(proc)
    try:
        with proc:
            try:
                out, err = proc.communicate(timeout=timeout)
            except subprocess.TimeoutExpired:
                proc.kill()
                out, err = proc.communicate()
                return CmdResult(args=cmd_list, returncode=124, stdout=out or "", stderr=err or "", timed_out=True)
            except BaseException:
                proc.kill()  # as subprocess.run does (Ctrl-C, ...)
                raise
            return CmdResult(
                args=cmd_list,
                returncode=proc.returncode,
                stdout=out,
                stderr=err,
                timed_out=False,
            )
    finally:
        with _LIVE_PROCS_LOCK:
            _LIVE_PROCS.discard(proc)


def terminate_children() -> int:
    """SIGTERM every command run_cmd still has running; return how many.

    Used on a forced exit (second Ctrl-C while --jobs phases drain): the worker
    threads that own those commands are abandoned, so nobody else would reap
    them. Children usually got the terminal's SIGINT already (same foreground
    process group); this covers the rest (a signal sent to Scylax alone, a
    tool that ignores SIGINT). Never raises."""
    with _LIVE_PROCS_LOCK:
        procs = list(_LIVE_PROCS)
    n = 0
    for proc in procs:
        try:
            if proc.poll() is None:
                proc.terminate()
                n += 1
        except Exception:
            pass
    return n


def record_virtual_cmd(
    console_dir: Path,
    phase: str,
    cmd_str: str,
    output: str,
    *,
    title: str = "",
    returncode: int = 0,
    duration_ms: int = 0,
) -> None:
    """Record a command execution (or virtual command) to <phase>.log and commands.jsonl."""
    console_dir.mkdir(parents=True, exist_ok=True)
    log_path = console_dir / f"{phase}.log"
    cmd_str = redact(cmd_str)
    title = redact(title)
    clean_out = redact(output.rstrip())
    block = f"$ {cmd_str}\n{clean_out}\n\n"

    record = {
        "phase": str(phase),
        "title": title or (cmd_str.split()[0] if cmd_str.split() else ""),
        "cmd": cmd_str,
        "output": clean_out,
        "returncode": returncode,
        "duration_ms": duration_ms,
        "timestamp": datetime.datetime.now(datetime.timezone.utc).isoformat(),
    }
    jsonl_path = console_dir / "commands.jsonl"
    with CONSOLE_LOCK:
        with log_path.open("a", encoding="utf-8") as f:
            f.write(block)
        with jsonl_path.open("a", encoding="utf-8") as f:
            f.write(json.dumps(record) + "\n")


def reset_phase_console(console_dir: Path, phase: str) -> None:
    """Drop a phase's previous evidence so re-running it in the same run dir
    replaces its console output instead of appending a duplicate copy."""
    with CONSOLE_LOCK:
        _reset_phase_console(console_dir, phase)


def _reset_phase_console(console_dir: Path, phase: str) -> None:
    log_path = console_dir / f"{phase}.log"
    if log_path.is_file():
        log_path.unlink()
    jsonl_path = console_dir / "commands.jsonl"
    if not jsonl_path.is_file():
        return
    kept: list[str] = []
    for line in jsonl_path.read_text(encoding="utf-8", errors="replace").splitlines():
        try:
            if str(json.loads(line).get("phase")) == str(phase):
                continue
        except (json.JSONDecodeError, AttributeError):
            pass
        if line.strip():
            kept.append(line)
    jsonl_path.write_text("".join(f"{l}\n" for l in kept), encoding="utf-8")


TOOL_FAILURES_FILE = "tool_failures.tsv"

# Failures of the tool itself, as opposed to a tool that ran and found nothing:
# missing binary, Docker daemon down, timeout. These must never pass silently,
# or a finding that could not be re-checked would look resolved.
_INFRA_FAILURE_RE = re.compile(
    r"Cannot connect to the Docker daemon|docker daemon is not running|executable file not found"
    r"|command not found|No such file or directory: '|Unable to find image",
    re.IGNORECASE,
)


def tool_name(args: Sequence[str]) -> str:
    """Short tool name for a command line, looking through 'docker run ... image'."""
    parts = [str(a) for a in args]
    if not parts:
        return "?"
    if Path(parts[0]).name == "docker" and "run" in parts:
        for a in parts[parts.index("run") + 1:]:
            if not a.startswith("-") and ("/" in a or ":" in a) and not a.startswith(("/", ".")) and "=" not in a:
                return a.rsplit("/", 1)[-1].split(":", 1)[0]
    return Path(parts[0]).name


def infra_failure(res: CmdResult) -> str:
    """Why a command failed to run at all ('' if it ran)."""
    if res.timed_out:
        return "timed out"
    if res.returncode in (125, 126, 127):
        return f"could not start (exit {res.returncode})"
    m = _INFRA_FAILURE_RE.search(res.combined or "")
    if m and res.returncode != 0:
        return m.group(0)
    return ""


def record_tool_failure(run_dir: Path, phase: str, tool: str, reason: str) -> None:
    """Append a tool failure to <run_dir>/tool_failures.tsv (read by the CLI and triage)."""
    path = run_dir / TOOL_FAILURES_FILE
    line = f"{phase}\t{tool}\t{reason.replace(chr(9), ' ').replace(chr(10), ' ')[:200]}"
    with TOOL_FAILURES_LOCK:
        existing = path.read_text(encoding="utf-8").splitlines() if path.is_file() else []
        if line not in existing:
            with path.open("a", encoding="utf-8") as f:
                f.write(line + "\n")


def load_tool_failures(run_dir: Path) -> list[tuple[str, str, str]]:
    """(phase, tool, reason) for every tool that failed in a run."""
    path = run_dir / TOOL_FAILURES_FILE
    with TOOL_FAILURES_LOCK:
        if not path.is_file():
            return []
        text = path.read_text(encoding="utf-8", errors="replace")
    out = []
    for line in text.splitlines():
        parts = line.split("\t")
        if len(parts) >= 3:
            out.append((parts[0], parts[1], parts[2]))
    return out


def ev(
    console_dir: Path,
    phase: str,
    args: Sequence[str],
    *,
    timeout: int | float | None = None,
    display_cmd: str | None = None,
    title: str = "",
) -> CmdResult:
    """Run a command and append '$ cmd + output' to console/<phase>.log as report evidence.

    A command that could not run at all (see infra_failure) is also recorded in
    tool_failures.tsv so the gap is reported and triage does not mistake the
    missing results for resolved findings."""
    cmd_str = display_cmd if display_cmd is not None else shlex.join(str(a) for a in args)
    t0 = time.perf_counter()
    res = run_cmd(args, timeout=timeout)
    duration_ms = int((time.perf_counter() - t0) * 1000)
    record_virtual_cmd(
        console_dir=console_dir,
        phase=phase,
        cmd_str=cmd_str,
        output=res.combined,
        title=title,
        returncode=res.returncode,
        duration_ms=duration_ms,
    )
    reason = infra_failure(res)
    if reason:
        record_tool_failure(console_dir.parent, phase, tool_name(args), reason)
    return res


def docker_run(
    run_dir: Path,
    image_and_args: Sequence[str],
    *,
    timeout: int | float | None = None,
    mount_data: bool = True,
) -> CmdResult:
    cmd = ["docker", "run", "--rm"]
    if mount_data:
        cmd.extend(["-v", f"{run_dir}:/data"])
    cmd.extend(str(a) for a in image_and_args)
    return run_cmd(cmd, timeout=timeout)


@dataclass
class HttpResponse:
    status: int
    body: str
    headers: dict[str, str]
    final_url: str
    redirect_url: str = ""


class _NoRedirectHandler(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req: Any, fp: Any, code: int, msg: str, headers: Any, newurl: str) -> None:
        return None


def http_get(
    url: str,
    *,
    headers: dict[str, str] | None = None,
    timeout: float = 15.0,
    verify_ssl: bool = True,
    follow_redirects: bool = True,
    method: str = "GET",
    max_bytes: int | None = None,
) -> HttpResponse:
    """GET a URL. ``max_bytes`` caps how much of the body is read (and asks the
    server for that range), so probes can classify a response without
    downloading it."""
    _check_stop()
    if DRY_RUN.active:
        DRY_RUN.requests.append((DRY_RUN.phase, f"{method} {url}"))
        return HttpResponse(status=0, body="", headers={}, final_url=url, redirect_url="")
    ctx = ssl.create_default_context()
    if not verify_ssl:
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE

    handlers: list[Any] = [urllib.request.HTTPSHandler(context=ctx)]
    if not follow_redirects:
        handlers.append(_NoRedirectHandler())

    opener = urllib.request.build_opener(*handlers)
    req_headers = {"User-Agent": "Scylax/1.0"}
    if max_bytes:
        req_headers["Range"] = f"bytes=0-{max_bytes - 1}"
    if headers:
        req_headers.update(headers)
    req = urllib.request.Request(
        url,
        method=method,
        headers=req_headers,
    )
    try:
        with opener.open(req, timeout=timeout) as resp:
            raw_bytes = resp.read(max_bytes) if method != "HEAD" else b""
            headers = {k.lower(): v for k, v in resp.headers.items()}
            return HttpResponse(
                status=resp.status,
                body=raw_bytes.decode("utf-8", errors="replace"),
                headers=headers,
                final_url=resp.geturl(),
                redirect_url=headers.get("location", ""),
            )
    except urllib.error.HTTPError as exc:
        try:
            err_body = exc.read(max_bytes).decode("utf-8", errors="replace") if method != "HEAD" else ""
        except Exception:
            err_body = ""
        headers = {k.lower(): v for k, v in exc.headers.items()} if exc.headers else {}
        return HttpResponse(
            status=exc.code,
            body=err_body,
            headers=headers,
            final_url=url,
            redirect_url=headers.get("location", ""),
        )
    except Exception:
        return HttpResponse(
            status=0,
            body="",
            headers={},
            final_url=url,
            redirect_url="",
        )


def http_get_json(
    url: str,
    *,
    headers: dict[str, str] | None = None,
    timeout: float = 30.0,
) -> tuple[int, Any]:
    resp = http_get(url, headers=headers, timeout=timeout)
    if resp.status != 200 or not resp.body:
        return resp.status, None
    try:
        return resp.status, json.loads(resp.body)
    except json.JSONDecodeError:
        return resp.status, None


def ver_lt(v_actual: str, v_floor: str) -> bool:
    """Compare up to 3 numeric version components (returns True if v_actual < v_floor)."""
    def _parse(s: str) -> list[int]:
        return [int(x) for x in re.findall(r"\d+", s)[:3]]

    a = _parse(v_actual)
    b = _parse(v_floor)
    if not a or not b:
        return False
    return a < b


def dry_run_report() -> str:
    """Human-readable plan: commands in full, HTTP requests grouped by host."""
    import urllib.parse

    probe_re = re.compile(r"( -version| --version| -V| -v| version)$|^theHarvester -h$|^gh auth status$")
    lines: list[str] = []
    phases = [ph for ph in dict.fromkeys([p for p, _ in DRY_RUN.commands] + [p for p, _ in DRY_RUN.requests]) if ph]
    for ph in phases:
        lines.append(f"== Phase {ph}")
        shown: list[str] = []
        for p, cmd in DRY_RUN.commands:
            if p == ph and not probe_re.search(cmd):
                c = redact(cmd)
                if DRY_RUN.root:
                    for form in (DRY_RUN.root, DRY_RUN.root.removeprefix("/private")):
                        c = c.replace(form, "<runs>")
                if c not in shown:
                    shown.append(c)
        lines.extend(f"  $ {c}" for c in shown)
        by_host: dict[str, list[str]] = {}
        for p, req in DRY_RUN.requests:
            if p == ph:
                method, url = req.split(" ", 1)
                u = urllib.parse.urlsplit(url)
                by_host.setdefault(u.netloc, []).append(f"{method} {u.path or '/'}")
        for host, reqs in by_host.items():
            sample = ", ".join(list(dict.fromkeys(reqs))[:3])
            lines.append(f"  HTTP {host}: {len(reqs)} request(s) e.g. {redact(sample)}")
    return "\n".join(lines)
