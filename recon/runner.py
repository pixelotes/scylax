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
import time
import urllib.error
import urllib.request
from dataclasses import dataclass
from pathlib import Path
from typing import Any, List, Sequence


class PipelineError(Exception):
    """Raised when a fatal pipeline condition is encountered."""


class Logger:
    def __init__(self, gaps_file: Path | None = None) -> None:
        self.gaps_file = gaps_file

    def _c(self, code: str, msg: str) -> None:
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
        self._c("33", f"[!] {msg}")
        if self.gaps_file is not None:
            self.gaps_file.parent.mkdir(parents=True, exist_ok=True)
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
    try:
        proc = subprocess.run(
            cmd_list,
            capture_output=True,
            text=True,
            errors="replace",
            timeout=timeout,
            cwd=cwd,
            check=False,
        )
        return CmdResult(
            args=cmd_list,
            returncode=proc.returncode,
            stdout=proc.stdout,
            stderr=proc.stderr,
            timed_out=False,
        )
    except subprocess.TimeoutExpired as exc:
        out = exc.stdout.decode("utf-8", errors="replace") if isinstance(exc.stdout, bytes) else (exc.stdout or "")
        err = exc.stderr.decode("utf-8", errors="replace") if isinstance(exc.stderr, bytes) else (exc.stderr or "")
        return CmdResult(
            args=cmd_list,
            returncode=124,
            stdout=out,
            stderr=err,
            timed_out=True,
        )
    except OSError as exc:
        return CmdResult(
            args=cmd_list,
            returncode=127,
            stdout="",
            stderr=str(exc),
            timed_out=False,
        )


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
    clean_out = output.rstrip()
    block = f"$ {cmd_str}\n{clean_out}\n\n"
    with log_path.open("a", encoding="utf-8") as f:
        f.write(block)

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
    with jsonl_path.open("a", encoding="utf-8") as f:
        f.write(json.dumps(record) + "\n")


def ev(
    console_dir: Path,
    phase: str,
    args: Sequence[str],
    *,
    timeout: int | float | None = None,
    display_cmd: str | None = None,
    title: str = "",
) -> CmdResult:
    """Run a command and append '$ cmd + output' to console/<phase>.log as report evidence."""
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
) -> HttpResponse:
    ctx = ssl.create_default_context()
    if not verify_ssl:
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE

    handlers: list[Any] = [urllib.request.HTTPSHandler(context=ctx)]
    if not follow_redirects:
        handlers.append(_NoRedirectHandler())

    opener = urllib.request.build_opener(*handlers)
    req_headers = {"User-Agent": "recon-pipeline/1.0"}
    if headers:
        req_headers.update(headers)
    req = urllib.request.Request(
        url,
        method=method,
        headers=req_headers,
    )
    try:
        with opener.open(req, timeout=timeout) as resp:
            raw_bytes = resp.read() if method != "HEAD" else b""
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
            err_body = exc.read().decode("utf-8", errors="replace") if method != "HEAD" else ""
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
