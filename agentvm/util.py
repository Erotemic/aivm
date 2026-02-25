from __future__ import annotations

import os
import shlex
import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import Optional, Sequence

import logging

log = logging.getLogger("agentvm")

@dataclass(frozen=True)
class CmdResult:
    code: int
    stdout: str
    stderr: str

class CmdError(RuntimeError):
    def __init__(self, cmd: Sequence[str] | str, result: CmdResult):
        self.cmd = cmd
        self.result = result
        super().__init__(f"Command failed (code={result.code}): {cmd}\n{result.stderr}".strip())

def shell_join(cmd: Sequence[str]) -> str:
    return " ".join(shlex.quote(c) for c in cmd)

def run_cmd(
    cmd: Sequence[str],
    *,
    sudo: bool = False,
    check: bool = True,
    capture: bool = True,
    text: bool = True,
    input_text: Optional[str] = None,
    env: Optional[dict[str, str]] = None,
) -> CmdResult:
    if sudo and os.geteuid() != 0:
        cmd = ["sudo", *cmd]
    log.debug("RUN: %s", shell_join(cmd))
    p = subprocess.run(
        cmd,
        input=input_text if input_text is not None else None,
        capture_output=capture,
        text=text,
        env=env,
    )
    res = CmdResult(p.returncode, p.stdout or "", p.stderr or "")
    if check and p.returncode != 0:
        raise CmdError(cmd, res)
    return res

def which(cmd: str) -> Optional[str]:
    from shutil import which as _which
    return _which(cmd)

def ensure_dir(path: Path) -> None:
    path.mkdir(parents=True, exist_ok=True)

def expand(path: str) -> str:
    return os.path.expandvars(os.path.expanduser(path))
