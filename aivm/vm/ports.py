"""SSH forward-port allocation for session-runtime VMs.

Session VMs have no routable guest IP: passt user-mode networking exposes
guest SSH through a forwarded localhost port instead. The port is chosen
deterministically from the VM name (so re-creates of the same VM land on
the same port), probed for collisions against live listeners, and
persisted in the VM state directory next to the cached IP so every later
SSH-shaped operation can recover it without libvirt queries.
"""

from __future__ import annotations

import errno
import hashlib
import socket
from pathlib import Path

from loguru import logger

from ..config import AgentVMConfig
from ..util import ensure_dir
from .paths import _paths

log = logger

#: Inclusive port range session VMs forward guest SSH into. Deliberately
#: above the common 22000-22100 ad-hoc territory and below ephemeral ports.
SESSION_SSH_PORT_BASE = 22200
SESSION_SSH_PORT_SPAN = 800

SSH_FORWARD_HOST = '127.0.0.1'


def _ssh_port_file(cfg: AgentVMConfig) -> Path:
    return _paths(cfg, dry_run=False)['state_dir'] / 'ssh-forward-port'


def deterministic_ssh_port(vm_name: str) -> int:
    """Return the preferred forward port for ``vm_name`` (pre-collision)."""
    digest = hashlib.sha256(vm_name.encode('utf-8')).digest()
    offset = int.from_bytes(digest[:4], 'big') % SESSION_SSH_PORT_SPAN
    return SESSION_SSH_PORT_BASE + offset


def _port_is_free(port: int) -> bool:
    """Return True when nothing is listening on the localhost port."""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            sock.bind((SSH_FORWARD_HOST, port))
        except OSError as ex:
            if ex.errno in {errno.EADDRINUSE, errno.EACCES}:
                return False
            raise
    return True


def read_ssh_forward_port(cfg: AgentVMConfig) -> int | None:
    """Return the persisted forward port for this VM, if any."""
    port_file = _ssh_port_file(cfg)
    try:
        raw = port_file.read_text(encoding='utf-8').strip()
    except FileNotFoundError:
        return None
    if not raw.isdigit():
        log.warning(
            'Ignoring malformed ssh forward port file {} (content {!r})',
            port_file,
            raw,
        )
        return None
    return int(raw)


def allocate_ssh_forward_port(
    cfg: AgentVMConfig, *, dry_run: bool = False
) -> int:
    """Return this VM's forward port, allocating and persisting on first use.

    A previously persisted port always wins (the domain XML already embeds
    it). Fresh allocations start at the deterministic per-name port and
    linearly probe within the range until an unused localhost port is
    found.
    """
    existing = read_ssh_forward_port(cfg)
    if existing is not None:
        return existing
    start = deterministic_ssh_port(cfg.vm.name)
    port = None
    for step in range(SESSION_SSH_PORT_SPAN):
        candidate = (
            SESSION_SSH_PORT_BASE
            + (start - SESSION_SSH_PORT_BASE + step) % SESSION_SSH_PORT_SPAN
        )
        if _port_is_free(candidate):
            port = candidate
            break
    if port is None:
        raise RuntimeError(
            'No free localhost port available for session SSH forwarding '
            f'in {SESSION_SSH_PORT_BASE}-'
            f'{SESSION_SSH_PORT_BASE + SESSION_SSH_PORT_SPAN - 1}.'
        )
    if dry_run:
        log.info(
            'DRYRUN: would persist SSH forward port {} for VM {}',
            port,
            cfg.vm.name,
        )
        return port
    port_file = _ssh_port_file(cfg)
    ensure_dir(port_file.parent)
    port_file.write_text(f'{port}\n', encoding='utf-8')
    log.info(
        'Allocated SSH forward port {} for session VM {} (saved to {})',
        port,
        cfg.vm.name,
        port_file,
    )
    return port
