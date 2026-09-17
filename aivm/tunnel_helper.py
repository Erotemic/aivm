"""Host-side access to the standalone VS Code tunnel helper resource."""

from __future__ import annotations

from importlib import resources

TUNNEL_HELPER_PATH = '/usr/local/libexec/aivm/code-tunnel'
DEFAULT_TMUX_SESSION = 'aivm-tunnel'


def tunnel_helper_source() -> str:
    """Return the standalone helper source installed in managed guests."""
    return (
        resources.files('aivm')
        .joinpath('rc', 'guest', 'tunnel_helper.py')
        .read_text(encoding='utf-8')
    )
