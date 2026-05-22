"""Guest developer-tool provisioning script helpers."""

from __future__ import annotations

import shlex
import textwrap

from ..config import AgentVMConfig

_TOOL_DISABLED_SPECS = {'', '0', 'false', 'no', 'none', 'off', 'disabled'}

def _guest_tool_uv_spec(cfg: AgentVMConfig) -> str:
    """Normalize ``[tools].uv`` into a compact string spec."""
    raw = getattr(cfg.tools, 'uv', 'latest')
    if isinstance(raw, bool):
        return 'latest' if raw else 'off'
    return str(raw or '').strip()

def _guest_tool_spec(cfg: AgentVMConfig, name: str, *, default: str) -> str:
    """Normalize a compact ``[tools]`` spec to a string."""
    raw = getattr(cfg.tools, name, default)
    if isinstance(raw, bool):
        return default if raw else 'off'
    return str(raw or '').strip()

def _guest_tool_enabled(cfg: AgentVMConfig, name: str, *, default: str) -> bool:
    """Return whether a compact ``[tools]`` spec enables management."""
    return _guest_tool_spec(cfg, name, default=default).lower() not in _TOOL_DISABLED_SPECS

def _guest_tool_uv_enabled(cfg: AgentVMConfig) -> bool:
    """Return whether aivm should keep uv available in the guest."""
    return _guest_tool_enabled(cfg, 'uv', default='latest')

def _guest_tool_rust_spec(cfg: AgentVMConfig) -> str:
    """Normalize ``[tools].rust`` into a rustup toolchain spec."""
    spec = _guest_tool_spec(cfg, 'rust', default='off')
    if spec.lower() == 'latest':
        return 'stable'
    return spec

def _guest_tool_rust_enabled(cfg: AgentVMConfig) -> bool:
    """Return whether aivm should keep Rust available in the guest."""
    return _guest_tool_enabled(cfg, 'rust', default='off')

def _guest_tool_code_spec(cfg: AgentVMConfig) -> str:
    """Normalize ``[tools].code`` into a compact string spec."""
    return _guest_tool_spec(cfg, 'code', default='latest')

def _guest_tool_code_enabled(cfg: AgentVMConfig) -> bool:
    """Return whether aivm should keep the VS Code CLI available in the guest."""
    return _guest_tool_enabled(cfg, 'code', default='latest')

def _uv_installer_url(spec: str) -> str:
    """Return Astral's standalone installer URL for latest or a version."""
    version = str(spec or '').strip().strip('/')
    if not version or version.lower() == 'latest':
        return 'https://astral.sh/uv/install.sh'
    return f'https://astral.sh/uv/{version}/install.sh'

def _guest_ensure_uv_script(
    cfg: AgentVMConfig,
    *,
    ensure_transport: bool = False,
) -> str:
    """Build an idempotent guest-side shell script that installs uv.

    The script deliberately uses Astral's standalone installer rather than
    apt/snap packages. ``aivm`` owns the PATH update with a small, marked
    ``~/.profile`` block so the upstream installer does not mutate shell
    startup files unexpectedly.
    """
    install_dir = str(getattr(cfg.tools, 'bin_dir', '~/.local/bin') or '~/.local/bin').strip()
    install_url = _uv_installer_url(_guest_tool_uv_spec(cfg))
    transport_bootstrap = ''
    if ensure_transport:
        transport_bootstrap = """
if ! command -v curl >/dev/null 2>&1 && ! command -v wget >/dev/null 2>&1; then
    sudo apt-get update -y
    sudo DEBIAN_FRONTEND=noninteractive apt-get install -y ca-certificates curl
fi
""".strip()
    script = f"""
set -euo pipefail
INSTALL_DIR={shlex.quote(install_dir)}
case "$INSTALL_DIR" in
    '~') INSTALL_DIR="$HOME" ;;
    '~/'*) INSTALL_DIR="$HOME/${{INSTALL_DIR#'~/'}}" ;;
esac
{transport_bootstrap}
mkdir -p "$INSTALL_DIR"
export PATH="$INSTALL_DIR:$HOME/.local/bin:$PATH"
if ! command -v uv >/dev/null 2>&1; then
    if command -v curl >/dev/null 2>&1; then
        curl -LsSf {shlex.quote(install_url)} | env UV_INSTALL_DIR="$INSTALL_DIR" UV_NO_MODIFY_PATH=1 sh
    elif command -v wget >/dev/null 2>&1; then
        wget -qO- {shlex.quote(install_url)} | env UV_INSTALL_DIR="$INSTALL_DIR" UV_NO_MODIFY_PATH=1 sh
    else
        echo 'Neither curl nor wget is installed; cannot install uv.' >&2
        exit 1
    fi
fi
if [ ! -x "$INSTALL_DIR/uv" ]; then
    if ! command -v uv >/dev/null 2>&1; then
        echo "uv installer completed, but uv was not found in $INSTALL_DIR or PATH" >&2
        exit 1
    fi
fi
PROFILE="$HOME/.profile"
if ! grep -Fq '# >>> aivm tools PATH >>>' "$PROFILE" 2>/dev/null; then
    {{
        echo ''
        echo '# >>> aivm tools PATH >>>'
        printf '%s\n' "case ':\\$PATH:' in"
        printf '%s\n' "  *':$INSTALL_DIR:'*) ;;"
        printf '%s\n' "  *) PATH='$INSTALL_DIR':\\$PATH ;;"
        printf '%s\n' 'esac'
        printf '%s\n' 'export PATH'
        echo '# <<< aivm tools PATH <<<'
    }} >> "$PROFILE"
fi
uv --version
"""
    return textwrap.dedent(script).strip()

def _guest_ensure_code_script(
    cfg: AgentVMConfig,
    *,
    ensure_transport: bool = False,
) -> str:
    """Build an idempotent guest-side shell script that installs the VS Code CLI.

    The script registers Microsoft's official ``packages.microsoft.com``
    apt repository (signed with ``microsoft.gpg``) and installs the ``code``
    deb package, which provides the ``code`` CLI used by
    ``code tunnel`` workflows. Snap is intentionally avoided.
    """
    transport_bootstrap = ''
    if ensure_transport:
        transport_bootstrap = """
if ! command -v curl >/dev/null 2>&1 && ! command -v wget >/dev/null 2>&1; then
    sudo apt-get update -y
    sudo DEBIAN_FRONTEND=noninteractive apt-get install -y ca-certificates curl
fi
""".strip()
    # The MS-recommended install steps for the ``code`` deb on Ubuntu 24.04.
    # Use printf into a tempfile then sudo install so the keyring drops in
    # with mode 0644 and the source list is owned by root.
    script = f"""
set -euo pipefail
{transport_bootstrap}
sudo DEBIAN_FRONTEND=noninteractive apt-get install -y wget gpg apt-transport-https ca-certificates
KEYRING=/etc/apt/keyrings/packages.microsoft.gpg
SOURCE=/etc/apt/sources.list.d/vscode.sources
sudo install -d -m 0755 /etc/apt/keyrings
if [ ! -s "$KEYRING" ]; then
    TMPKEY=$(mktemp)
    wget -qO- https://packages.microsoft.com/keys/microsoft.asc | gpg --dearmor > "$TMPKEY"
    sudo install -m 0644 "$TMPKEY" "$KEYRING"
    rm -f "$TMPKEY"
fi
if [ ! -s "$SOURCE" ]; then
    sudo tee "$SOURCE" >/dev/null <<EOF
Types: deb
URIs: https://packages.microsoft.com/repos/code
Suites: stable
Components: main
Architectures: amd64,arm64,armhf
Signed-By: $KEYRING
EOF
fi
sudo apt-get update -y
if ! command -v code >/dev/null 2>&1; then
    sudo DEBIAN_FRONTEND=noninteractive apt-get install -y code
fi
code --version
"""
    return textwrap.dedent(script).strip()

def _guest_ensure_rust_script(
    cfg: AgentVMConfig,
    *,
    ensure_transport: bool = False,
) -> str:
    """Build an idempotent guest-side shell script that installs Rust.

    The script uses rustup, not apt/snap Rust packages. It avoids upstream
    profile mutation with ``--no-modify-path`` and owns a small marked PATH
    block for Cargo's bin directory.
    """
    toolchain = _guest_tool_rust_spec(cfg) or 'stable'
    rustup_url = 'https://sh.rustup.rs'
    transport_bootstrap = ''
    if ensure_transport:
        transport_bootstrap = """
if ! command -v curl >/dev/null 2>&1 && ! command -v wget >/dev/null 2>&1; then
    sudo apt-get update -y
    sudo DEBIAN_FRONTEND=noninteractive apt-get install -y ca-certificates curl
fi
""".strip()
    script = f"""
set -euo pipefail
RUST_TOOLCHAIN={shlex.quote(toolchain)}
RUSTUP_URL={shlex.quote(rustup_url)}
export CARGO_HOME="${{CARGO_HOME:-$HOME/.cargo}}"
export RUSTUP_HOME="${{RUSTUP_HOME:-$HOME/.rustup}}"
export PATH="$CARGO_HOME/bin:$PATH"
{transport_bootstrap}
mkdir -p "$CARGO_HOME" "$RUSTUP_HOME"
if ! command -v rustup >/dev/null 2>&1; then
    if command -v curl >/dev/null 2>&1; then
        curl --proto '=https' --tlsv1.2 -sSf "$RUSTUP_URL" | sh -s -- -y --profile minimal --default-toolchain "$RUST_TOOLCHAIN" --no-modify-path
    elif command -v wget >/dev/null 2>&1; then
        wget -qO- "$RUSTUP_URL" | sh -s -- -y --profile minimal --default-toolchain "$RUST_TOOLCHAIN" --no-modify-path
    else
        echo 'Neither curl nor wget is installed; cannot install Rust via rustup.' >&2
        exit 1
    fi
else
    rustup toolchain install "$RUST_TOOLCHAIN" --profile minimal
    rustup default "$RUST_TOOLCHAIN"
fi
if ! command -v rustup >/dev/null 2>&1 || ! command -v cargo >/dev/null 2>&1 || ! command -v rustc >/dev/null 2>&1; then
    echo 'Rust installation completed, but rustup/cargo/rustc was not found in PATH.' >&2
    exit 1
fi
PROFILE="$HOME/.profile"
if ! grep -Fq '# >>> aivm rust PATH >>>' "$PROFILE" 2>/dev/null; then
    {{
        echo ''
        echo '# >>> aivm rust PATH >>>'
        printf '%s\n' "case ':\\$PATH:' in"
        printf '%s\n' "  *':$CARGO_HOME/bin:'*) ;;"
        printf '%s\n' "  *) PATH='$CARGO_HOME/bin':\\$PATH ;;"
        printf '%s\n' 'esac'
        printf '%s\n' 'export PATH'
        echo '# <<< aivm rust PATH <<<'
    }} >> "$PROFILE"
fi
rustup --version
rustc --version
cargo --version
"""
    return textwrap.dedent(script).strip()
