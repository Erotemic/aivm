"""Registry and guest-side installers for optional developer tools."""

from __future__ import annotations

import re
import shlex
import textwrap
from collections.abc import Callable, Iterable, Iterator
from dataclasses import dataclass

from ..config import AgentVMConfig, ToolSpec, ToolsConfig

_TOOL_DISABLED_SPECS = {'', '0', 'false', 'no', 'none', 'off', 'disabled'}
_TOOL_NAME_RE = re.compile(r'^[a-z][a-z0-9-]*$')

InstallScriptBuilder = Callable[[AgentVMConfig, str, bool], str]
SpecNormalizer = Callable[[str], str]


class UnknownGuestToolError(ValueError):
    """Raised when config or CLI input names a tool outside the registry."""


@dataclass(frozen=True)
class GuestToolDefinition:
    """All metadata consumers need for one optional guest tool."""

    name: str
    display_name: str
    description: str
    config_default: str
    enable_default: str
    required_packages: tuple[str, ...]
    required_commands: tuple[str, ...]
    normalize_spec: SpecNormalizer
    build_install_script: InstallScriptBuilder


@dataclass(frozen=True)
class ResolvedGuestTool:
    """One registry definition resolved against a concrete tools config."""

    definition: GuestToolDefinition
    requested_spec: str
    effective_spec: str
    enabled: bool

    @property
    def name(self) -> str:
        return self.definition.name

    def install_script(
        self, cfg: AgentVMConfig, *, ensure_transport: bool = False
    ) -> str:
        if not self.enabled:
            raise ValueError(f'guest tool {self.name!r} is disabled')
        return self.definition.build_install_script(
            cfg, self.effective_spec, ensure_transport
        )


class GuestToolRegistry:
    """Ordered source of truth for optional guest-tool behavior."""

    def __init__(self, definitions: Iterable[GuestToolDefinition]) -> None:
        ordered = tuple(definitions)
        by_name: dict[str, GuestToolDefinition] = {}
        for definition in ordered:
            if not _TOOL_NAME_RE.fullmatch(definition.name):
                raise ValueError(
                    f'invalid guest tool name: {definition.name!r}'
                )
            if definition.name in by_name:
                raise ValueError(
                    f'duplicate guest tool definition: {definition.name!r}'
                )
            if not definition.enable_default.strip():
                raise ValueError(
                    f'guest tool {definition.name!r} has an empty enable default'
                )
            if not definition.required_commands:
                raise ValueError(
                    f'guest tool {definition.name!r} has no status commands'
                )
            by_name[definition.name] = definition
        self._ordered = ordered
        self._by_name = by_name

    def __iter__(self) -> Iterator[GuestToolDefinition]:
        return iter(self._ordered)

    def names(self) -> tuple[str, ...]:
        return tuple(definition.name for definition in self._ordered)

    def get(self, name: str) -> GuestToolDefinition | None:
        return self._by_name.get(str(name))

    def require(self, name: str) -> GuestToolDefinition:
        definition = self.get(name)
        if definition is None:
            known = ', '.join(self.names())
            raise UnknownGuestToolError(
                f'Unknown guest tool {name!r}. Known tools: {known}.'
            )
        return definition

    def config_values(self, tools: ToolsConfig) -> dict[str, ToolSpec]:
        """Return flat config values in deterministic registry order."""
        return {
            definition.name: tools.get(
                definition.name, definition.config_default
            )
            for definition in self._ordered
        }

    def resolve(self, tools: ToolsConfig, name: str) -> ResolvedGuestTool:
        definition = self.require(name)
        raw = tools.get(name, definition.config_default)
        if isinstance(raw, bool):
            requested = definition.enable_default if raw else 'off'
        else:
            requested = str(raw or '').strip()
        enabled = requested.lower() not in _TOOL_DISABLED_SPECS
        effective = (
            definition.normalize_spec(requested)
            if enabled
            else 'off'
        )
        if enabled and not effective.strip():
            effective = definition.normalize_spec(definition.enable_default)
        return ResolvedGuestTool(
            definition=definition,
            requested_spec=requested,
            effective_spec=effective,
            enabled=enabled,
        )

    def resolve_all(self, tools: ToolsConfig) -> tuple[ResolvedGuestTool, ...]:
        return tuple(self.resolve(tools, name) for name in self.names())

    def enabled(self, tools: ToolsConfig) -> tuple[ResolvedGuestTool, ...]:
        return tuple(tool for tool in self.resolve_all(tools) if tool.enabled)

    def apply_enable_overrides(
        self, tools: ToolsConfig, names: Iterable[str]
    ) -> None:
        """Enable named tools for one invocation after validating all names."""
        requested = tuple(str(name) for name in names)
        definitions = tuple(self.require(name) for name in requested)
        for definition in definitions:
            tools.set(definition.name, definition.enable_default)

    def required_packages(self, tools: ToolsConfig) -> tuple[str, ...]:
        """Return deduplicated apt prerequisites for enabled tools."""
        packages: list[str] = []
        seen: set[str] = set()
        for resolved in self.enabled(tools):
            for package in resolved.definition.required_packages:
                if package not in seen:
                    packages.append(package)
                    seen.add(package)
        return tuple(packages)

    def install_scripts(
        self, cfg: AgentVMConfig, *, ensure_transport: bool = False
    ) -> tuple[str, ...]:
        return tuple(
            tool.install_script(cfg, ensure_transport=ensure_transport)
            for tool in self.enabled(cfg.tools)
        )

    def command_requirements(
        self, tools: ToolsConfig
    ) -> tuple[tuple[str, str], ...]:
        """Return ``(tool_name, command)`` probes for enabled tools."""
        return tuple(
            (tool.name, command)
            for tool in self.enabled(tools)
            for command in tool.definition.required_commands
        )


def _identity_spec(spec: str) -> str:
    return spec.strip()


def _rust_spec(spec: str) -> str:
    normalized = spec.strip()
    return 'stable' if normalized.lower() == 'latest' else normalized


def _claude_spec(spec: str) -> str:
    normalized = spec.strip().lower()
    if normalized in {'', 'latest'}:
        return 'latest'
    raise ValueError(
        f"Claude only supports the specs 'latest' and 'off', not {spec!r}"
    )


def _uv_installer_url(spec: str) -> str:
    """Return Astral's standalone installer URL for latest or a version."""
    version = str(spec or '').strip().strip('/')
    if not version or version.lower() == 'latest':
        return 'https://astral.sh/uv/install.sh'
    return f'https://astral.sh/uv/{version}/install.sh'


def _build_uv_install_script(
    cfg: AgentVMConfig, spec: str, ensure_transport: bool
) -> str:
    """Build an idempotent guest-side shell script that installs uv."""
    install_dir = str(cfg.tools.bin_dir or '~/.local/bin').strip()
    install_url = _uv_installer_url(spec)
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


def _build_code_install_script(
    cfg: AgentVMConfig, spec: str, ensure_transport: bool
) -> str:
    """Build an idempotent script using Microsoft's official apt repo."""
    del cfg, spec
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


def _build_claude_install_script(
    cfg: AgentVMConfig, spec: str, ensure_transport: bool
) -> str:
    """Build an idempotent script using Anthropic's official installer."""
    del cfg, spec
    transport_bootstrap = ''
    if ensure_transport:
        transport_bootstrap = """
if ! command -v curl >/dev/null 2>&1; then
    sudo apt-get update -y
    sudo DEBIAN_FRONTEND=noninteractive apt-get install -y ca-certificates curl
fi
""".strip()
    script = f"""
set -euo pipefail
{transport_bootstrap}
CLAUDE_BIN_DIR="$HOME/.local/bin"
export PATH="$CLAUDE_BIN_DIR:$PATH"
if ! command -v claude >/dev/null 2>&1; then
    curl -fsSL https://claude.ai/install.sh | bash
fi
if ! command -v claude >/dev/null 2>&1; then
    echo 'Claude installer completed, but claude was not found in PATH.' >&2
    exit 1
fi
PROFILE="$HOME/.profile"
if ! grep -Fq '# >>> aivm claude PATH >>>' "$PROFILE" 2>/dev/null; then
    {{
        echo ''
        echo '# >>> aivm claude PATH >>>'
        printf '%s\n' "case ':\\$PATH:' in"
        printf '%s\n' "  *':$CLAUDE_BIN_DIR:'*) ;;"
        printf '%s\n' "  *) PATH='$CLAUDE_BIN_DIR':\\$PATH ;;"
        printf '%s\n' 'esac'
        printf '%s\n' 'export PATH'
        echo '# <<< aivm claude PATH <<<'
    }} >> "$PROFILE"
fi
claude --version
"""
    return textwrap.dedent(script).strip()


def _build_rust_install_script(
    cfg: AgentVMConfig, spec: str, ensure_transport: bool
) -> str:
    """Build an idempotent guest-side script that installs Rust via rustup."""
    del cfg
    toolchain = spec or 'stable'
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


# Adding a tool should require one definition here plus its installer builder.
# CLI validation, config defaults, package prerequisites, provisioning order,
# and status probes all derive from this ordered registry.
GUEST_TOOL_REGISTRY = GuestToolRegistry(
    (
        GuestToolDefinition(
            name='uv',
            display_name='uv',
            description='Astral uv Python package and environment manager',
            config_default='latest',
            enable_default='latest',
            required_packages=('ca-certificates', 'curl'),
            required_commands=('uv',),
            normalize_spec=_identity_spec,
            build_install_script=_build_uv_install_script,
        ),
        GuestToolDefinition(
            name='rust',
            display_name='Rust',
            description='Rust toolchain installed and managed with rustup',
            config_default='off',
            enable_default='stable',
            required_packages=(
                'ca-certificates',
                'curl',
                'build-essential',
                'pkg-config',
                'libssl-dev',
            ),
            required_commands=('rustup', 'cargo', 'rustc'),
            normalize_spec=_rust_spec,
            build_install_script=_build_rust_install_script,
        ),
        GuestToolDefinition(
            name='code',
            display_name='VS Code CLI',
            description='VS Code CLI for Remote Tunnels workflows',
            config_default='off',
            enable_default='latest',
            required_packages=(
                'ca-certificates',
                'wget',
                'gpg',
                'apt-transport-https',
            ),
            required_commands=('code',),
            normalize_spec=_identity_spec,
            build_install_script=_build_code_install_script,
        ),
        GuestToolDefinition(
            name='claude',
            display_name='Claude Code',
            description=(
                "Claude Code installed with Anthropic's official installer"
            ),
            config_default='off',
            enable_default='latest',
            required_packages=('ca-certificates', 'curl'),
            required_commands=('claude',),
            normalize_spec=_claude_spec,
            build_install_script=_build_claude_install_script,
        ),
    )
)


# Narrow compatibility helpers for callers that still need individual script
# builders. Runtime consumers should query GUEST_TOOL_REGISTRY instead.
def _guest_tool_spec(cfg: AgentVMConfig, name: str, *, default: str = '') -> str:
    definition = GUEST_TOOL_REGISTRY.get(name)
    if definition is None:
        raw = cfg.tools.get(name, default)
        return str(raw or '').strip()
    return GUEST_TOOL_REGISTRY.resolve(cfg.tools, name).effective_spec


def _guest_tool_enabled(
    cfg: AgentVMConfig, name: str, *, default: str = ''
) -> bool:
    del default
    return GUEST_TOOL_REGISTRY.resolve(cfg.tools, name).enabled


def _guest_tool_uv_spec(cfg: AgentVMConfig) -> str:
    return GUEST_TOOL_REGISTRY.resolve(cfg.tools, 'uv').effective_spec


def _guest_tool_uv_enabled(cfg: AgentVMConfig) -> bool:
    return GUEST_TOOL_REGISTRY.resolve(cfg.tools, 'uv').enabled


def _guest_tool_rust_spec(cfg: AgentVMConfig) -> str:
    return GUEST_TOOL_REGISTRY.resolve(cfg.tools, 'rust').effective_spec


def _guest_tool_rust_enabled(cfg: AgentVMConfig) -> bool:
    return GUEST_TOOL_REGISTRY.resolve(cfg.tools, 'rust').enabled


def _guest_tool_code_spec(cfg: AgentVMConfig) -> str:
    return GUEST_TOOL_REGISTRY.resolve(cfg.tools, 'code').effective_spec


def _guest_tool_code_enabled(cfg: AgentVMConfig) -> bool:
    return GUEST_TOOL_REGISTRY.resolve(cfg.tools, 'code').enabled


def _guest_ensure_uv_script(
    cfg: AgentVMConfig, *, ensure_transport: bool = False
) -> str:
    tool = GUEST_TOOL_REGISTRY.resolve(cfg.tools, 'uv')
    return _build_uv_install_script(
        cfg, tool.effective_spec, ensure_transport
    )


def _guest_ensure_rust_script(
    cfg: AgentVMConfig, *, ensure_transport: bool = False
) -> str:
    tool = GUEST_TOOL_REGISTRY.resolve(cfg.tools, 'rust')
    return _build_rust_install_script(
        cfg, tool.effective_spec, ensure_transport
    )


def _guest_ensure_code_script(
    cfg: AgentVMConfig, *, ensure_transport: bool = False
) -> str:
    tool = GUEST_TOOL_REGISTRY.resolve(cfg.tools, 'code')
    return _build_code_install_script(
        cfg, tool.effective_spec, ensure_transport
    )
