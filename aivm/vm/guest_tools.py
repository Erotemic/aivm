"""Registry and guest-side installers for optional developer tools."""

from __future__ import annotations

import re
import shlex
import textwrap
from collections.abc import Callable, Iterable, Iterator
from dataclasses import dataclass

from ..config import AgentVMConfig, ToolsConfig, ToolSpec
from ..errors import AIVMError

_TOOL_DISABLED_SPECS = {'', '0', 'false', 'no', 'none', 'off', 'disabled'}
_TOOL_NAME_RE = re.compile(r'^[a-z][a-z0-9-]*$')

InstallScriptBuilder = Callable[[AgentVMConfig, str, bool], str]
SpecNormalizer = Callable[[str], str]


class GuestToolConfigError(AIVMError, ValueError):
    """Base for user-config problems in the ``[tools]`` table.

    Subclasses :class:`AIVMError` so the CLI presents the message cleanly
    instead of dumping a traceback, and :class:`ValueError` for callers that
    still catch the historical bare type.
    """


class UnknownGuestToolError(GuestToolConfigError):
    """Raised when config or CLI input names a tool outside the registry."""


class GuestToolSpecError(GuestToolConfigError):
    """Raised when a known guest tool's configured spec value is invalid."""


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
    # Optional identity-aware status probe shell fragment; when unset,
    # aivm/status.py falls back to a generic `command -v` check.
    status_check: str | None = None


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
        effective = definition.normalize_spec(requested) if enabled else 'off'
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
    raise GuestToolSpecError(
        f'Invalid config value [tools] claude = {spec!r}: the official '
        'installer cannot pin a Claude Code version, so the accepted values '
        "are 'latest' (or true) to enable and 'off' (or false) to disable."
    )


def _pi_spec(spec: str) -> str:
    normalized = str(spec or '').strip().lower()
    if normalized in {'', 'latest'}:
        return 'latest'
    raise GuestToolSpecError(
        f'Invalid config value [tools] pi = {spec!r}: the official '
        'installer cannot pin a pi version, so the accepted values are '
        "'latest' (or true) to enable and 'off' (or false) to disable."
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


def _build_codex_install_script(
    cfg: AgentVMConfig, spec: str, ensure_transport: bool
) -> str:
    """Build an idempotent script using OpenAI's official installer."""
    install_dir = str(cfg.tools.bin_dir or '~/.local/bin').strip()
    release = str(spec or 'latest').strip() or 'latest'
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
INSTALL_DIR={shlex.quote(install_dir)}
case "$INSTALL_DIR" in
    '~') INSTALL_DIR="$HOME" ;;
    '~/'*) INSTALL_DIR="$HOME/${{INSTALL_DIR#'~/'}}" ;;
esac
CODEX_RELEASE={shlex.quote(release)}
{transport_bootstrap}
mkdir -p "$INSTALL_DIR"
export PATH="$INSTALL_DIR:$PATH"
if [ "$CODEX_RELEASE" != "latest" ] || [ ! -x "$INSTALL_DIR/codex" ]; then
    curl -fsSL https://chatgpt.com/codex/install.sh | env CODEX_NON_INTERACTIVE=1 CODEX_INSTALL_DIR="$INSTALL_DIR" CODEX_RELEASE="$CODEX_RELEASE" sh
fi
if [ ! -x "$INSTALL_DIR/codex" ]; then
    echo "Codex installer completed, but codex was not found in $INSTALL_DIR." >&2
    exit 1
fi
PROFILE="$HOME/.profile"
if ! grep -Fq '# >>> aivm tools PATH >>>' "$PROFILE" 2>/dev/null; then
    {{
        echo ''
        echo '# >>> aivm tools PATH >>>'
        printf '%s\\n' "case ':\\$PATH:' in"
        printf '%s\\n' "  *':$INSTALL_DIR:'*) ;;"
        printf '%s\\n' "  *) PATH='$INSTALL_DIR':\\$PATH ;;"
        printf '%s\\n' 'esac'
        printf '%s\\n' 'export PATH'
        echo '# <<< aivm tools PATH <<<'
    }} >> "$PROFILE"
fi
"$INSTALL_DIR/codex" --version
"""
    return textwrap.dedent(script).strip()


# Shared shell helpers that identify the npm package providing ``pi`` on
# PATH, embedded in both the install script and the status probe so that
# "is pi installed?" is answered identically in both places: by the owning
# package's name, never by the bare binary name.  ``aivm_version_at_least``
# compares dotted versions numerically, failing closed on non-numeric
# components (e.g. pre-release suffixes).  ``aivm_pi_identity`` resolves the
# ``pi`` executable to its real file, walks up to the nearest package.json,
# and prints "<name> <version>" (exit 0); it exits 3 when ``pi`` is not on
# PATH and 1 when ``pi`` exists but cannot be attributed to an npm package.
_PI_IDENTITY_PROBE = textwrap.dedent(r"""
    aivm_version_at_least() {
        aivm_va=$1
        aivm_vb=$2
        aivm_vi=0
        while [ "$aivm_vi" -lt 3 ] && { [ -n "$aivm_va" ] || [ -n "$aivm_vb" ]; }; do
            aivm_pa=${aivm_va%%.*}
            if [ "$aivm_pa" = "$aivm_va" ]; then aivm_va=''; else aivm_va=${aivm_va#*.}; fi
            aivm_pb=${aivm_vb%%.*}
            if [ "$aivm_pb" = "$aivm_vb" ]; then aivm_vb=''; else aivm_vb=${aivm_vb#*.}; fi
            aivm_pa=${aivm_pa:-0}
            aivm_pb=${aivm_pb:-0}
            case "$aivm_pa$aivm_pb" in
                *[!0-9]*) return 1 ;;
            esac
            if [ "$aivm_pa" -gt "$aivm_pb" ]; then return 0; fi
            if [ "$aivm_pa" -lt "$aivm_pb" ]; then return 1; fi
            aivm_vi=$((aivm_vi + 1))
        done
        return 0
    }

    aivm_pi_identity() {
        aivm_pi_bin=$(command -v pi 2>/dev/null) || return 3
        aivm_pi_file=$(readlink -f "$aivm_pi_bin" 2>/dev/null) || return 1
        aivm_pi_dir=$(dirname "$aivm_pi_file")
        while [ -n "$aivm_pi_dir" ] && [ "$aivm_pi_dir" != '/' ]; do
            if [ -f "$aivm_pi_dir/package.json" ]; then
                aivm_pi_name=$(sed -n 's/.*"name"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p' "$aivm_pi_dir/package.json" | head -n 1)
                aivm_pi_version=$(sed -n 's/.*"version"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p' "$aivm_pi_dir/package.json" | head -n 1)
                if [ -n "$aivm_pi_name" ] && [ -n "$aivm_pi_version" ]; then
                    printf '%s %s\n' "$aivm_pi_name" "$aivm_pi_version"
                    return 0
                fi
                return 1
            fi
            aivm_pi_dir=$(dirname "$aivm_pi_dir")
        done
        return 1
    }
""").strip()


# Body of the pi install script (after the shared probe header).  Kept as
# one plain string — not an f-string — so shell ${...} and brace groups
# stay literal; the two dynamic parts (transport bootstrap, shared probe)
# are joined in _build_pi_install_script. The Node prerequisite check and
# bootstrap stay in shell so the script remains testable without a real guest.
_PI_INSTALL_BODY = textwrap.dedent("""
# pi's official installer preflights for Node.js 22.19.0+ and npm; its
# own Node bootstrap is interactive-only, so in a no-tty session like
# aivm's ssh transport it fails when the toolchain is missing or old.
aivm_node_ok() {
    command -v node >/dev/null 2>&1 || return 1
    command -v npm >/dev/null 2>&1 || return 1
    aivm_node_version=$(node --version 2>/dev/null | sed 's/^v//') || return 1
    [ -n "$aivm_node_version" ] || return 1
    aivm_version_at_least "$aivm_node_version" 22.19.0
}
aivm_fetch_to() {
    aivm_fetch_url=$1
    aivm_fetch_out=$2
    if command -v curl >/dev/null 2>&1; then
        curl -fsSL "$aivm_fetch_url" -o "$aivm_fetch_out"
    elif command -v wget >/dev/null 2>&1; then
        wget -qO "$aivm_fetch_out" "$aivm_fetch_url"
    else
        echo 'Neither curl nor wget is installed; cannot download Pi prerequisites.' >&2
        return 1
    fi
}
aivm_fetch_stdout() {
    aivm_fetch_url=$1
    if command -v curl >/dev/null 2>&1; then
        curl -fsSL "$aivm_fetch_url"
    elif command -v wget >/dev/null 2>&1; then
        wget -qO- "$aivm_fetch_url"
    else
        echo 'Neither curl nor wget is installed; cannot download the Pi installer.' >&2
        return 1
    fi
}
# Install the minimum supported Node release under the guest user's home when
# the existing toolchain is missing or too old. This deliberately avoids apt:
# a broken unrelated third-party apt source must not prevent provisioning pi.
aivm_install_node_local() {
    aivm_node_version=22.19.0
    case "$(uname -m)" in
        x86_64|amd64) aivm_node_arch=x64 ;;
        aarch64|arm64) aivm_node_arch=arm64 ;;
        armv7l|armv7*) aivm_node_arch=armv7l ;;
        ppc64le) aivm_node_arch=ppc64le ;;
        s390x) aivm_node_arch=s390x ;;
        *)
            echo "Unsupported architecture for the pi Node.js bootstrap: $(uname -m)" >&2
            return 1
            ;;
    esac
    aivm_node_root=${AIVM_NODE_ROOT:-"$HOME/.local/share/aivm/node"}
    aivm_node_name="node-v${aivm_node_version}-linux-${aivm_node_arch}"
    aivm_node_home="$aivm_node_root/$aivm_node_name"
    if [ ! -x "$aivm_node_home/bin/node" ] || [ ! -x "$aivm_node_home/bin/npm" ]; then
        if [ -e "$aivm_node_home" ]; then
            echo "AIVM's Node.js bootstrap target exists but is incomplete: $aivm_node_home" >&2
            echo 'Remove that incomplete directory and re-run: aivm vm provision pi' >&2
            return 1
        fi
        for aivm_cmd in tar sha256sum awk mktemp; do
            if ! command -v "$aivm_cmd" >/dev/null 2>&1; then
                echo "Missing command required to bootstrap Node.js for pi: $aivm_cmd" >&2
                return 1
            fi
        done
        aivm_tmp=$(mktemp -d "${TMPDIR:-/tmp}/aivm-node.XXXXXX") || return 1
        aivm_archive="$aivm_node_name.tar.gz"
        aivm_dist="https://nodejs.org/dist/v${aivm_node_version}"
        aivm_fetch_to "$aivm_dist/$aivm_archive" "$aivm_tmp/$aivm_archive"
        aivm_fetch_to "$aivm_dist/SHASUMS256.txt" "$aivm_tmp/SHASUMS256.txt"
        aivm_expected=$(awk -v name="$aivm_archive" '$2 == name {print $1; exit}' "$aivm_tmp/SHASUMS256.txt")
        aivm_actual=$(sha256sum "$aivm_tmp/$aivm_archive" | awk '{print $1}')
        if [ -z "$aivm_expected" ] || [ "$aivm_expected" != "$aivm_actual" ]; then
            echo "Node.js archive checksum verification failed for $aivm_archive" >&2
            rm -rf "$aivm_tmp"
            return 1
        fi
        mkdir -p "$aivm_node_root"
        tar -xzf "$aivm_tmp/$aivm_archive" -C "$aivm_node_root"
        rm -rf "$aivm_tmp"
    fi
    AIVM_PI_NODE_BIN_DIR="$aivm_node_home/bin"
    export AIVM_PI_NODE_BIN_DIR
    export PATH="$AIVM_PI_NODE_BIN_DIR:$PATH"
}
# Global npm operations need write access to the npm prefix; use sudo
# only when the current user cannot write it directly.
aivm_npm_global() {
    if [ -w "$(npm prefix -g 2>/dev/null)" ]; then
        npm "$@"
    else
        sudo npm "$@"
    fi
}
if ! aivm_node_ok; then
    aivm_install_node_local
fi
if ! aivm_node_ok; then
    echo 'Node.js 22.19.0+ and npm are required to install pi, but no suitable toolchain was found after the user-local bootstrap.' >&2
    exit 1
fi
# pi moved from @mariozechner/pi-coding-agent (frozen at 0.73.1, with an
# unpatched credential-exposure advisory) to
# @earendil-works/pi-coding-agent (0.78.1+).  Remove the deprecated
# package before installing so its old `pi` shim cannot shadow the new
# install.
if npm ls -g --depth=0 @mariozechner/pi-coding-agent 2>/dev/null | grep -q '@mariozechner/pi-coding-agent'; then
    echo 'Removing deprecated @mariozechner/pi-coding-agent...'
    aivm_npm_global uninstall -g @mariozechner/pi-coding-agent
fi
# Decide whether the installer must run from what actually provides `pi`
# on PATH, not merely whether an executable named pi exists: a missing,
# deprecated, or too-old install all need it, but a foreign `pi` (an
# unrelated tool) is refused rather than clobbered.
aivm_need_install=1
aivm_identity_rc=0
aivm_pi_id=$(aivm_pi_identity) || aivm_identity_rc=$?
case $aivm_identity_rc in
    0)
        aivm_pi_name=${aivm_pi_id%% *}
        aivm_pi_version=${aivm_pi_id##* }
        case $aivm_pi_name in
            @earendil-works/pi-coding-agent)
                if aivm_version_at_least "$aivm_pi_version" 0.78.1; then
                    aivm_need_install=0
                    echo "pi $aivm_pi_version is already installed."
                else
                    echo "pi $aivm_pi_version is older than 0.78.1; updating."
                fi
                ;;
            @mariozechner/pi-coding-agent)
                echo "pi $aivm_pi_version is the deprecated @mariozechner package; migrating."
                ;;
            *)
                echo "refusing to install pi: the pi on PATH is owned by package '$aivm_pi_name', not @earendil-works/pi-coding-agent" >&2
                echo 'remove or rename that pi, then re-run: aivm vm provision pi' >&2
                exit 1
                ;;
        esac
        ;;
    3)
        ;;
    *)
        echo 'refusing to install pi: the pi on PATH is not an install of @earendil-works/pi-coding-agent (or its deprecated predecessor)' >&2
        echo 'remove or rename that pi, then re-run: aivm vm provision pi' >&2
        exit 1
        ;;
esac
if [ "$aivm_need_install" -eq 1 ]; then
    aivm_fetch_stdout https://pi.dev/install.sh | sh
fi
# Verify the identity of what actually provides `pi` on PATH after the
# (possibly skipped) install: a `pi` that is not
# @earendil-works/pi-coding-agent 0.78.1+ is a failure, not a success.
aivm_identity_rc=0
aivm_pi_id=$(aivm_pi_identity) || aivm_identity_rc=$?
if [ "$aivm_identity_rc" -eq 3 ]; then
    echo 'Pi installer completed, but pi was not found in PATH.' >&2
    exit 1
elif [ "$aivm_identity_rc" -ne 0 ]; then
    echo 'Pi installer completed, but the pi on PATH cannot be attributed to an npm package.' >&2
    exit 1
fi
aivm_pi_name=${aivm_pi_id%% *}
aivm_pi_version=${aivm_pi_id##* }
if [ "$aivm_pi_name" != '@earendil-works/pi-coding-agent' ] || ! aivm_version_at_least "$aivm_pi_version" 0.78.1; then
    echo "post-install verification failed: pi on PATH is '$aivm_pi_name' $aivm_pi_version, expected @earendil-works/pi-coding-agent 0.78.1 or newer" >&2
    exit 1
fi
# The no-tty installer never updates shell profiles, so add a guarded
# PATH block for wherever pi actually landed: ~/.local/bin by default,
# or the npm global prefix bin dir when the installer used a
# user-writable prefix (e.g. a user-managed node install).
PI_BIN_DIR="$HOME/.local/bin"
if [ ! -x "$HOME/.local/bin/pi" ]; then
    NPM_GLOBAL_BIN="$(npm prefix -g 2>/dev/null)/bin"
    if [ -n "$NPM_GLOBAL_BIN" ] && [ -x "$NPM_GLOBAL_BIN/pi" ]; then
        PI_BIN_DIR="$NPM_GLOBAL_BIN"
    fi
fi
export PATH="$PI_BIN_DIR:$PATH"
if ! command -v pi >/dev/null 2>&1; then
    echo 'Pi installer completed, but pi was not found in PATH.' >&2
    exit 1
fi
PROFILE="$HOME/.profile"
if [ -n "${AIVM_PI_NODE_BIN_DIR:-}" ] && ! grep -Fq '# >>> aivm pi node PATH >>>' "$PROFILE" 2>/dev/null; then
    {
        echo ''
        echo '# >>> aivm pi node PATH >>>'
        printf '%s\\n' "case ':\\$PATH:' in"
        printf '%s\\n' "  *':$AIVM_PI_NODE_BIN_DIR:'*) ;;"
        printf '%s\\n' "  *) PATH='$AIVM_PI_NODE_BIN_DIR':\\$PATH ;;"
        printf '%s\\n' 'esac'
        printf '%s\\n' 'export PATH'
        echo '# <<< aivm pi node PATH <<<'
    } >> "$PROFILE"
fi
if ! grep -Fq '# >>> aivm pi PATH >>>' "$PROFILE" 2>/dev/null; then
    {
        echo ''
        echo '# >>> aivm pi PATH >>>'
        printf '%s\\n' "case ':\\$PATH:' in"
        printf '%s\\n' "  *':$PI_BIN_DIR:'*) ;;"
        printf '%s\\n' "  *) PATH='$PI_BIN_DIR':\\$PATH ;;"
        printf '%s\\n' 'esac'
        printf '%s\\n' 'export PATH'
        echo '# <<< aivm pi PATH <<<'
    } >> "$PROFILE"
fi
pi --version
""").strip()


def _build_pi_install_script(
    cfg: AgentVMConfig, spec: str, ensure_transport: bool
) -> str:
    """Build a script that installs pi's current package with identity
    gating around the official installer.

    The official ``https://pi.dev/install.sh`` script remains the package
    install mechanism (it wraps ``npm install -g
    @earendil-works/pi-coding-agent``), but aivm gates it on the *identity*
    of whatever ``pi`` is on PATH rather than the bare binary name:

    * a missing, deprecated (``@mariozechner/pi-coding-agent``, frozen at
      0.73.1 with an unpatched credential-exposure advisory), or too-old
      install runs the installer, with the deprecated package uninstalled
      first so its old shim cannot shadow the new install;
    * a healthy ``@earendil-works/pi-coding-agent`` 0.78.1+ is a no-op;
    * a foreign ``pi`` (an unrelated tool) is refused, never clobbered;
    * after the (possibly skipped) install, the on-PATH identity is
      re-verified, so a ``pi`` that is not the expected package and
      version is a failure, not a success.

    The installer's Node prerequisite (Node.js 22.19.0+ *and* npm) is
    checked in pure shell (``node --version``) so the whole script stays
    testable with a stub ``node``. When it is unmet, the official Node.js
    22.19.0 binary archive is checksum-verified and installed under the
    guest user's AIVM data directory instead of using apt. That isolation is
    intentional: unrelated broken third-party apt sources must not block a
    targeted ``aivm vm provision pi``. The 0.78.1 and 22.19.0 floors mirror
    the package history / installer preflight; verify them against pi.dev's
    docs and https://pi.dev/install.sh when they change.

    pi.dev's installer always installs the latest release and offers no
    version pinning, so ``spec`` is 'latest' only (enforced by
    ``_pi_spec``).
    """
    del cfg, spec  # No versioned install path exists; latest is the only spec.
    transport_bootstrap = ''
    if ensure_transport:
        transport_bootstrap = """
if ! command -v curl >/dev/null 2>&1 && ! command -v wget >/dev/null 2>&1; then
    sudo apt-get update -y
    sudo DEBIAN_FRONTEND=noninteractive apt-get install -y ca-certificates curl
fi
""".strip()
    return textwrap.dedent('\n'.join((
        'set -euo pipefail',
        transport_bootstrap,
        _PI_IDENTITY_PROBE,
        _PI_INSTALL_BODY,
    ))).strip()


def _pi_status_check() -> str:
    """Build the identity-aware status probe for pi.

    A bare ``command -v pi`` would pass for the deprecated
    ``@mariozechner/pi-coding-agent`` package (frozen at 0.73.1 with an
    unpatched credential-exposure advisory) or any unrelated tool that
    happens to share the name ``pi``.  This fragment reuses the same
    identity helpers as the install script: it passes only when ``pi``
    is provided by ``@earendil-works/pi-coding-agent`` 0.78.1 or newer and
    otherwise exits nonzero with an actionable stderr diagnostic.  It is
    appended to the status probe's ``set -e`` command list, so the exits
    here terminate the whole remote command with that status.
    """
    check = textwrap.dedent("""
{
    aivm_pi_check_rc=0
    aivm_pi_id=$(aivm_pi_identity 2>/dev/null) || aivm_pi_check_rc=$?
    case $aivm_pi_check_rc in
        0)
            aivm_pi_name=${aivm_pi_id%% *}
            aivm_pi_version=${aivm_pi_id##* }
            if [ "$aivm_pi_name" = '@earendil-works/pi-coding-agent' ] && aivm_version_at_least "$aivm_pi_version" 0.78.1; then
                # Surface the verified identity on stdout: in ``aivm status
                # --detail`` this line is the evidence that ``pi`` is the
                # expected package at the expected version, not just an
                # executable with the right name.
                echo "$aivm_pi_id"
                exit 0
            fi
            if [ "$aivm_pi_name" = '@mariozechner/pi-coding-agent' ]; then
                echo "pi $aivm_pi_version on PATH is the deprecated @mariozechner/pi-coding-agent; run 'aivm vm provision pi' to migrate to @earendil-works/pi-coding-agent" >&2
            elif [ "$aivm_pi_name" = '@earendil-works/pi-coding-agent' ]; then
                echo "pi $aivm_pi_version on PATH is older than 0.78.1; run 'aivm vm provision pi' to update" >&2
            else
                echo "pi on PATH is owned by '$aivm_pi_name', not @earendil-works/pi-coding-agent" >&2
            fi
            exit 12
            ;;
        3)
            echo 'missing configured guest tool command: pi:pi' >&2
            exit 11
            ;;
        *)
            echo 'pi on PATH is not an install of @earendil-works/pi-coding-agent' >&2
            exit 12
            ;;
    esac
}
""")
    return _PI_IDENTITY_PROBE + '\n' + check.strip()


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
        GuestToolDefinition(
            name='codex',
            display_name='Codex CLI',
            description=(
                "Codex CLI installed with OpenAI's official standalone installer"
            ),
            config_default='off',
            enable_default='latest',
            required_packages=('ca-certificates', 'curl'),
            required_commands=('codex',),
            normalize_spec=_identity_spec,
            build_install_script=_build_codex_install_script,
        ),
        GuestToolDefinition(
            name='pi',
            display_name='pi',
            description=(
                'Terminal coding agent (pi.dev; Node 22.19+ required; '
                'verifies the @earendil-works/pi-coding-agent package '
                'identity and migrates the deprecated @mariozechner package)'
            ),
            config_default='off',
            enable_default='latest',
            required_packages=('ca-certificates', 'curl'),
            required_commands=('pi',),
            normalize_spec=_pi_spec,
            build_install_script=_build_pi_install_script,
            status_check=_pi_status_check(),
        ),
    )
)


# Narrow compatibility helpers for callers that still need individual script
# builders. Runtime consumers should query GUEST_TOOL_REGISTRY instead.
def _guest_tool_spec(
    cfg: AgentVMConfig, name: str, *, default: str = ''
) -> str:
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
    return _build_uv_install_script(cfg, tool.effective_spec, ensure_transport)


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
