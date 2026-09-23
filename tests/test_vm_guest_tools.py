"""Tests for guest developer tool provisioning helpers."""

from __future__ import annotations

import shutil
import subprocess
from pathlib import Path

import pytest

from aivm.config import AgentVMConfig, dump_toml, load
from aivm.errors import AIVMError
from aivm.status import probe_provisioned
from aivm.util import CmdResult
from aivm.vm.guest_tools import (
    GUEST_TOOL_REGISTRY,
    GuestToolRegistry,
    GuestToolSpecError,
    UnknownGuestToolError,
    _build_claude_install_script,
    _build_codex_install_script,
    _build_pi_install_script,
    _guest_ensure_code_script,
    _guest_ensure_rust_script,
    _guest_ensure_uv_script,
    _guest_tool_code_enabled,
    _guest_tool_rust_enabled,
    _guest_tool_rust_spec,
    _guest_tool_uv_enabled,
    _uv_installer_url,
)


def test_guest_tool_registry_is_canonical_and_ordered() -> None:
    assert GUEST_TOOL_REGISTRY.names() == (
        'uv',
        'rust',
        'code',
        'claude',
        'codex',
        'pi',
    )
    assert [tool.name for tool in GUEST_TOOL_REGISTRY] == [
        'uv',
        'rust',
        'code',
        'claude',
        'codex',
        'pi',
    ]
    assert GUEST_TOOL_REGISTRY.require('rust').enable_default == 'stable'
    with pytest.raises(
        UnknownGuestToolError,
        match='Known tools: uv, rust, code, claude, codex, pi',
    ):
        GUEST_TOOL_REGISTRY.require('kubernetes')


def test_guest_tool_registry_rejects_duplicate_names() -> None:
    definition = GUEST_TOOL_REGISTRY.require('uv')
    with pytest.raises(ValueError, match='duplicate guest tool definition'):
        GuestToolRegistry((definition, definition))


def test_guest_tool_registry_resolves_defaults_booleans_and_overrides() -> None:
    cfg = AgentVMConfig()
    resolved = {
        tool.name: tool for tool in GUEST_TOOL_REGISTRY.resolve_all(cfg.tools)
    }
    assert resolved['uv'].enabled is True
    assert resolved['uv'].effective_spec == 'latest'
    assert resolved['rust'].enabled is False
    assert resolved['code'].enabled is False
    assert resolved['claude'].enabled is False
    assert resolved['codex'].enabled is False
    assert resolved['pi'].enabled is False

    cfg.tools.rust = True
    assert (
        GUEST_TOOL_REGISTRY.resolve(cfg.tools, 'rust').effective_spec
        == 'stable'
    )
    GUEST_TOOL_REGISTRY.apply_enable_overrides(
        cfg.tools, ['code', 'claude', 'codex']
    )
    assert cfg.tools.code == 'latest'
    assert cfg.tools.claude == 'latest'
    assert cfg.tools.codex == 'latest'


def test_guest_tool_registry_aggregates_packages_and_commands() -> None:
    cfg = AgentVMConfig()
    cfg.provision.packages = []
    cfg.tools.rust = 'stable'
    cfg.tools.code = 'latest'
    cfg.tools.claude = 'latest'
    cfg.tools.codex = 'latest'
    cfg.tools.pi = 'latest'
    packages = GUEST_TOOL_REGISTRY.required_packages(cfg.tools)
    assert packages == (
        'ca-certificates',
        'curl',
        'build-essential',
        'pkg-config',
        'libssl-dev',
        'wget',
        'gpg',
        'apt-transport-https',
    )
    assert GUEST_TOOL_REGISTRY.command_requirements(cfg.tools) == (
        ('uv', 'uv'),
        ('rust', 'rustup'),
        ('rust', 'cargo'),
        ('rust', 'rustc'),
        ('code', 'code'),
        ('claude', 'claude'),
        ('codex', 'codex'),
        ('pi', 'pi'),
    )


def test_uv_installer_url_latest_and_versioned() -> None:
    assert _uv_installer_url('latest') == 'https://astral.sh/uv/install.sh'
    assert _uv_installer_url('') == 'https://astral.sh/uv/install.sh'
    assert (
        _uv_installer_url('0.11.11')
        == 'https://astral.sh/uv/0.11.11/install.sh'
    )


def test_guest_uv_tool_spec_can_be_disabled() -> None:
    cfg = AgentVMConfig()
    assert _guest_tool_uv_enabled(cfg) is True
    cfg.tools.uv = 'off'
    assert _guest_tool_uv_enabled(cfg) is False
    setattr(cfg.tools, 'uv', False)
    assert _guest_tool_uv_enabled(cfg) is False


def test_guest_ensure_uv_script_is_standalone_and_not_snap() -> None:
    cfg = AgentVMConfig()
    cfg.tools.uv = '0.11.11'
    cfg.tools.bin_dir = '~/.local/aivm/bin'
    script = _guest_ensure_uv_script(cfg, ensure_transport=True)
    assert 'https://astral.sh/uv/0.11.11/install.sh' in script
    assert 'UV_INSTALL_DIR="$INSTALL_DIR"' in script
    assert 'UV_NO_MODIFY_PATH=1' in script
    assert '# >>> aivm tools PATH >>>' in script
    assert 'apt-get install -y ca-certificates curl' in script
    assert '~/.local/aivm/bin' in script
    assert 'snap' not in script.lower()


@pytest.mark.parametrize(
    ('bin_dir', 'expected'),
    [
        ('~/.local/bin', '/tmp/aivm-fakehome/.local/bin'),
        ('~/.local/aivm/bin', '/tmp/aivm-fakehome/.local/aivm/bin'),
        ('~', '/tmp/aivm-fakehome'),
        ('/opt/aivm/bin', '/opt/aivm/bin'),
    ],
)
def test_guest_ensure_uv_script_expands_tilde_install_dir(
    bin_dir: str, expected: str
) -> None:
    """Regression: ``${INSTALL_DIR#~/}`` tilde-expanded the pattern itself,
    so the prefix never matched and provision created a literal ``~``
    directory under ``$HOME``."""
    if shutil.which('bash') is None:
        pytest.skip('bash not available')
    cfg = AgentVMConfig()
    cfg.tools.bin_dir = bin_dir
    script = _guest_ensure_uv_script(cfg, ensure_transport=False)
    # Run only the tilde-resolution prologue so the test never invokes
    # curl/wget or the real uv installer.
    prologue_end = script.index('esac') + len('esac')
    prologue = script[:prologue_end] + '\necho "$INSTALL_DIR"\n'
    result = subprocess.run(
        ['bash', '-c', prologue],
        env={'HOME': '/tmp/aivm-fakehome', 'PATH': '/usr/bin:/bin'},
        capture_output=True,
        text=True,
        check=True,
    )
    assert result.stdout.strip() == expected


def test_guest_rust_tool_spec_can_be_enabled_or_disabled() -> None:
    cfg = AgentVMConfig()
    assert _guest_tool_rust_enabled(cfg) is False
    cfg.tools.rust = 'stable'
    assert _guest_tool_rust_enabled(cfg) is True
    assert _guest_tool_rust_spec(cfg) == 'stable'
    cfg.tools.rust = 'latest'
    assert _guest_tool_rust_spec(cfg) == 'stable'
    cfg.tools.rust = '1.83.0'
    assert _guest_tool_rust_spec(cfg) == '1.83.0'
    cfg.tools.rust = 'off'
    assert _guest_tool_rust_enabled(cfg) is False
    setattr(cfg.tools, 'rust', False)
    assert _guest_tool_rust_enabled(cfg) is False


def test_guest_ensure_rust_script_uses_rustup_and_not_snap() -> None:
    cfg = AgentVMConfig()
    cfg.tools.rust = '1.83.0'
    script = _guest_ensure_rust_script(cfg, ensure_transport=True)
    assert 'https://sh.rustup.rs' in script
    assert '--default-toolchain "$RUST_TOOLCHAIN"' in script
    assert 'RUST_TOOLCHAIN=1.83.0' in script
    assert '--profile minimal' in script
    assert '--no-modify-path' in script
    assert 'CARGO_HOME' in script
    assert 'RUSTUP_HOME' in script
    assert '# >>> aivm rust PATH >>>' in script
    assert 'apt-get install -y ca-certificates curl' in script
    assert 'snap' not in script.lower()


def test_guest_code_tool_default_off_and_opt_in() -> None:
    cfg = AgentVMConfig()
    # code is off by default — it is only useful for VS Code Remote Tunnels
    # users and should not be installed into every VM.
    assert _guest_tool_code_enabled(cfg) is False
    cfg.tools.code = 'latest'
    assert _guest_tool_code_enabled(cfg) is True
    cfg.tools.code = 'off'
    assert _guest_tool_code_enabled(cfg) is False
    setattr(cfg.tools, 'code', False)
    assert _guest_tool_code_enabled(cfg) is False


def test_guest_ensure_code_script_uses_microsoft_apt_repo_not_snap() -> None:
    cfg = AgentVMConfig()
    script = _guest_ensure_code_script(cfg, ensure_transport=True)
    assert 'packages.microsoft.com/keys/microsoft.asc' in script
    assert 'packages.microsoft.com/repos/code' in script
    assert '/etc/apt/keyrings/packages.microsoft.gpg' in script
    assert '/etc/apt/sources.list.d/vscode.sources' in script
    assert 'apt-get install -y code' in script
    assert 'apt-get install -y ca-certificates curl' in script
    assert 'snap' not in script.lower()


def test_guest_claude_tool_default_off_and_opt_in() -> None:
    cfg = AgentVMConfig()
    resolved = GUEST_TOOL_REGISTRY.resolve(cfg.tools, 'claude')
    assert resolved.enabled is False
    assert resolved.effective_spec == 'off'

    cfg.tools.claude = True
    resolved = GUEST_TOOL_REGISTRY.resolve(cfg.tools, 'claude')
    assert resolved.enabled is True
    assert resolved.effective_spec == 'latest'

    cfg.tools.claude = 'stable'
    with pytest.raises(
        GuestToolSpecError, match=r"accepted values are 'latest'"
    ):
        GUEST_TOOL_REGISTRY.resolve(cfg.tools, 'claude')


def test_guest_claude_script_uses_anthropic_installer() -> None:
    cfg = AgentVMConfig()
    script = _build_claude_install_script(cfg, 'latest', True)
    assert 'curl -fsSL https://claude.ai/install.sh | bash' in script
    assert 'apt-get install -y ca-certificates curl' in script
    assert 'command -v claude' in script
    assert 'CLAUDE_BIN_DIR="$HOME/.local/bin"' in script
    assert '# >>> aivm claude PATH >>>' in script
    assert 'claude --version' in script


def test_guest_codex_tool_default_off_and_opt_in() -> None:
    cfg = AgentVMConfig()
    resolved = GUEST_TOOL_REGISTRY.resolve(cfg.tools, 'codex')
    assert resolved.enabled is False
    assert resolved.effective_spec == 'off'

    cfg.tools.codex = True
    resolved = GUEST_TOOL_REGISTRY.resolve(cfg.tools, 'codex')
    assert resolved.enabled is True
    assert resolved.effective_spec == 'latest'

    cfg.tools.codex = '0.150.0'
    resolved = GUEST_TOOL_REGISTRY.resolve(cfg.tools, 'codex')
    assert resolved.enabled is True
    assert resolved.effective_spec == '0.150.0'


def test_guest_codex_script_uses_openai_standalone_installer() -> None:
    cfg = AgentVMConfig()
    cfg.tools.bin_dir = '~/.local/aivm/bin'
    script = _build_codex_install_script(cfg, '0.150.0', True)
    assert 'curl -fsSL https://chatgpt.com/codex/install.sh' in script
    assert 'CODEX_NON_INTERACTIVE=1' in script
    assert 'CODEX_INSTALL_DIR="$INSTALL_DIR"' in script
    assert 'CODEX_RELEASE=0.150.0' in script
    assert 'apt-get install -y ca-certificates curl' in script
    assert '~/.local/aivm/bin' in script
    assert '# >>> aivm tools PATH >>>' in script
    assert '"$INSTALL_DIR/codex" --version' in script


def test_guest_pi_tool_default_off_and_opt_in() -> None:
    cfg = AgentVMConfig()
    resolved = GUEST_TOOL_REGISTRY.resolve(cfg.tools, 'pi')
    assert resolved.enabled is False
    assert resolved.effective_spec == 'off'

    cfg.tools.pi = True
    resolved = GUEST_TOOL_REGISTRY.resolve(cfg.tools, 'pi')
    assert resolved.enabled is True
    assert resolved.effective_spec == 'latest'

    # pi.dev's installer always installs the latest release and offers no
    # version pinning, so pinned and channel specs must be rejected.
    cfg.tools.pi = '0.42.0'
    with pytest.raises(GuestToolSpecError):
        GUEST_TOOL_REGISTRY.resolve(cfg.tools, 'pi')
    cfg.tools.pi = 'stable'
    with pytest.raises(GuestToolSpecError):
        GUEST_TOOL_REGISTRY.resolve(cfg.tools, 'pi')


def test_guest_pi_script_uses_official_installer() -> None:
    cfg = AgentVMConfig()
    script = _build_pi_install_script(cfg, 'latest', True)
    assert 'aivm_fetch_stdout https://pi.dev/install.sh | sh' in script
    assert 'wget -qO-' in script
    # The Node prerequisite is checked in pure shell (node --version
    # against the 22.19.0 floor the installer preflights). When unmet,
    # AIVM fetches the official Node archive into user-owned storage rather
    # than depending on apt/NodeSource.
    assert 'aivm_node_ok' in script
    assert '22.19.0' in script
    assert 'nodejs.org/dist/v${aivm_node_version}' in script
    assert 'SHASUMS256.txt' in script
    assert 'sha256sum' in script
    assert 'AIVM_NODE_ROOT' in script
    assert 'deb.nodesource.com' not in script
    assert 'apt-get install -y nodejs' not in script
    assert 'apt-get install -y ca-certificates curl' in script
    # The local bootstrap must take precedence over a leftover user-managed
    # node on PATH and persist that path for later shells.
    assert 'AIVM_PI_NODE_BIN_DIR' in script
    assert '# >>> aivm pi node PATH >>>' in script
    # The deprecated @mariozechner/pi-coding-agent package (frozen with an
    # unpatched credential-exposure advisory) is uninstalled before the
    # installer runs, and a foreign `pi` is refused rather than clobbered.
    assert '@mariozechner/pi-coding-agent' in script
    assert 'refusing to install pi' in script
    # After the (possibly skipped) install the on-PATH identity is
    # re-verified against the expected package and version floor.
    assert '@earendil-works/pi-coding-agent' in script
    assert '0.78.1' in script
    assert 'post-install verification failed' in script
    # The tty-less installer never updates shell profiles, so the script adds
    # a guarded PATH block for wherever pi actually landed.
    assert '# >>> aivm pi PATH >>>' in script
    assert 'PI_BIN_DIR' in script
    assert 'pi --version' in script


def test_pi_status_check_is_identity_aware() -> None:
    check = GUEST_TOOL_REGISTRY.get('pi').status_check
    assert check is not None
    # The probe must attribute the pi binary to its npm package rather
    # than trusting the bare binary name or `pi --version` output.
    assert 'aivm_pi_identity' in check
    assert '@earendil-works/pi-coding-agent' in check
    assert '@mariozechner/pi-coding-agent' in check
    assert '0.78.1' in check
    assert 'exit 11' in check
    assert 'exit 12' in check
    # Every other tool keeps the generic command -v probe.
    for name in ('uv', 'rust', 'code', 'claude', 'codex'):
        assert GUEST_TOOL_REGISTRY.get(name).status_check is None


def test_tools_config_roundtrip(tmp_path: Path) -> None:
    cfg = AgentVMConfig()
    cfg.tools.uv = '0.11.11'
    cfg.tools.rust = 'stable'
    cfg.tools.code = 'latest'  # opt in (default is "off")
    cfg.tools.claude = 'latest'
    cfg.tools.codex = '0.150.0'
    cfg.tools.pi = 'latest'
    cfg.tools.bin_dir = '~/.local/aivm/bin'
    text = dump_toml(cfg)
    assert '[tools]' in text
    assert 'uv = "0.11.11"' in text
    assert 'rust = "stable"' in text
    assert 'code = "latest"' in text
    assert 'claude = "latest"' in text
    assert 'codex = "0.150.0"' in text
    assert 'pi = "latest"' in text
    assert 'bin_dir = "~/.local/aivm/bin"' in text
    assert 'install_uv' not in text
    assert 'uv_install_dir' not in text
    assert 'rust_install' not in text
    fpath = tmp_path / 'config.toml'
    fpath.write_text(text, encoding='utf-8')
    loaded = load(fpath)
    assert loaded.tools.uv == '0.11.11'
    assert loaded.tools.rust == 'stable'
    assert loaded.tools.code == 'latest'
    assert loaded.tools.claude == 'latest'
    assert loaded.tools.codex == '0.150.0'
    assert loaded.tools.pi == 'latest'
    assert loaded.tools.bin_dir == '~/.local/aivm/bin'


def test_tools_config_default_dumps_code_off(tmp_path: Path) -> None:
    cfg = AgentVMConfig()
    text = dump_toml(cfg)
    assert 'code = "off"' in text
    assert 'claude = "off"' in text
    assert 'codex = "off"' in text
    assert 'pi = "off"' in text
    fpath = tmp_path / 'config.toml'
    fpath.write_text(text, encoding='utf-8')
    loaded = load(fpath)
    assert loaded.tools.code == 'off'
    assert loaded.tools.claude == 'off'
    assert loaded.tools.codex == 'off'
    assert loaded.tools.pi == 'off'


def test_tools_config_rejects_unknown_registry_name(tmp_path: Path) -> None:
    fpath = tmp_path / 'config.toml'
    fpath.write_text(
        '[tools]\nuv = "latest"\nkubernetes = "latest"\n',
        encoding='utf-8',
    )
    with pytest.raises(UnknownGuestToolError, match='kubernetes'):
        load(fpath)


def test_tools_config_errors_are_domain_errors(tmp_path: Path) -> None:
    """Regression: ``[tools]`` config mistakes raised bare ``ValueError``,
    which escaped ``aivm.cli.main``'s ``AIVMError`` handler and crashed every
    command with a traceback instead of a clean error message."""
    fpath = tmp_path / 'config.toml'
    fpath.write_text('[tools]\nkubernetes = "latest"\n', encoding='utf-8')
    with pytest.raises(AIVMError, match='kubernetes'):
        load(fpath)

    fpath.write_text('[tools]\nuv = 3\n', encoding='utf-8')
    with pytest.raises(AIVMError, match='strings or booleans'):
        load(fpath)


def test_claude_pinned_version_is_domain_error() -> None:
    """Regression: a pinned ``claude = "1.2.3"`` spec raised bare
    ``ValueError`` at resolve time (status/provision) — also a traceback."""
    cfg = AgentVMConfig()
    cfg.tools.claude = '1.2.3'
    with pytest.raises(AIVMError, match=r"\[tools\] claude = '1.2.3'"):
        GUEST_TOOL_REGISTRY.resolve(cfg.tools, 'claude')


def test_pi_pinned_version_is_domain_error() -> None:
    """Regression: a pinned ``pi = "0.42.0"`` spec must fail as a domain
    error with the config value named, not as a bare ``ValueError``."""
    cfg = AgentVMConfig()
    cfg.tools.pi = '0.42.0'
    with pytest.raises(AIVMError, match=r"\[tools\] pi = '0.42.0'"):
        GUEST_TOOL_REGISTRY.resolve(cfg.tools, 'pi')


def test_probe_provisioned_uses_registry_command_requirements(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    cfg = AgentVMConfig()
    cfg.provision.packages = []
    cfg.provision.install_docker = False
    cfg.tools.code = 'latest'
    cfg.tools.codex = 'latest'
    cfg.tools.pi = 'latest'
    cfg.paths.ssh_identity_file = '/tmp/id_ed25519'
    captured: dict[str, str] = {}

    monkeypatch.setattr(
        'aivm.status.require_ssh_identity', lambda path: Path(path)
    )

    def fake_run(self: object, cmd: list[str], **kwargs: object) -> CmdResult:
        del self, kwargs
        captured['remote'] = cmd[-1]
        return CmdResult(0, '', '')

    monkeypatch.setattr('aivm.status.CommandManager.run', fake_run)
    outcome = probe_provisioned(cfg, '10.77.0.100')

    assert outcome.ok is True
    assert 'command -v uv' in captured['remote']
    assert 'command -v code' in captured['remote']
    assert 'command -v codex' in captured['remote']
    assert 'command -v rustup' not in captured['remote']
    # pi contributes its identity-aware fragment, not a bare command -v
    # check (the generic pattern is ``command -v pi >/dev/null 2>&1``;
    # the fragment's own probe writes ``command -v pi 2>/dev/null``).
    assert 'aivm_pi_check_rc' in captured['remote']
    assert 'aivm_pi_identity' in captured['remote']
    assert 'command -v pi >/dev/null' not in captured['remote']


def test_lifecycle_compatibility_exports_are_bound() -> None:
    from aivm.vm import lifecycle

    missing = [
        name for name in lifecycle.__all__ if not hasattr(lifecycle, name)
    ]
    assert missing == []


# ------------------------------------------------------------------
# Hermetic shell-execution tests for the pi install script and the pi
# status probe fragment.
#
# The substring assertions above prove the generated shell *contains* the
# right pieces, but they cannot prove the shell *works*: the identity walk,
# user-local Node bootstrap, PATH shadowing, deprecated-package migration,
# and refusal path only make sense when executed. Each test below builds a
# fake guest tree whose apt-get stub fails deliberately. A successful clean
# Pi bootstrap therefore proves it does not depend on unrelated apt sources.
# ------------------------------------------------------------------


_PI_HARNESS_COREUTILS = (
    'bash', 'sh', 'sed', 'head', 'dirname', 'readlink', 'grep', 'env',
    'cat', 'mkdir', 'ln', 'chmod', 'cp', 'rm', 'awk', 'mktemp', 'basename',
)

# The npm fake models the subcommands the pi script uses (prefix/ls/
# uninstall/--version); any other invocation is logged, so a regression
# that introduces an unexpected npm call is visible instead of silently
# succeeding.
_PI_STUB_NPM = r"""\
#!/bin/sh
set -eu
cmd=$1; shift
args=''
while [ $# -gt 0 ]; do
    case "$1" in
        --depth=0|-g) : ;;
        *) args=$1 ;;
    esac
    shift
done
case "$cmd" in
    prefix) echo "$NPM_PREFIX" ;;
    ls)
        dir="$NPM_PREFIX/lib/node_modules/$args"
        if [ -f "$dir/package.json" ]; then
            ver=$(sed -n 's/.*"version"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p' "$dir/package.json" | head -n 1)
            echo "$args@$ver"
        else
            exit 1
        fi
        ;;
    uninstall)
        echo "uninstall -g $args" >> "$STUB_LOG"
        rm -rf "$NPM_PREFIX/lib/node_modules/$args"
        link="$NPM_PREFIX/bin/pi"
        if [ -L "$link" ]; then
            case "$(readlink -f "$link")" in
                "$NPM_PREFIX/lib/node_modules/$args"/*) rm -f "$link" ;;
            esac
        fi
        ;;
    --version) echo 10.9.2 ;;
    *) echo "npm $cmd $args" >> "$STUB_LOG" ;;
esac
"""

# curl stands in for the Pi installer and the two files fetched from the
# official Node.js distribution. It accepts the option shapes used by the
# generated script and rejects every other URL.
_PI_STUB_CURL = r"""\
#!/bin/sh
set -eu
url=''
out=''
while [ $# -gt 0 ]; do
    case "$1" in
        -o)
            out=$2
            shift 2
            ;;
        -*) shift ;;
        *)
            url=$1
            shift
            ;;
    esac
done
case "$url" in
    https://pi.dev/install.sh)
        echo "request $url" >> "$STUB_LOG"
        cat "$INSTALLER_SCRIPT"
        ;;
    https://nodejs.org/dist/v22.19.0/node-v22.19.0-linux-x64.tar.gz)
        echo "request $url" >> "$STUB_LOG"
        printf '%s\n' 'fake-node-archive' > "$out"
        ;;
    https://nodejs.org/dist/v22.19.0/SHASUMS256.txt)
        echo "request $url" >> "$STUB_LOG"
        printf '%s  %s\n' 'deadbeef' 'node-v22.19.0-linux-x64.tar.gz' > "$out"
        ;;
    *)
        echo "unexpected curl $url" >> "$STUB_LOG"
        exit 1
        ;;
esac
"""

_PI_STUB_SHA256SUM = r"""\
#!/bin/sh
set -eu
printf '%s  %s\n' 'deadbeef' "$1"
"""

_PI_STUB_UNAME = r"""\
#!/bin/sh
set -eu
echo x86_64
"""

# tar simulates extracting the verified official Node archive into AIVM's
# user-owned Node root. The generated node/npm are the staging fixtures below.
_PI_STUB_TAR = r"""\
#!/bin/sh
set -eu
archive=''
dest=''
while [ $# -gt 0 ]; do
    case "$1" in
        -xzf)
            archive=$2
            shift 2
            ;;
        -C)
            dest=$2
            shift 2
            ;;
        *) shift ;;
    esac
done
name=$(basename "$archive" .tar.gz)
target="$dest/$name"
mkdir -p "$target/bin"
cp "$STAGING/node" "$target/bin/node"
cp "$STAGING/npm" "$target/bin/npm"
chmod +x "$target/bin/node" "$target/bin/npm"
echo "extract $archive -> $target" >> "$STUB_LOG"
"""

# Any apt invocation is a regression for these Pi tests. The transport
# fallback still contains apt for a guest that lacks curl, but curl is present
# in this harness and Node bootstrap itself must remain apt-independent.
_PI_STUB_APT_GET = r"""\
#!/bin/sh
echo "unexpected apt-get $*" >> "$STUB_LOG"
exit 99
"""

# sudo is a plain pass-through (the stubs run as the current user).
_PI_STUB_SUDO = """\
#!/bin/sh
while [ $# -gt 0 ] && [ "$1" = '-E' ]; do shift; done
exec "$@"
"""

# The staging node is the user-local Node toolchain extracted from the
# official archive.
_PI_STAGING_NODE = """\
#!/bin/sh
if [ "$1" = '--version' ]; then echo v22.19.0; exit 0; fi
echo "node unhandled: $*" >&2
exit 1
"""

# The pi.dev installer payload: installs the current earendil release
# into the npm global prefix the way the real installer does.
_PI_STUB_INSTALLER = """\
#!/bin/sh
set -eu
echo "stub installer started" >> "$STUB_LOG"
prefix=$(npm prefix -g)
dir="$prefix/lib/node_modules/@earendil-works/pi-coding-agent"
mkdir -p "$dir/bin" "$prefix/bin"
printf '%s\n' '{"name": "@earendil-works/pi-coding-agent", "version": "0.85.1", "bin": {"pi": "bin/pi.js"}}' > "$dir/package.json"
printf '%s\n' '#!/bin/sh' 'echo 0.85.1' > "$dir/bin/pi.js"
chmod +x "$dir/bin/pi.js"
ln -sf "$dir/bin/pi.js" "$prefix/bin/pi"
"""


class _PiShellHarness:
    """Fake guest tree for executing the generated pi shell.

    ``node-root`` stands in for ``~/.local/share/aivm/node``; ``stub`` holds
    fake network/privilege commands; ``core`` exposes only the ordinary Unix
    utilities the script expects; ``prefix`` is npm's global prefix; and
    ``staging`` is the verified Node payload that the tar stub extracts.
    The child environment is fully custom, so nothing else on the host PATH
    can accidentally make a test pass.
    """

    def __init__(
        self,
        base: Path,
        *,
        npm_in_stub: bool = True,
        sysbin_node: str | None = None,
    ) -> None:
        self.base = base
        self.home = base / 'home'
        self.sysbin = base / 'sysbin'
        self.stub = base / 'stub'
        self.core = base / 'core'
        self.prefix = base / 'prefix'
        self.staging = base / 'staging'
        self.node_root = base / 'node-root'
        self.log = base / 'log'
        for d in (
            self.home / '.local' / 'bin',
            self.sysbin,
            self.stub,
            self.core,
            self.prefix / 'bin',
            self.prefix / 'lib' / 'node_modules',
            self.staging,
            self.node_root,
        ):
            d.mkdir(parents=True)
        for name in _PI_HARNESS_COREUTILS:
            (self.core / name).symlink_to('/usr/bin/' + name)
        self._write(self.stub / 'curl', _PI_STUB_CURL)
        self._write(self.stub / 'sha256sum', _PI_STUB_SHA256SUM)
        self._write(self.stub / 'uname', _PI_STUB_UNAME)
        self._write(self.stub / 'tar', _PI_STUB_TAR)
        self._write(self.stub / 'sudo', _PI_STUB_SUDO)
        self._write(self.stub / 'apt-get', _PI_STUB_APT_GET)
        if npm_in_stub:
            self._write(self.stub / 'npm', _PI_STUB_NPM)
        self._write(self.staging / 'node', _PI_STAGING_NODE)
        self._write(self.staging / 'npm', _PI_STUB_NPM)
        if sysbin_node is not None:
            self.seed_sysbin(sysbin_node)
        self.log.touch()
        self._write(base / 'installer.sh', _PI_STUB_INSTALLER)
        self.run_script = base / 'run.sh'

    @staticmethod
    def _write(path: Path, body: str) -> None:
        path.write_text(body)
        path.chmod(0o755)

    def seed_sysbin(self, node_version: str) -> None:
        """Preseed a system-style Node/npm toolchain."""
        node = self.sysbin / 'node'
        node.write_text(
            '#!/bin/sh\n'
            f'if [ "$1" = --version ]; then echo v{node_version}; exit 0; fi\n'
            'echo "node unhandled: $*" >&2\nexit 1\n'
        )
        node.chmod(0o755)
        npm = self.sysbin / 'npm'
        npm.write_text(_PI_STUB_NPM)
        npm.chmod(0o755)

    def add_user_node(self, version: str) -> Path:
        """A user-managed node in ~/.local/bin (typically earlier in PATH)."""
        path = self.home / '.local' / 'bin' / 'node'
        path.write_text(
            '#!/bin/sh\n'
            f'if [ "$1" = --version ]; then echo v{version}; exit 0; fi\n'
            'echo "node unhandled: $*" >&2\nexit 1\n'
        )
        path.chmod(0o755)
        return path

    def install_pi_package(self, name: str, version: str) -> Path:
        """Install an npm global package providing ``pi`` with real shape."""
        pkg = self.prefix / 'lib' / 'node_modules' / name
        (pkg / 'bin').mkdir(parents=True)
        (pkg / 'package.json').write_text(
            '{"name": "%s", "version": "%s", "bin": {"pi": "bin/pi.js"}}\n'
            % (name, version)
        )
        pi = pkg / 'bin' / 'pi.js'
        pi.write_text(f'#!/bin/sh\necho {version}\n')
        pi.chmod(0o755)
        link = self.prefix / 'bin' / 'pi'
        if link.exists() or link.is_symlink():
            link.unlink()
        link.symlink_to(pi)
        return pi

    def add_unattributable_pi(self, version: str) -> Path:
        """A plain pi script with no package.json in any ancestor."""
        path = self.home / '.local' / 'bin' / 'pi'
        path.write_text(f'#!/bin/sh\necho {version}\n')
        path.chmod(0o755)
        return path

    def write_run_script(self, script: str) -> None:
        self.run_script.write_text('#!/bin/sh\n' + script)
        self.run_script.chmod(0o755)

    def _path(self, dirs: tuple[str, ...]) -> str:
        return ':'.join(str(self.base / d) for d in dirs)

    def default_path_dirs(self) -> tuple[str, ...]:
        # The system dir is ahead of the user dir here; the shadowing test
        # passes an explicit ordering instead.
        return ('stub', 'sysbin', 'home/.local/bin', 'prefix/bin', 'core')

    def run(
        self,
        path_dirs: tuple[str, ...] | None = None,
        timeout: float = 30.0,
    ) -> subprocess.CompletedProcess:
        env = {
            'PATH': self._path(path_dirs or self.default_path_dirs()),
            'HOME': str(self.home),
            'NPM_PREFIX': str(self.prefix),
            'STUB_LOG': str(self.log),
            'STAGING': str(self.staging),
            'INSTALLER_SCRIPT': str(self.base / 'installer.sh'),
            'AIVM_NODE_ROOT': str(self.node_root),
            'LC_ALL': 'C',
        }
        bash = shutil.which('bash') or '/usr/bin/bash'
        return subprocess.run(
            [bash, str(self.run_script)],
            env=env,
            capture_output=True,
            text=True,
            timeout=timeout,
        )

    def log_text(self) -> str:
        return self.log.read_text()

    def assert_no_unhandled_stub_calls(self) -> None:
        """The stubs log anything they do not model; none may appear."""
        log = self.log_text()
        assert 'unhandled' not in log, log
        assert 'unexpected curl' not in log, log
        assert 'unexpected apt-get' not in log, log
        for line in log.splitlines():
            # The npm fake only logs non-modeled invocations.
            assert not line.startswith('npm '), log


def _run_pi_install_script(
    harness: _PiShellHarness,
    *,
    ensure_transport: bool = True,
    path_dirs: tuple[str, ...] | None = None,
) -> subprocess.CompletedProcess:
    """Build the install script from the *current* guest_tools code and
    execute it inside the harness's hermetic guest."""
    script = _build_pi_install_script(
        AgentVMConfig(), 'latest', ensure_transport
    )
    harness.write_run_script(script)
    return harness.run(path_dirs=path_dirs)


def test_pi_install_clean_machine_bootstraps_node(tmp_path: Path) -> None:
    """Case 1: no node or npm -> verified user-local Node bootstrap ->
    installer -> healthy end state with persistent PATH blocks."""
    harness = _PiShellHarness(tmp_path / 'base')
    res = _run_pi_install_script(harness)
    assert res.returncode == 0, res.stderr
    # The final `pi --version` is the success signal (0.85.1 is the
    # version the stub installer records).
    assert res.stdout.strip() == '0.85.1'
    log = harness.log_text()
    # The official archive and checksum are fetched once; apt is never touched.
    assert log.count('request https://nodejs.org/dist/v22.19.0/node-v22.19.0-linux-x64.tar.gz') == 1
    assert log.count('request https://nodejs.org/dist/v22.19.0/SHASUMS256.txt') == 1
    assert 'apt-get' not in log
    assert 'request https://pi.dev/install.sh' in log
    assert 'stub installer started' in log
    harness.assert_no_unhandled_stub_calls()
    # The PATH block is written to $HOME/.profile and points at the
    # npm global bin dir.
    profile = (harness.home / '.profile').read_text()
    assert profile.count('# >>> aivm pi PATH >>>') == 1
    assert str(harness.prefix / 'bin') in profile
    # The fresh Node toolchain landed under AIVM's user-owned data root.
    local_node = harness.node_root / 'node-v22.19.0-linux-x64'
    assert (local_node / 'bin' / 'node').exists()
    assert (local_node / 'bin' / 'npm').exists()
    assert profile.count('# >>> aivm pi node PATH >>>') == 1
    assert str(local_node / 'bin') in profile


def test_pi_install_node_without_npm_bootstraps(tmp_path: Path) -> None:
    """Case 2: sufficient user node but no npm -> local bootstrap still
    supplies a complete toolchain without modifying the user's node."""
    harness = _PiShellHarness(tmp_path / 'base', npm_in_stub=False)
    user_node = harness.add_user_node('22.19.0')
    before = user_node.read_text()
    res = _run_pi_install_script(harness)
    assert res.returncode == 0, res.stderr
    assert res.stdout.strip() == '0.85.1'
    log = harness.log_text()
    assert 'request https://nodejs.org/dist/v22.19.0/node-v22.19.0-linux-x64.tar.gz' in log
    assert 'request https://pi.dev/install.sh' in log
    harness.assert_no_unhandled_stub_calls()
    assert user_node.read_text() == before


def test_pi_install_old_user_node_shadowed_by_local_bootstrap(tmp_path: Path) -> None:
    """Case 3: old user node earlier in PATH -> the local bootstrap's
    PATH prepend makes Node 22.19 win without touching the user's node."""
    harness = _PiShellHarness(tmp_path / 'base')
    user_node = harness.add_user_node('18.0.0')
    before = user_node.read_text()
    res = _run_pi_install_script(
        harness,
        path_dirs=('stub', 'home/.local/bin', 'sysbin', 'prefix/bin', 'core'),
    )
    assert res.returncode == 0, res.stderr
    assert res.stdout.strip() == '0.85.1'
    log = harness.log_text()
    assert log.count('request https://nodejs.org/dist/v22.19.0/node-v22.19.0-linux-x64.tar.gz') == 1
    assert 'request https://pi.dev/install.sh' in log
    harness.assert_no_unhandled_stub_calls()
    # The user's v18 node is still there and byte-identical.  rc 0 also
    # proves the v22 node won the PATH race: had the v18 still shadowed
    # it, the post-bootstrap aivm_node_ok would have exited 1.
    assert user_node.read_text() == before


def test_pi_install_migrates_deprecated_mariozechner_package(tmp_path: Path) -> None:
    """Case 4: the deprecated @mariozechner/pi-coding-agent is
    uninstalled before the installer runs, so its old pi shim cannot
    shadow the new install."""
    harness = _PiShellHarness(tmp_path / 'base', sysbin_node='22.23.2')
    old = harness.install_pi_package(
        '@mariozechner/pi-coding-agent', '0.73.1'
    )
    res = _run_pi_install_script(harness)
    assert res.returncode == 0, res.stderr
    # The migration announces itself, then the final `pi --version` is
    # the success signal.
    assert 'Removing deprecated @mariozechner/pi-coding-agent...' in res.stdout
    assert res.stdout.strip().splitlines()[-1] == '0.85.1'
    log = harness.log_text()
    assert 'uninstall -g @mariozechner/pi-coding-agent' in log
    assert 'request https://pi.dev/install.sh' in log
    # The seeded Node was adequate, so no Node archive bootstrap.
    assert 'nodejs.org/dist/' not in log
    harness.assert_no_unhandled_stub_calls()
    # The deprecated package is gone (an empty scope dir is harmless
    # residue, as with real npm); pi now resolves to earendil.
    assert not (
        harness.prefix / 'lib' / 'node_modules' / '@mariozechner'
        / 'pi-coding-agent'
    ).exists()
    assert str((harness.prefix / 'bin' / 'pi').resolve()).startswith(
        str(harness.prefix / 'lib' / 'node_modules' / '@earendil-works')
    )


def test_pi_install_healthy_package_is_noop_and_idempotent(tmp_path: Path) -> None:
    """Case 5: earendil 0.85.1 is already installed -> no install,
    the profile block is still ensured, and a second run adds nothing
    (the marker appears exactly once)."""
    harness = _PiShellHarness(tmp_path / 'base', sysbin_node='22.23.2')
    harness.install_pi_package('@earendil-works/pi-coding-agent', '0.85.1')
    res = _run_pi_install_script(harness)
    assert res.returncode == 0, res.stderr
    assert 'pi 0.85.1 is already installed.' in res.stdout
    assert res.stdout.strip().splitlines()[-1] == '0.85.1'
    assert 'request https://pi.dev/install.sh' not in harness.log_text()
    harness.assert_no_unhandled_stub_calls()
    profile = harness.home / '.profile'
    assert profile.read_text().count('# >>> aivm pi PATH >>>') == 1
    # Second run: still a no-op, and the profile block is not
    # duplicated.
    res2 = _run_pi_install_script(harness)
    assert res2.returncode == 0, res2.stderr
    assert profile.read_text().count('# >>> aivm pi PATH >>>') == 1
    log = harness.log_text()
    assert log.count('request https://pi.dev/install.sh') == 0
    harness.assert_no_unhandled_stub_calls()


def test_pi_install_refuses_foreign_pi(tmp_path: Path) -> None:
    """Case 6: a pi owned by an unrelated package is refused (exit 1,
    naming the package); the installer is not run and the fixture is
    untouched."""
    harness = _PiShellHarness(tmp_path / 'base', sysbin_node='22.23.2')
    foreign = harness.install_pi_package('@example/foreign', '1.2.3')
    before = foreign.read_text()
    res = _run_pi_install_script(harness)
    assert res.returncode == 1
    assert 'refusing to install pi' in res.stderr
    assert '@example/foreign' in res.stderr
    assert 'request https://pi.dev/install.sh' not in harness.log_text()
    harness.assert_no_unhandled_stub_calls()
    assert foreign.read_text() == before
    assert (harness.prefix / 'bin' / 'pi').resolve() == foreign.resolve()


def test_pi_install_updates_below_floor_earendil(tmp_path: Path) -> None:
    """Case 7: earendil below the 0.78.1 floor -> the installer runs to
    update it, and the post-install verification passes with the new
    version."""
    harness = _PiShellHarness(tmp_path / 'base', sysbin_node='22.23.2')
    harness.install_pi_package('@earendil-works/pi-coding-agent', '0.77.0')
    res = _run_pi_install_script(harness)
    assert res.returncode == 0, res.stderr
    assert 'pi 0.77.0 is older than 0.78.1; updating.' in res.stdout
    assert res.stdout.strip().splitlines()[-1] == '0.85.1'
    log = harness.log_text()
    assert 'request https://pi.dev/install.sh' in log
    # Updating an existing healthy-shaped install does not re-bootstrap Node.
    assert 'nodejs.org/dist/' not in log
    harness.assert_no_unhandled_stub_calls()
    pkg_json = (
        harness.prefix / 'lib' / 'node_modules'
        / '@earendil-works/pi-coding-agent' / 'package.json'
    ).read_text()
    assert '"version": "0.85.1"' in pkg_json


def _run_pi_status_check(
    harness: _PiShellHarness,
    path_dirs: tuple[str, ...] | None = None,
) -> subprocess.CompletedProcess:
    """Execute the pi status fragment exactly the way aivm/status.py
    does (as a standalone remote command under set -e)."""
    fragment = GUEST_TOOL_REGISTRY.get('pi').status_check
    assert fragment is not None
    harness.write_run_script('set -e\n' + fragment)
    return harness.run(path_dirs=path_dirs)


def test_pi_status_check_reports_healthy_identity(tmp_path: Path) -> None:
    """Healthy: exit 0, and stdout carries the verified package
    identity (the line aivm status --detail shows as probe evidence)."""
    harness = _PiShellHarness(tmp_path / 'healthy')
    harness.install_pi_package('@earendil-works/pi-coding-agent', '0.85.1')
    res = _run_pi_status_check(harness)
    assert res.returncode == 0, res.stderr
    assert res.stdout.strip() == '@earendil-works/pi-coding-agent 0.85.1'
    harness.assert_no_unhandled_stub_calls()


def test_pi_status_check_missing_exits_11(tmp_path: Path) -> None:
    harness = _PiShellHarness(tmp_path / 'missing')
    res = _run_pi_status_check(harness)
    assert res.returncode == 11
    assert 'missing configured guest tool command: pi:pi' in res.stderr


def test_pi_status_check_deprecated_exits_12(tmp_path: Path) -> None:
    harness = _PiShellHarness(tmp_path / 'deprecated')
    harness.install_pi_package('@mariozechner/pi-coding-agent', '0.73.1')
    res = _run_pi_status_check(harness)
    assert res.returncode == 12
    assert 'the deprecated @mariozechner/pi-coding-agent' in res.stderr


def test_pi_status_check_below_floor_exits_12(tmp_path: Path) -> None:
    harness = _PiShellHarness(tmp_path / 'below-floor')
    harness.install_pi_package('@earendil-works/pi-coding-agent', '0.77.0')
    res = _run_pi_status_check(harness)
    assert res.returncode == 12
    assert 'older than 0.78.1' in res.stderr


def test_pi_status_check_foreign_exits_12(tmp_path: Path) -> None:
    harness = _PiShellHarness(tmp_path / 'foreign')
    harness.install_pi_package('@example/foreign', '1.2.3')
    res = _run_pi_status_check(harness)
    assert res.returncode == 12
    assert "owned by '@example/foreign'" in res.stderr


def test_pi_status_check_unattributable_exits_12(tmp_path: Path) -> None:
    """A plain script named pi (no package.json anywhere in its
    ancestor chain) cannot be attributed and is reported as such."""
    harness = _PiShellHarness(tmp_path / 'unattributable')
    harness.add_unattributable_pi('9.9.9')
    res = _run_pi_status_check(harness)
    assert res.returncode == 12
    assert 'not an install of @earendil-works/pi-coding-agent' in res.stderr
