"""Tests for config-store lint command and unknown-key detection."""

from __future__ import annotations

from pathlib import Path

import pytest

from aivm.cli.config import ConfigLintCLI, _lint_store_file


def test_lint_store_file_detects_unknown_sections(tmp_path: Path) -> None:
    fpath = tmp_path / 'config.toml'
    fpath.write_text(
        '\n'.join(
            [
                'schema_version = 3',
                'active_vm = "aivm-2404"',
                'rogue_top = "x"',
                '',
                '[[networks]]',
                'name = "aivm-net"',
                '[networks.network]',
                'bridge = "virbr-aivm"',
                '[networks.firewall]',
                'enabled = true',
                '',
                '[[vms]]',
                'name = "aivm-2404"',
                'network_name = "aivm-net"',
                '[vms.vm]',
                'name = "aivm-2404"',
                '[vms.share]',
                'host_src = "/tmp/x"',
                '',
                '[[attachments]]',
                'host_path = "/tmp/x"',
                'vm_name = "aivm-2404"',
                'mode = "shared"',
                'guest_dst = "/tmp/x"',
                'tag = "hostcode"',
                'extra = "bad"',
                '',
            ]
        ),
        encoding='utf-8',
    )
    probs = _lint_store_file(fpath)
    text = '\n'.join(probs)
    assert 'unknown top-level key' in text
    assert "vms[0] unknown key/section: 'share'" in text
    assert "attachments[0] unknown key: 'extra'" in text


def test_config_lint_cli_passes_for_clean_store(tmp_path: Path) -> None:
    fpath = tmp_path / 'config.toml'
    fpath.write_text(
        '\n'.join(
            [
                'schema_version = 3',
                'active_vm = "aivm-2404"',
                '',
                '[behavior]',
                'yes_sudo = false',
                'verbose = 3',
                '',
                '[[networks]]',
                'name = "aivm-net"',
                '[networks.network]',
                'bridge = "virbr-aivm"',
                'subnet_cidr = "10.77.0.0/24"',
                'gateway_ip = "10.77.0.1"',
                'dhcp_start = "10.77.0.100"',
                'dhcp_end = "10.77.0.200"',
                '[networks.firewall]',
                'enabled = true',
                '',
                '[[vms]]',
                'name = "aivm-2404"',
                'network_name = "aivm-net"',
                '[vms.vm]',
                'name = "aivm-2404"',
                'cpus = 2',
                'ram_mb = 2048',
                '',
                '[[attachments]]',
                'host_path = "/tmp/x"',
                'vm_name = "aivm-2404"',
                'mode = "shared"',
                'guest_dst = "/tmp/x"',
                'tag = "hostcode"',
                '',
            ]
        ),
        encoding='utf-8',
    )
    rc = ConfigLintCLI.main(argv=False, config=str(fpath), yes=True)
    assert rc == 0


def test_config_lint_reports_unknown_tools_key_without_crashing(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """Regression: an unknown ``[vms.tools]`` key aborted the store parse
    inside ``load_config_document``, so lint crashed with a traceback instead
    of reporting the very problem it exists to find."""
    fpath = tmp_path / 'config.toml'
    fpath.write_text(
        '\n'.join(
            [
                'schema_version = 7',
                'active_vm = "aivm-2404"',
                '',
                '[[vms]]',
                'name = "aivm-2404"',
                'network_name = "aivm-net"',
                '[vms.tools]',
                'kubernets = "latest"',
                '',
            ]
        ),
        encoding='utf-8',
    )
    rc = ConfigLintCLI.main(argv=False, config=str(fpath), yes=True)
    assert rc == 2
    out = capsys.readouterr().out
    assert "vms[0].tools unknown key: 'kubernets'" in out


def test_config_lint_reports_pinned_claude_spec(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """A pinned claude version parses but fails at status/provision resolve
    time, so lint must flag it instead of passing the config as clean."""
    fpath = tmp_path / 'config.toml'
    fpath.write_text(
        '\n'.join(
            [
                'schema_version = 7',
                'active_vm = "aivm-2404"',
                '',
                '[[vms]]',
                'name = "aivm-2404"',
                'network_name = "aivm-net"',
                '[vms.tools]',
                'claude = "1.2.3"',
                '',
            ]
        ),
        encoding='utf-8',
    )
    rc = ConfigLintCLI.main(argv=False, config=str(fpath), yes=True)
    assert rc == 2
    out = capsys.readouterr().out
    assert "vms[0].tools: Invalid config value [tools] claude = '1.2.3'" in out
