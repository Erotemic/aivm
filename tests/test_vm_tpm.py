"""Device lifecycle contracts; fake only the external libvirt daemon."""
from pathlib import Path
import xml.etree.ElementTree as ET

import pytest

from aivm.config import AgentVMConfig
from aivm.errors import AIVMError
from aivm.util import CmdResult
from aivm.vm import tpm
from aivm.vm.create import build_virt_install_cmd
from tests.helpers import activate_manager, normalize_cmd


CAPS = '''<domainCapabilities><devices><tpm supported="yes">
<enum name="model"><value>tpm-crb</value></enum>
<enum name="backendModel"><value>emulator</value></enum>
<enum name="backendVersion"><value>2.0</value></enum>
</tpm></devices></domainCapabilities>'''
XML = '''<domain type="kvm"><name>test</name><uuid>9dc48c15-9fc7-44c2-807a-815368bb9674</uuid>
<metadata><owner xmlns="urn:example">original</owner></metadata>
<devices><disk type="file"><source file="/keep/disk.qcow2"/></disk>
<filesystem><target dir="workspace"/></filesystem></devices></domain>'''


@pytest.fixture
def daemon(monkeypatch):
    activate_manager(monkeypatch)
    state = dict(xml=XML, power='shut off', saved='no', caps=CAPS,
                 calls=[], definitions=[], fail=False)

    def run(self, cmd, **kwargs):
        cmd = normalize_cmd(cmd)
        state['calls'].append(cmd)
        verb = cmd[1]
        if verb == 'dumpxml':
            assert '--inactive' in cmd
            return CmdResult(0, state['xml'], '')
        if verb == 'domstate':
            return CmdResult(0, state['power'], '')
        if verb == 'dominfo':
            return CmdResult(0, 'Managed save: ' + state['saved'], '')
        if verb == 'domcapabilities':
            return CmdResult(0, state['caps'], '')
        if verb == 'define':
            assert '--validate' in cmd
            state['definitions'].append(Path(cmd[2]).read_text())
            if state['fail']:
                raise AIVMError('definition rejected')
            state['xml'] = state['definitions'][-1]
            return CmdResult(0, '', '')
        raise AssertionError(cmd)

    monkeypatch.setattr(tpm.CommandManager, 'run', run)
    return state


def cfg():
    result = AgentVMConfig()
    result.vm.name = 'test'
    result.vm.tpm = 'emulator'
    return result


def test_creation_modes_are_explicit():
    config = cfg()
    args = build_virt_install_cmd(config, vm_disk='/disk', seed_iso='/seed')
    assert args[args.index('--tpm') + 1] == 'backend.type=emulator,backend.version=2.0,model=tpm-crb'
    config.vm.tpm = 'none'
    args = build_virt_install_cmd(config, vm_disk='/disk', seed_iso='/seed')
    assert args[args.index('--tpm') + 1] == 'none'
    config.vm.tpm = 'typo'
    with pytest.raises(AIVMError, match='vm.tpm'):
        build_virt_install_cmd(config, vm_disk='/disk', seed_iso='/seed')


def test_offline_upgrade_preserves_identity_storage_and_devices(daemon):
    assert tpm.tpm_update_needed(cfg())
    tpm.add_tpm(cfg(), dry_run=False)
    after = ET.fromstring(daemon['xml'])
    before = ET.fromstring(XML)
    for path in ('name', 'uuid', 'metadata', './devices/disk', './devices/filesystem'):
        assert ET.tostring(after.find(path)) == ET.tostring(before.find(path))
    assert tpm.emulator_tpm(after)
    assert not tpm.tpm_update_needed(cfg())
    tpm.add_tpm(cfg(), dry_run=False)
    assert len(daemon['definitions']) == 1
    assert all('destroy' not in call and 'shutdown' not in call for call in daemon['calls'])


@pytest.mark.parametrize('power', ['running', 'paused', 'crashed', 'unknown'])
def test_active_or_uncertain_vm_is_untouched(daemon, power):
    daemon['power'] = power
    with pytest.raises(AIVMError, match='shut-off'):
        tpm.add_tpm(cfg(), dry_run=False)
    assert daemon['definitions'] == []


@pytest.mark.parametrize('saved', ['yes', ''])
def test_saved_memory_cannot_restore_without_new_device(daemon, saved):
    daemon['saved'] = saved
    with pytest.raises(AIVMError, match='managed-save'):
        tpm.add_tpm(cfg(), dry_run=False)
    assert daemon['definitions'] == []


def test_dry_run_is_read_only(daemon):
    tpm.add_tpm(cfg(), dry_run=True)
    assert daemon['xml'] == XML
    assert daemon['definitions'] == []
    assert all(call[1] in {'dumpxml', 'dominfo', 'domstate'} for call in daemon['calls'])


def test_missing_host_support_does_not_downgrade(daemon):
    daemon['caps'] = '<domainCapabilities><devices><tpm supported="no"/></devices></domainCapabilities>'
    with pytest.raises(AIVMError, match='no weaker fallback'):
        tpm.add_tpm(cfg(), dry_run=False)
    assert daemon['definitions'] == []


def test_conflicting_existing_device_is_never_replaced(daemon):
    daemon['xml'] = XML.replace('</devices>', '<tpm model="tpm-tis"><backend type="passthrough"/></tpm></devices>')
    with pytest.raises(AIVMError, match='refusing replacement'):
        tpm.add_tpm(cfg(), dry_run=False)
    assert daemon['definitions'] == []
    config = cfg()
    config.vm.tpm = 'none'
    assert not tpm.tpm_update_needed(config)


def test_redefine_failure_preserves_original(daemon):
    daemon['fail'] = True
    with pytest.raises(AIVMError, match='rejected'):
        tpm.add_tpm(cfg(), dry_run=False)
    assert daemon['xml'] == XML


def test_concurrent_domain_edit_is_not_overwritten(daemon, monkeypatch):
    original = tpm._require_offline
    count = 0

    def check(config):
        nonlocal count
        original(config)
        count += 1
        if count == 2:
            daemon['xml'] = XML.replace('workspace', 'changed-workspace')

    monkeypatch.setattr(tpm, '_require_offline', check)
    with pytest.raises(AIVMError, match='changed during TPM review'):
        tpm.add_tpm(cfg(), dry_run=False)
    assert daemon['definitions'] == []


def test_persist_hardware_does_not_reenroll_or_change_active_vm(monkeypatch, tmp_path):
    from aivm.config_store import Store, load_store, save_store, upsert_vm
    store = Store()
    config = cfg()
    config.vm.tpm = 'none'
    upsert_vm(store, config)
    store.active_vm = 'another-vm'
    path = tmp_path / 'store.toml'
    activate_manager(monkeypatch)
    save_store(store, path)
    tpm.persist_tpm_choice(cfg(), path)
    saved = load_store(path)
    assert saved.active_vm == 'another-vm'
    assert saved.vms[0].cfg.vm.tpm == 'emulator'
    assert saved.principals == []


@pytest.mark.parametrize('dry_run', [False, True])
def test_update_cli_applies_choice_and_only_persists_success(monkeypatch, tmp_path, dry_run):
    from aivm.cli.vm_update import VMUpdateCLI
    config = cfg()
    config.vm.tpm = 'none'
    calls = []
    monkeypatch.setattr('aivm.cli.vm_update.load_cfg_with_path',
                        lambda *a, **k: (config, tmp_path / 'store.toml'))
    monkeypatch.setattr('aivm.cli.vm_update.run_vm_update',
                        lambda request: calls.append(('apply', request.cfg.vm.tpm)) or 0)
    monkeypatch.setattr(tpm, 'persist_tpm_choice',
                        lambda *a: calls.append(('persist', config.vm.tpm)))
    assert VMUpdateCLI.main(argv=False, tpm='emulator', dry_run=dry_run, yes=True) == 0
    assert calls == [('apply', 'emulator')] + ([] if dry_run else [('persist', 'emulator')])


@pytest.mark.parametrize('bad_xml', ['', '<domain>', '<network/>', '<domain/>'])
def test_missing_or_invalid_definition_never_becomes_an_empty_vm(daemon, bad_xml):
    daemon['xml'] = bad_xml
    with pytest.raises(AIVMError):
        tpm.add_tpm(cfg(), dry_run=False)
    assert daemon['definitions'] == []


def test_no_request_means_no_tpm_probe_or_removal(daemon):
    config = cfg()
    config.vm.tpm = 'none'
    assert not tpm.tpm_update_needed(config)
    assert daemon['calls'] == []


def test_disappearing_domain_with_failed_undefine_reports_recovery_uuid(monkeypatch):
    from aivm.vm import domain
    activate_manager(monkeypatch)
    present = iter([True, True, False])
    monkeypatch.setattr(domain, '_vm_defined', lambda name: next(present))
    monkeypatch.setattr(domain, 'domain_file_storage_paths', lambda name: ())
    xml = XML.replace('</devices>', tpm.TPM_XML + '</devices>')

    def run(self, cmd, **kwargs):
        cmd = normalize_cmd(cmd)
        if cmd[1] == 'dumpxml':
            return CmdResult(0, xml, '')
        if cmd[1] == 'destroy':
            return CmdResult(0, '', '')
        if cmd[1] == 'undefine':
            assert '--tpm' in cmd and '--remove-all-storage' in cmd
            return CmdResult(1, '', 'daemon disconnected during cleanup')
        raise AssertionError(cmd)

    monkeypatch.setattr(domain.CommandManager, 'run', run)
    with pytest.raises(AIVMError, match='TPM state removal unconfirmed.*9dc48c15'):
        domain._destroy_and_undefine_vm('test', storage_paths=())
