"""Opt-in TPM 2.0 device lifecycle, independent of any credential broker."""
from __future__ import annotations

import json
import tempfile
import xml.etree.ElementTree as ET
from pathlib import Path

from loguru import logger as log

from ..commands import CommandManager
from ..config import AgentVMConfig
from ..errors import AIVMError
from ..privilege import virsh_needs_sudo
from ..runtime import pin_locale, virsh_cmd


TPM_REMOVAL_UNCONFIRMED = 'TPM state removal unconfirmed'
TPM_XML = '<tpm model="tpm-crb"><backend type="emulator" version="2.0" /></tpm>'


def normalize_tpm(value: str) -> str:
    if value not in {'none', 'emulator'}:
        raise AIVMError('vm.tpm must be one of: none, emulator')
    return value


def domain_xml(text: str) -> ET.Element:
    try:
        root = ET.fromstring(text)
    except ET.ParseError as ex:
        raise AIVMError('Cannot inspect TPM: invalid libvirt XML.') from ex
    if root.tag != 'domain' or root.find('devices') is None:
        raise AIVMError('Cannot inspect TPM: incomplete libvirt domain XML.')
    return root


def emulator_tpm(root: ET.Element) -> bool:
    return any(backend.get('type') == 'emulator'
               for backend in root.findall('./devices/tpm/backend'))


def _compatible(root: ET.Element) -> bool:
    devices = root.findall('./devices/tpm')
    if not devices:
        return False
    if len(devices) == 1:
        device = devices[0]
        backend = device.find('backend')
        if (device.get('model') == 'tpm-crb' and backend is not None
                and backend.get('type') == 'emulator'
                and backend.get('version') == '2.0'):
            return True
    raise AIVMError('VM already has a different TPM configuration; refusing replacement.')


def _read_persistent(cfg: AgentVMConfig) -> str:
    return CommandManager.current().run(
        virsh_cmd('dumpxml', cfg.vm.name, '--inactive'),
        sudo=virsh_needs_sudo(), role='read', check=True, capture=True,
        summary=f'Inspect persistent TPM configuration for {cfg.vm.name}',
    ).stdout


def _require_host_tpm2_probe() -> None:
    """Verify TPM 2.0 when older local libvirt omits version reporting."""
    mgr = CommandManager.current()
    with mgr.step(
        'Verify host software TPM 2.0 support',
        why=('Libvirt omitted backendVersion; select TPM 2.0 in swtpm and '
             'exit before creating sockets or persistent TPM state.'),
    ):
        result = mgr.run(
            ['swtpm', 'socket', '--tpm2', '--print-capabilities'],
            role='read', check=False, capture=True, timeout=15,
            summary='Probe host swtpm with TPM 2.0 explicitly selected',
        )
    if result.code != 0:
        detail = (result.stderr or result.stdout).strip()
        raise AIVMError('Cannot verify TPM 2.0: libvirt omitted backendVersion '
                        f'and the host swtpm --tpm2 probe failed: {detail}. '
                        'Install/configure swtpm on the libvirt host and retry; '
                        'no weaker fallback is used.')
    try:
        caps = json.loads(result.stdout)
    except ValueError as ex:
        raise AIVMError('Cannot verify TPM 2.0: invalid JSON from the host '
                        'swtpm --tpm2 probe; no weaker fallback is used.') from ex
    if (not isinstance(caps, dict) or caps.get('type') != 'swtpm'
            or not isinstance(caps.get('features'), list)
            or not all(isinstance(feature, str) for feature in caps['features'])):
        raise AIVMError('Cannot verify TPM 2.0: unexpected capabilities from the '
                        'host swtpm --tpm2 probe; no weaker fallback is used.')
    log.info('Host swtpm successfully selected TPM 2.0; keeping emulator '
             'version=2.0 and model=tpm-crb in the domain definition.')


def require_tpm_capability(*, dry_run: bool = False) -> None:
    """Check system libvirt, probing local swtpm only for omitted versions."""
    if dry_run:
        print('DRYRUN: would require libvirt emulator TPM 2.0 / tpm-crb support '
              '(host packages swtpm and swtpm-tools).')
        return
    mgr = CommandManager.current()
    with mgr.step(
        'Inspect libvirt software TPM capabilities',
        why='Check the selected daemon for emulator TPM 2.0 and tpm-crb support.',
    ):
        result = mgr.run(
            virsh_cmd('domcapabilities'), sudo=virsh_needs_sudo(),
            role='read', check=True, capture=True,
            summary='Check libvirt software TPM capabilities',
        )
    try:
        root = ET.fromstring(result.stdout)
    except ET.ParseError as ex:
        raise AIVMError('Could not parse libvirt TPM capabilities.') from ex
    tpm = root.find('./devices/tpm')
    enums: dict[str | None, set[str]] = {}
    supported = tpm.get('supported', 'unknown') if tpm is not None else 'missing'
    if tpm is not None:
        enums = {e.get('name'): {(v.text or '').strip() for v in e.findall('value')}
                 for e in tpm.findall('enum')}
    required = {'backendModel': 'emulator', 'backendVersion': '2.0', 'model': 'tpm-crb'}
    missing = [f'{name}={value}' for name, value in required.items()
               if value not in enums.get(name, set())]
    if supported == 'yes' and not missing:
        return
    # Libvirt 8.0 exposes model/backend but has no backendVersion enum.
    # Absence permits a positive runtime probe; an explicit rejection does not.
    if (supported == 'yes' and missing == ['backendVersion=2.0']
            and 'backendVersion' not in enums):
        _require_host_tpm2_probe()
        return
    advertised = '; '.join(
        f'{name}={",".join(sorted(enums.get(name, set()))) or "(not advertised)"}'
        for name in required
    )
    raise AIVMError('Selected libvirt daemon does not advertise emulator TPM 2.0 '
                    f'with tpm-crb. Reported TPM supported={supported}; {advertised}. '
                    f'Missing requirements: {", ".join(missing) or "TPM supported=yes"}. '
                    'Install/configure swtpm and swtpm-tools on the libvirt host '
                    'and inspect the domcapabilities command shown above; '
                    'no weaker fallback is used. A physical host TPM '
                    '(/dev/tpm*) is not required for the emulator backend.')


def tpm_update_needed(cfg: AgentVMConfig) -> bool:
    if normalize_tpm(cfg.vm.tpm) == 'none':
        # An absent request must never remove a manually installed TPM.
        return False
    return not _compatible(domain_xml(_read_persistent(cfg)))


def _require_offline(cfg: AgentVMConfig) -> None:
    mgr = CommandManager.current()
    state = mgr.run(
        pin_locale(virsh_cmd('domstate', cfg.vm.name)),
        sudo=virsh_needs_sudo(), role='read', check=True, capture=True,
    )
    if state.stdout.strip().lower() != 'shut off':
        raise AIVMError('Adding a TPM requires a shut-off VM. Run '
                        '`aivm vm down` first, then repeat `aivm vm update --tpm emulator`.')
    info = mgr.run(
        pin_locale(virsh_cmd('dominfo', cfg.vm.name)),
        sudo=virsh_needs_sudo(), role='read', check=True, capture=True,
    )
    fields = dict(line.split(':', 1) for line in info.stdout.splitlines() if ':' in line)
    saved = fields.get('Managed save', '').strip().lower()
    if saved != 'no':
        raise AIVMError('Cannot add a TPM with a managed-save image or unknown '
                        'managed-save status. Cold-start and cleanly shut down the VM first.')


def add_tpm(cfg: AgentVMConfig, *, dry_run: bool) -> None:
    """Add one device to fresh persistent XML; preserve disks, UUID and metadata.

    libvirt does not support persistent attach-device for TPMs, so this is a
    validated redefine. Never reset/replace an existing TPM or stop a live VM.
    External libvirt administrators must serialize their own domain edits.
    """
    before = _read_persistent(cfg)
    root = domain_xml(before)
    if _compatible(root):
        return
    if root.findtext('name') != cfg.vm.name or not root.findtext('uuid'):
        raise AIVMError('Refusing TPM update without matching domain name and UUID.')
    _require_offline(cfg)
    require_tpm_capability(dry_run=dry_run)
    devices = root.find('devices')
    assert devices is not None
    devices.append(ET.fromstring(TPM_XML))
    new_xml = ET.tostring(root, encoding='unicode')
    log.info('Add virtual TPM device: {}', TPM_XML)
    if dry_run:
        print(f'DRYRUN: would redefine {cfg.vm.name} with this TPM, preserving '
              'its UUID, disks and other devices; no files or domain state changed.')
        return
    mgr = CommandManager.current()
    with mgr.step(
        f'Add virtual TPM to {cfg.vm.name}',
        why='Add a libvirt-managed TPM 2.0 device to the shut-off VM; existing identity keys are unchanged.',
        approval_scope=f'vm-tpm:{cfg.vm.name}',
    ):
        _require_offline(cfg)
        if _read_persistent(cfg) != before:
            raise AIVMError('Domain definition changed during TPM review; retry the update.')
        with tempfile.NamedTemporaryFile('w', suffix='.xml', prefix='aivm-tpm-',
                                         delete=False) as stream:
            stream.write(new_xml)
            path = Path(stream.name)
        try:
            mgr.run(virsh_cmd('define', str(path), '--validate'),
                    sudo=virsh_needs_sudo(), role='modify', check=True,
                    capture=True, summary=f'Define {cfg.vm.name} with a virtual TPM',
                    detail=new_xml)
        finally:
            path.unlink(missing_ok=True)
        after = domain_xml(_read_persistent(cfg))
        if after.findtext('uuid') != root.findtext('uuid') or not _compatible(after):
            raise AIVMError('Could not verify the TPM update; inspect the domain before retrying.')
    print('Added virtual TPM 2.0. Start the VM to use it. Existing software '
          'identity keys have not been moved into the TPM.')


def persist_tpm_choice(cfg: AgentVMConfig, store_path: Path) -> None:
    """Change only VM hardware metadata; leave principals and profiles intact."""
    from ..config_store import require_vm
    from ..scoped_store import load_scope_store, resolve_store_scope, save_scope_store

    scope = resolve_store_scope(str(store_path))
    store = load_scope_store(scope)
    require_vm(store, cfg.vm.name).cfg.vm.tpm = normalize_tpm(cfg.vm.tpm)
    save_scope_store(scope, store, reason='Persist the selected virtual TPM mode.')
