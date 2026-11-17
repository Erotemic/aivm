"""The privileged AIVM helper must run with an older system Python.

This file can be run with `python3 -m unittest discover` without installing the
AIVM application or its Python dependencies. The helper is stdlib-only.
"""

from __future__ import annotations

import importlib.util
import os
import pwd
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch


HELPER_SCRIPT = Path(__file__).resolve().parents[1] / 'aivm' / 'privileged_onboard_user.py'
spec = importlib.util.spec_from_file_location('privileged_onboard_helper', HELPER_SCRIPT)
assert spec is not None and spec.loader is not None
helper = importlib.util.module_from_spec(spec)
spec.loader.exec_module(helper)


class SystemPythonOnboardTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.home = Path(self.temp.name)
        self.vm = 'aivm-2404-aiq-gpu2'
        self.guest = 'benjamin-fenelon-agent'
        self.key = self.home / '.ssh' / 'id_aivm_ed25519'
        self.profile = (
            'schema_version = 3\n'
            f'active_vm = "{self.vm}"\n'
            f'ssh_identity_file = "{self.key}"\n'
            f'ssh_pubkey_path = "{self.key}.pub"\n'
            'state_dir = "~/.cache/aivm"\n'
            f'default_guest_user = "{self.guest}"\n'
            '[behavior]\nyes_sudo = false\n'
        )

    def test_system_interpreter_can_import_helper(self) -> None:
        result = subprocess.run(
            ['/usr/bin/python3', '-I', str(HELPER_SCRIPT), '--help'],
            capture_output=True, text=True, check=False,
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn('prepare', result.stdout)

    def test_expected_top_level_profile_fields(self) -> None:
        self.assertEqual(helper._profile_identity_fields(self.profile), {
            'active_vm': self.vm,
            'ssh_identity_file': str(self.key),
            'ssh_pubkey_path': str(self.key) + '.pub',
            'default_guest_user': self.guest,
        })
        quoted = self.profile.replace(
            f'active_vm = "{self.vm}"', 'active_vm = "test\\\"vm"',
        )
        self.assertEqual(helper._profile_identity_fields(quoted)['active_vm'], 'test"vm')

    def test_bad_or_ambiguous_profile_rejected(self) -> None:
        broken = [
            self.profile.replace(f'active_vm = "{self.vm}"', 'active_vm = 9'),
            self.profile.replace(
                f'active_vm = "{self.vm}"',
                f'active_vm = "{self.vm}"\nactive_vm = "other"',
            ),
            self.profile.replace('state_dir = "~/.cache/aivm"',
                                 'state_dir = """multiline\nactive_vm = "fake"\n"""'),
            '[behavior]\n' + self.profile,
        ]
        for profile in broken:
            with self.subTest(profile=profile[:100]):
                with self.assertRaises(ValueError):
                    helper._profile_identity_fields(profile)

    def test_owner_profile_and_key_created_once(self) -> None:
        real = pwd.getpwuid(os.getuid())
        account = pwd.struct_passwd((
            real.pw_name, 'x', os.getuid(), os.getgid(),
            '', str(self.home), '/bin/bash',
        ))

        def fake_ssh_keygen(cmd: list[str], **kwargs: object) -> SimpleNamespace:
            self.assertEqual(cmd[0], 'ssh-keygen')
            if '-y' in cmd:
                return SimpleNamespace(stdout='ssh-ed25519 TESTPUB any-comment\n')
            self.key.write_text('FAKE_PRIVATE_KEY\n')
            Path(str(self.key) + '.pub').write_text(
                f'ssh-ed25519 TESTPUB {cmd[-1]}\n'
            )
            return SimpleNamespace(stdout='')

        with patch.object(helper.subprocess, 'run', side_effect=fake_ssh_keygen):
            first = helper._prepare_owner(account, self.vm, self.guest, self.profile)
            second = helper._prepare_owner(account, self.vm, self.guest, self.profile)
        self.assertTrue(first['created_profile'])
        self.assertTrue(first['created_key'])
        self.assertFalse(second['created_profile'])
        self.assertFalse(second['created_key'])
        self.assertEqual(first['public_key'], second['public_key'])
        self.assertEqual(self.key.stat().st_mode & 0o777, 0o600)
        self.assertEqual((self.home / '.config/aivm/profile.toml').stat().st_mode & 0o777, 0o600)


if __name__ == '__main__':
    unittest.main()
