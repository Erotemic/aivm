"""Host token resolvers work without gh and without a shell."""
import os
import sys

import pytest

from aivm_secrets.errors import SecretsError
from aivm_secrets.sources import credential_from_command, parse_source, resolve_source

TOKEN = 'NOT_REAL_generic_host_command_token_1234'


def test_host_command_resolver_no_shell_and_only_selected_environment(monkeypatch):
    monkeypatch.setenv('DANGEROUS_ENV', 'do-not-inherit')
    command = [sys.executable, '-c',
               "import os; print('NOT_REAL_generic_host_command_token_1234' if 'DANGEROUS_ENV' not in os.environ else 'FAILED')"]
    source = parse_source({'kind': 'command', 'argv': command})
    assert resolve_source(source) == TOKEN
    assert credential_from_command(command) == TOKEN


def test_shell_metacharacters_are_literal_arguments():
    command = [sys.executable, '-c',
               'import sys; print(sys.argv[1])', 'NOT_REAL_generic_host_command_token_1234; echo bad']
    with pytest.raises(SecretsError):
        credential_from_command(command)
    # A semicolon never executes another shell command.


def test_resolver_rejects_bad_output_and_failure():
    for body in ["print('bad')", "print('A'*10000)", "import sys; sys.exit(1)"]:
        with pytest.raises(SecretsError) as ex:
            credential_from_command([sys.executable, '-c', body])
        assert ex.value.code == 'credential_source'


@pytest.mark.parametrize('invalid', [
    {'kind': 'command', 'argv': 'gh auth token'},
    {'kind': 'command', 'argv': []},
    {'kind': 'command', 'argv': ['sh', '-c', 'printenv'], 'inherit_env': ['LD_PRELOAD']},
    {'kind': 'file', 'path': 'relative/token'},
    {'kind': 'shell', 'script': 'gh auth token'},
])
def test_policy_rejects_unsafe_resolver_schema(invalid):
    with pytest.raises(SecretsError, match='policy'):
        parse_source(invalid)
