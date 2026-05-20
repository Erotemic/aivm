from aivm.runtime import ssh_base_args


def test_ssh_base_args_restricts_auth_to_configured_identity_by_default() -> None:
    args = ssh_base_args('/tmp/id_ed25519')

    assert ['-o', 'IdentitiesOnly=yes'] == args[-4:-2]
    assert args[-2:] == ['-i', '/tmp/id_ed25519']


def test_ssh_base_args_can_disable_identities_only() -> None:
    args = ssh_base_args('/tmp/id_ed25519', identities_only=False)

    assert 'IdentitiesOnly=yes' not in args
    assert args[-2:] == ['-i', '/tmp/id_ed25519']
