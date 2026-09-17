from aivm.runtime import pin_locale, ssh_base_args, virsh_cmd


def test_pin_locale_prefixes_env_lc_all_c() -> None:
    """The pin is argv-level so it survives sudo's environment reset."""
    assert pin_locale(virsh_cmd('dominfo', 'vm')) == [
        'env',
        'LC_ALL=C',
        'virsh',
        '-c',
        'qemu:///system',
        'dominfo',
        'vm',
    ]


def test_ssh_base_args_restricts_auth_to_configured_identity_by_default() -> (
    None
):
    args = ssh_base_args('/tmp/id_ed25519')

    assert ['-o', 'IdentitiesOnly=yes'] == args[-4:-2]
    assert args[-2:] == ['-i', '/tmp/id_ed25519']


def test_ssh_base_args_can_disable_identities_only() -> None:
    args = ssh_base_args('/tmp/id_ed25519', identities_only=False)

    assert 'IdentitiesOnly=yes' not in args
    assert args[-2:] == ['-i', '/tmp/id_ed25519']
