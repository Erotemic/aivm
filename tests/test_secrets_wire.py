"""Protocol version 1 frames and replies."""

from __future__ import annotations

import pytest

from aivm_secrets.errors import SecretsError
from aivm_secrets.kernel import wire
from aivm_secrets.kernel.wire import Frame, parse_frame


def frame(**fields):
    return {'version': 1, 'capability': 'aivs1.x', **fields}


@pytest.mark.parametrize(
    'verb,payload',
    [
        ('request', {'operation': 'x'}),
        ('describe', True),
        ('renounce', True),
        ('delegate', {'operations': {}}),
    ],
)
def test_each_verb_parses_to_one_frame(verb, payload):
    assert parse_frame(frame(**{verb: payload})) == Frame(
        verb, 'aivs1.x', payload
    )


@pytest.mark.parametrize(
    'value',
    [
        None, [], 'request', 7,
        {},
        frame(),
        {'version': 1, 'request': {}},
        {'capability': 'x', 'request': {}},
        frame(request={}, describe=True),
        frame(request={}, delegate={}),
        frame(request={}, extra=1),
        frame(describe=False), frame(describe=1), frame(describe='true'),
        frame(renounce=None), frame(renounce={}),
        frame(approve='a' * 64), frame(revoke=True), frame(command='status'),
        frame(exec=['id']), frame(url='https://evil.invalid'),
        {**frame(request={}), 'version': 2},
        {**frame(request={}), 'version': True},
        {**frame(request={}), 'version': '1'},
        {**frame(request={}), 'capability': 7},
        {**frame(request={}), 'capability': None},
        {**frame(request={}), 'capability': 'x' * (wire.MAX_CAPABILITY + 1)},
    ],
)  # fmt: skip
def test_frames_are_a_closed_grammar(value):
    with pytest.raises(SecretsError) as caught:
        parse_frame(value)
    assert caught.value.code == 'invalid_request'


def test_the_verb_set_has_no_host_plane_verbs():
    assert wire.VERBS == ('request', 'describe', 'delegate', 'renounce')


def test_replies_carry_fixed_text_and_only_a_bounded_status():
    assert wire.success(result=[1]) == {'version': 1, 'ok': True, 'result': [1]}
    error = SecretsError(
        'upstream_rejected', status=403, detail='/host/only/path'
    )
    reply = wire.failure(error, approval={'digest': 'd'})
    assert reply == {
        'version': 1,
        'ok': False,
        'error': {
            'code': 'upstream_rejected',
            'message': 'Service refused the request; it was not applied.',
            'status': 403,
        },
        'approval': {'digest': 'd'},
    }
    assert '/host/only/path' not in repr(reply)
    assert 'status' not in wire.failure(SecretsError('denied'))['error']
