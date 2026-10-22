"""Public errors contain fixed codes, never exception or provider text.

The code set is closed: it is the ``Denial`` enum of the planned Rust kernel.
An unknown code collapses to ``internal_error`` rather than leaking a string
chosen by a caller.
"""

from __future__ import annotations

MESSAGES = {
    'invalid_request': 'Malformed or unsupported request.',
    'invalid_policy': 'Invalid policy; see the policy schema documentation.',
    'invalid_capability': 'Capability authentication failed.',
    'wrong_binding': 'Capability is not valid on this session channel.',
    'expired': 'Capability has expired.',
    'revoked': 'Session authority has been revoked.',
    'exhausted': 'Session request budget is exhausted.',
    'denied': 'Operation is outside the granted authority.',
    'approval_required': (
        'A host operator must approve this exact write before it is sent.'
    ),
    'resource_mismatch': 'Service resource metadata does not match the grant.',
    'unreachable': (
        'Service connection could not be established; nothing was sent.'
    ),
    'upstream_rejected': 'Service refused the read request.',
    'upstream_error': 'Service request failed; no automatic retry was made.',
    'upstream_response': 'Service returned an invalid or oversized response.',
    'unsafe_file': 'Host file ownership, permissions, or type is unsafe.',
    'credential_source': 'Could not obtain a valid host service credential.',
    'missing_crypto': 'Install the aivm[secrets] extra on the host.',
    'audit_failed': 'Audit recording failed; the request was stopped.',
    'outcome_unknown': (
        'A dispatched request may have completed; reconcile before retrying.'
    ),
    'internal_error': 'Broker failed closed.',
    'guest_setup': 'Secret session guest setup failed.',
    'wrong_owner': (
        'Secret sessions must run as the owning active access identity.'
    ),
    'shared_source': (
        'Keep the broker, policy and credential outside the shared workspace.'
    ),
    'no_session': 'No matching live secret session was found.',
}


class SecretsError(RuntimeError):
    """An error safe to expose to an untrusted client or an operator log.

    ``status`` is the only provider-derived datum an error may carry: a
    three-digit HTTP status, which is bounded and carries no provider text.

    ``detail`` is host-generated context for the *operator's own terminal*
    (which file was unsafe, and why). It is never placed in a guest reply or
    an audit record; those are built from ``code`` alone.
    """

    def __init__(self, code: str, *, status: int = 0, detail: str = ''):
        if code not in MESSAGES:
            code = 'internal_error'
        if type(status) is not int or not 100 <= status <= 599:
            status = 0
        self.code = code
        self.status = status
        self.detail = detail
        super().__init__(MESSAGES[code])

    def for_operator(self) -> str:
        """The fixed message plus host-only context, for a host terminal."""
        return f'{self} ({self.detail})' if self.detail else str(self)
