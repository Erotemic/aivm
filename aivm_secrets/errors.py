"""Public errors contain fixed codes, never exception or provider text."""

MESSAGES = {
    'invalid_request': 'Malformed or unsupported request.',
    'invalid_policy': 'Invalid policy; see the policy schema documentation.',
    'invalid_capability': 'Capability authentication failed.',
    'wrong_binding': 'Capability is not valid on this session channel.',
    'expired': 'Capability has expired.',
    'revoked': 'Session authority has been revoked.',
    'exhausted': 'Session request budget is exhausted.',
    'denied': 'Operation is outside the granted authority.',
    'resource_mismatch': 'Service resource metadata does not match the grant.',
    'upstream_error': 'Service request failed; no automatic retry was made.',
    'upstream_response': 'Service returned an invalid or oversized response.',
    'unsafe_file': 'Host file ownership, permissions, or type is unsafe.',
    'credential_source': 'Could not obtain a valid host service credential.',
    'missing_crypto': 'Install the aivm[secrets] extra on the host.',
    'audit_failed': 'Audit recording failed; the request was stopped.',
    'outcome_unknown': 'A dispatched request may have completed; reconcile before retrying.',
    'internal_error': 'Broker failed closed.',
    'guest_setup': 'Secret session guest setup failed.',
    'wrong_owner': 'Secret sessions must run as the owning active access identity.',
    'shared_source': 'Keep the policy and credential outside the shared workspace.',
}


class SecretsError(RuntimeError):
    """An error safe to expose to an untrusted client or an operator log."""

    def __init__(self, code: str):
        if code not in MESSAGES:
            code = 'internal_error'
        self.code = code
        super().__init__(MESSAGES[code])
