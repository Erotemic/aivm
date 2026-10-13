"""Pure, proof-sized guest identity key replacement rule (contract v1).

No CSR, X.509, secret material, clocks, I/O, or VM state here. The trusted
adapter supplies fingerprints of *verified* public keys extracted from an
already-enrolled certificate and an authenticated CSR. The host registry
locks and CAS transition remain independent obligations.
"""
from __future__ import annotations

from ...errors import SecretsError
from ...primitives.epochs import advance
from .claims import MAX_EPOCH


def _fingerprint(value: object) -> str:
    if (type(value) is not str or len(value) != 64 or
            any(ch not in '0123456789abcdef' for ch in value)):
        raise SecretsError('invalid_capability')
    return value


def authorize_key_rotation(*, expected_epoch: int, actual_epoch: int,
                           expected_thumbprint: str, actual_thumbprint: str,
                           enrolled_key_fingerprint: str,
                           candidate_key_fingerprint: str) -> int:
    """Return next epoch iff CAS holds and the candidate public key differs.

    This does not authenticate a caller, prove possession of the new private
    key, or make registry persistence atomic. Those are caller obligations.
    """
    if (type(expected_epoch) is not int or type(actual_epoch) is not int or
            not 0 <= expected_epoch <= MAX_EPOCH or
            not 0 <= actual_epoch <= MAX_EPOCH):
        raise SecretsError('invalid_capability')
    _fingerprint(enrolled_key_fingerprint)
    _fingerprint(candidate_key_fingerprint)
    # SHA256 certificate thumbprints are encoded as canonical unpadded base64url.
    # The state model validates this structure elsewhere. Here only equality
    # matters, but the input types must still be strict.
    if type(expected_thumbprint) is not str or type(actual_thumbprint) is not str:
        raise SecretsError('invalid_capability')
    if (expected_epoch != actual_epoch or
            expected_thumbprint != actual_thumbprint):
        raise SecretsError('revoked')
    if enrolled_key_fingerprint == candidate_key_fingerprint:
        raise SecretsError('denied')
    return advance(actual_epoch, maximum=MAX_EPOCH)


__all__ = ['authorize_key_rotation']
