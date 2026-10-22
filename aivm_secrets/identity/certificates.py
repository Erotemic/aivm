"""X.509/CSR adapter for the Garrett identity authority.

Cryptography, certificate formats, entropy, guest-owned software keys and
filesystem writes are trusted effects, NOT pure proof primitives. The pure
Garrett models consume explicit authenticated public claims from this layer.
"""
from __future__ import annotations

import datetime as dt
import hashlib
from pathlib import Path
from typing import Any

from ..errors import SecretsError
from ..host.files import write_new

MAX_CSR_BYTES = 8192

def _x509():
    try:
        from cryptography import x509
        from cryptography.hazmat.primitives import hashes, serialization
        from cryptography.hazmat.primitives.asymmetric import ec
        from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID
    except ImportError:
        raise SecretsError('missing_crypto') from None
    return x509, hashes, serialization, ec, ExtendedKeyUsageOID, NameOID


def _utc(value: int) -> dt.datetime:
    return dt.datetime.fromtimestamp(value, dt.timezone.utc)


def _key_pem(key: Any) -> bytes:
    _, _, serialization, _, _, _ = _x509()
    return key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )


def _certificate_pem(cert: Any) -> bytes:
    _, _, serialization, _, _, _ = _x509()
    return cert.public_bytes(serialization.Encoding.PEM)


def _certificate_der(cert: Any) -> bytes:
    _, _, serialization, _, _, _ = _x509()
    return cert.public_bytes(serialization.Encoding.DER)


def _key_fingerprint(public_key: Any) -> str:
    _, _, serialization, _, _, _ = _x509()
    return hashlib.sha256(public_key.public_bytes(
        serialization.Encoding.DER,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )).hexdigest()


def _name(value: str):
    x509, _, _, _, _, NameOID = _x509()
    return x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, value[:64])])


def create_ca(*, now: int, days: int):
    """Generate one self-signed P-256 authority; host-only cryptographic effect."""
    x509, hashes, _, ec, _, _ = _x509()
    key = ec.generate_private_key(ec.SECP256R1())
    name = _name('aivm-secrets host CA')
    cert = (x509.CertificateBuilder()
            .subject_name(name).issuer_name(name)
            .public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(_utc(now - 60))
            .not_valid_after(_utc(now + days * 86400))
            .add_extension(x509.BasicConstraints(ca=True, path_length=0), True)
            .add_extension(x509.SubjectKeyIdentifier.from_public_key(
                key.public_key()), False)
            .add_extension(x509.KeyUsage(
                digital_signature=True, content_commitment=False,
                key_encipherment=False, data_encipherment=False,
                key_agreement=False, key_cert_sign=True, crl_sign=True,
                encipher_only=False, decipher_only=False), True)
            .sign(key, hashes.SHA256()))
    return key, cert


def _leaf_certificate(ca_key: Any, ca_cert: Any, public_key: Any,
                      *, name: str, now: int, days: int, server: bool):
    x509, hashes, _, _, ExtendedKeyUsageOID, _ = _x509()
    builder = (x509.CertificateBuilder()
        .subject_name(_name(name)).issuer_name(ca_cert.subject)
        .public_key(public_key).serial_number(x509.random_serial_number())
        .not_valid_before(_utc(now - 60))
        .not_valid_after(_utc(now + days * 86400))
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), True)
        .add_extension(x509.SubjectKeyIdentifier.from_public_key(public_key), False)
        .add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(
            ca_key.public_key()), False)
        .add_extension(x509.KeyUsage(
            digital_signature=True, content_commitment=False,
            key_encipherment=False, data_encipherment=False,
            key_agreement=False, key_cert_sign=False, crl_sign=False,
            encipher_only=False, decipher_only=False,
        ), True)
        .add_extension(x509.ExtendedKeyUsage([
            ExtendedKeyUsageOID.SERVER_AUTH if server
            else ExtendedKeyUsageOID.CLIENT_AUTH,
        ]), False))
    if server:
        builder = builder.add_extension(
            x509.SubjectAlternativeName([x509.DNSName('localhost')]), False)
    return builder.sign(ca_key, hashes.SHA256())


def _read_csr(data: bytes):
    x509, _, _, ec, _, _ = _x509()
    if type(data) is not bytes or not 1 <= len(data) <= MAX_CSR_BYTES:
        raise SecretsError('invalid_capability')
    try:
        request = x509.load_pem_x509_csr(data)
        key = request.public_key()
        if (not request.is_signature_valid or
                not isinstance(key, ec.EllipticCurvePublicKey) or
                not isinstance(key.curve, ec.SECP256R1) or
                len(request.extensions)):
            raise ValueError('unsupported or unauthenticated CSR')
        return request, _key_fingerprint(key)
    except (ValueError, TypeError, x509.DuplicateExtension):
        raise SecretsError('invalid_capability') from None


def inspect_csr(data: bytes) -> str:
    """A public P-256 CSR key fingerprint for out-of-band operator confirmation."""
    return _read_csr(data)[1]


def create_csr(*, private_key: Path, request_file: Path) -> str:
    """Generate an EXPORTABLE guest software key, and a CSR signed by it.

    Both destinations must not exist. This does not enroll the key and cannot
    attest the VM; the user must compare its fingerprint out of band.
    """
    x509, hashes, _, ec, _, _ = _x509()
    key = ec.generate_private_key(ec.SECP256R1())
    request = (x509.CertificateSigningRequestBuilder()
               .subject_name(_name('aivm-untrusted-request'))
               .sign(key, hashes.SHA256()))
    # Never return the secret; never overwrite an existing identity key.
    write_new(Path(private_key).expanduser().absolute(), _key_pem(key))
    write_new(Path(request_file).expanduser().absolute(),
              request.public_bytes(_x509()[2].Encoding.PEM))
    return _key_fingerprint(key.public_key())


