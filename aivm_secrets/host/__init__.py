"""The trusted, impure shell around :mod:`aivm_secrets.kernel`.

These modules hold what the kernel is forbidden to touch -- the session key,
clocks, randomness, files, sockets and the provider credential -- and each
one states the assumption it contributes to the trusted computing base:

==============  ==============================================================
``envelope``    AEAD sealing of capabilities; one ephemeral key per session
``egress``      the single TLS destination a credential may be sent to
``sources``     host-only credential acquisition
``files``       whole-path ownership checks for policy, secrets and anchors
``audit``       hash-chained, fsync-before-dispatch audit records
``broker``      the interpreter that drives kernel transitions
``server``      guest and control Unix sockets with kernel peer-UID checks
``session``     per-user registry of live sessions and the control client
``hardening``   best-effort process hardening
==============  ==============================================================

In the planned Rust port this layer becomes the ``secrets-host`` crate and
the only code allowed to perform I/O.
"""
