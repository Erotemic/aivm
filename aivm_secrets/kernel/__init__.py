"""The pure core of the secret-use broker.

Everything under ``aivm_secrets.kernel`` is deterministic computation over
immutable values. It performs no I/O, reads no clock, draws no randomness
and never holds a provider credential. ``tests/test_secrets_purity.py``
enforces that by inspecting imports, so the boundary cannot erode silently.

This package is the Python reference for the planned ``secrets-kernel`` and
``secrets-protocol`` Rust crates:

==============  ==============================================================
``grammar``     total, regex-free validators over closed alphabets
``codec``       strict JSON with one canonical encoding, and digests
``model``       bindings, claims, requests, effects, egress destinations
``scope``       authorization as data: membership and attenuation
``source``      the grammar of a host-only credential source
``https``       declarative HTTPS service specs (policy schema 2)
``github``      the fact-conditioned GitHub PR service (policy schema 1)
``service``     the closed sum of service specs
``machine``     the state machine: admit, emit, delegate, approve, revoke
``wire``        protocol version 1 frames and replies
==============  ==============================================================

The impure, trusted shell that interprets its decisions lives in
``aivm_secrets.host``.
"""
