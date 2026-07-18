"""Opt-in end-to-end suite that drives real libvirt/KVM hosts.

Every module here is marked ``pytest.mark.e2e`` and gated behind
``AIVM_E2E`` environment variables, so the default test run deselects
them.  Shared scaffolding lives in :mod:`tests.e2e._helpers`.
"""
