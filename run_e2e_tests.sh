#!/usr/bin/env bash
# Run end-to-end tests with full verbosity and output capture disabled.
#
# Prerequisites:
#   - libvirt/KVM with nested virtualization enabled
#   - passwordless sudo (sudo -n true)
#   - SSH keygen available
#   - Optional: cached Ubuntu image at ~/.cache/aivm/e2e/noble-base.img
#
# Modes:
#   - host-context e2e (default): tests run in the current host context
#   - bootstrap-context e2e (opt-in): creates a fresh outer VM and runs the
#     host-context suite inside that VM. Enable with AIVM_E2E_BOOTSTRAP=1.

set -euo pipefail

export AIVM_E2E=1
export AIVM_E2E_HOST_CONTEXT="${AIVM_E2E_HOST_CONTEXT:-1}"

# Run with -s (no capture) and -v (verbose) so you can watch progress in real-time.
tests=(
  tests/e2e/test_nested.py
  tests/e2e/test_full.py
  tests/e2e/test_adopt.py
  tests/e2e/test_host_bind_probe.py
)
if [[ "${AIVM_E2E_BOOTSTRAP:-0}" == "1" ]]; then
  tests+=(tests/e2e/test_bootstrap_context.py)
fi
pytest "${tests[@]}" -s -v "$@"
