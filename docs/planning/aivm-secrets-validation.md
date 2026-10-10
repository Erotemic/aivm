# AIVM Secrets: validation record

Date: 2026-10-10. Base commit: `f5cd93b` on `dev/0.6.2`, plus the change set
this record ships with. This records what was executed on one development
machine. It is not a production deployment review and not a proof result.

Environment: Ubuntu 24.04 guest used as the development host (kernel
6.8.0-110, nested KVM), Python 3.13.2, pytest 9.0.2, cryptography 49.0.0,
OpenSSH 9.6p1 with OpenSSL 3.0.13, libvirt 10.0.0, ruff, ty and mypy from the
project environment.

## Executed checks

| Check | Result |
| --- | --- |
| Secrets unit suite, `tests/test_secrets_*.py` | **1,118 passed** |
| Real-VM end-to-end suite, `tests/e2e/test_secrets.py`, creating its own VM | **18 passed** |
| Complete non-e2e suite, `python run_tests.py` | **2,480 passed**, 29 deselected (e2e) |
| Mutation gate (inside the unit suite) | **48 of 48** deleted checks detected |
| Generated traces against the reference model | ~38,600 steps, 3 write modes, all agree |
| Conformance vectors, `tests/secrets_vectors/v1` | 79 checks: codec, grammar, policy, 14 traces, envelope |
| Coverage of `aivm_secrets/kernel/` by its own unit tests | **100% of 1,124 statements and 248 branches** |
| `ruff check` on `aivm_secrets`, the adapter and all new tests | clean |
| `ty check` and strict `mypy` on `aivm_secrets` and `aivm/secrets_transport.py` | clean |
| `python dev/devcheck/architecture_docs.py check` | passed, after regenerating import edges |
| `docs/source/secrets.rst` under `sphinx-build -W` | no warnings from the page |

The commands were:

```bash
python -m pytest -o addopts='' -q tests/test_secrets_*.py
AIVM_E2E=1 python -m pytest -o addopts='' -v -s tests/e2e/test_secrets.py
python run_tests.py -q
```

Not everything in the repository's gates is green, and none of the following
was introduced or fixed here: `ruff check aivm tests` reports 26 import-order
and unused-name findings in files this change does not touch; `mypy aivm`
reports 25 errors in existing credential modules; and `./run_docs.sh` fails on
118 ambiguous cross-reference warnings in generated API pages.

## What the real-VM suite does

`tests/e2e/test_secrets.py` creates a libvirt/KVM guest from the pinned Ubuntu
cloud image, then opens real interactive `aivm ssh --secrets_policy` sessions
on a pseudo-terminal. The guest, OpenSSH with its streamlocal forward, the
broker child process and TLS are all real. The provider is an HTTPS server on
the host with a throwaway certificate authority pinned by the policy, and the
credential is a made-up token, so no third party is contacted.

Each test compares what the guest was told with three host-side records --
the requests the provider actually received, the audit file, and what is left
on both machines:

| Test | Establishes |
| --- | --- |
| reads reach the provider with a credential the guest never holds | Four authorized reads arrive carrying the credential; a search of the live guest's disk and every process environment finds no trace of it; the guest holds three paths and ciphertext |
| session teardown leaves nothing usable behind | Guest directory, host runtime directory and broker process are gone; the audit chain verifies |
| a plain ssh session is unchanged by the feature | No policy: no broker, client, environment or directory |
| an allowed write sends exactly the authorized body | One POST with exactly the projected body; other issue and oversized body refused; content absent from the audit |
| a write waits for the operator's approval of its exact content | `approval_required` in the guest; operator sees the exact bytes and approves from another process; one POST; altered and repeated requests need new approval |
| an expired grant is refused while the shell stays open | `expired` after the lifetime; nothing sent afterwards |
| the request budget holds under sequential and concurrent use | 3 of 5 sequential and exactly 5 of 12 simultaneous requests admitted; the provider saw exactly the budget |
| the operator can revoke a live session from the host | `aivm-secrets revoke` takes effect mid-session |
| a capability is worthless outside its own session | A capability copied out of one session is `invalid_capability` in the next |
| a guest can hand a helper a strictly smaller capability | Delegated capability is narrower, cannot widen itself, spends the parent's budget, can be renounced |
| killing the host session ends its authority | After `SIGKILL` of `aivm ssh` the broker exits, cleans up and seals its audit; the orphaned ciphertext is refused by the next session |
| a hostile guest cannot talk its way past the broker | 20 kinds of protocol abuse from inside the guest, including control-plane verbs, smuggled URLs, tampered capabilities, oversized and pipelined frames and a connection flood: all refused, service intact, provider saw only the two legitimate reads |
| a misbehaving provider cannot leak or redirect the credential | A reflected `Authorization` header never reaches the guest; a redirect is reported and not followed; a 403 is relayed as a status only |
| a policy inside the shared workspace is refused | Session refuses before any guest contact |
| bad trust anchor and resolver fail before the guest is touched | Likewise for a missing CA, a missing resolver and an empty policy |
| an untrusted provider certificate sends no credential | Wrong pinned CA: `unreachable`, zero provider requests |
| the GitHub service installs its alias and refuses out-of-grant requests | Schema 1 through a real session, with every request refused before egress |
| measure session and request overhead | See below |

## Measurements

From five real-VM runs on this machine, three of which created their own VM.
The spread is host load: the slowest runs shared the machine with a second VM
or another test suite.

| Quantity | Observed |
| --- | --- |
| Guest `aivm-secrets invoke` round trip, including the provider request | 64-117 ms, of which 13-26 ms is Python startup in the guest |
| Opening a secret session, first use of a folder | 6.5-13 s |
| Opening a secret session, folder already attached | about 3.3 s |
| Whole e2e suite including VM creation and teardown | 2.5-3.8 minutes |

Session-open time is dominated by AIVM's existing attachment reconciliation,
not by the broker. These are observations, not benchmarks or product claims.

## Defects this validation found

Running against a real VM and with adversarial peers found problems that the
earlier mocked tests could not:

* Secret sessions refused the `legacy` identity of every explicit `--config`
  store, which the rest of AIVM accepts. Found by the first real session.
* The provider total deadline did not fire: wrapping a socket in TLS detaches
  the original object, so the watchdog was shutting down a dead handle. Found
  by a real trickling TLS peer; the request ran 20 seconds instead of 1.
* A response cut short of its declared length was treated as a malformed
  answer instead of a transport failure.
* The broker aborted with `SIGABRT` on `SIGTERM`, because a thread was blocked
  inside buffered `stdin` at interpreter shutdown.
* A broker whose parent was killed raised `BrokenPipeError` during cleanup and
  left its runtime directory behind.
* The connection limit refused legitimate parallel requests instead of
  queueing them. Found by twelve simultaneous clients in the guest.
* Reading a directory as a credential file raised an unhandled error and
  leaked a descriptor.

Three findings were outside the broker. An existing test replaced
`os.makedirs` for the remainder of the test session (fixed). The project's
editable install predated `aivm_secrets`, so the `aivm-secrets` entry point
did not exist until the package was reinstalled. And the shared e2e teardown
leaves a libvirt network and the per-VM copy of the base image behind on every
run; the secrets suite now removes its own, and the other suites still leak.

After the final run nothing of the suite remained on the host: no domain, no
network, no storage directory, no mount and no temporary directory.

## Not established

* **No formal verification.** No Rust, Charon/Aeneas or Lean artifact exists.
  The kernel is written to be extractable and is specified in
  `aivm-secrets-kernel-spec.md`; that is preparation, not proof.
* **No real provider.** No real credential was used and neither GitHub nor
  GitLab was contacted. The shipped manifests are examples that parse; none
  has been exercised against its live service. Run one read-only session
  against the real service before relying on a policy.
* **The identity-disable path was not run on a real VM.** The e2e VM uses an
  explicit `--config` store, which has no access-identity records. The path is
  covered by `test_aivm_access_disable_revokes_a_live_secret_session`, which
  runs the real disable transaction against a real machine store and a real
  running broker, with the guest-side key removal stubbed.
* **One host, one guest OS.** Ubuntu 24.04 as both; no other sshd
  configuration, no remote host, no multi-user shared machine store.
* **Not implemented:** mTLS or non-exportable instance keys, durable
  revocation or approval state, OAuth refresh, VS Code and detached-session
  integration, stock-`gh` compatibility.
* Testing a finite set of inputs does not establish the absence of timing or
  size side channels, or of defects in the trusted base listed in
  `aivm-secrets-assumptions.json`.
