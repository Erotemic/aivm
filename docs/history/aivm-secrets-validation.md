# AIVM Secrets: validation record

Date: 2026-10-10. Base commit: `42da57f` on `dev/0.6.2`, plus the change set
this record ships with: the response to an external review of `42da57f`
(section "External review" below) and built-in `gh` support through the
general manifest mechanism. This records what was executed on one
development machine. It is not a production deployment review and not a
proof result.

Environment: Ubuntu 24.04 guest used as the development host (kernel
6.8.0-110, nested KVM), Python 3.13.2, pytest 9.0.2, cryptography 49.0.0,
OpenSSH 9.6p1 with OpenSSL 3.0.13, libvirt 10.0.0, ruff, ty and mypy from the
project environment.

## Executed checks

| Check | Result |
| --- | --- |
| Secrets unit suite, `tests/test_secrets_*.py` | **1,509 passed** |
| Real-VM end-to-end suite, `tests/e2e/test_secrets.py`, creating its own VM | **23 passed**, twice, each on a freshly created VM |
| Complete non-e2e suite, `python run_tests.py` | **2,871 passed**, 34 deselected (e2e) |
| Mutation gate (inside the unit suite) | **69 of 69** deleted checks detected |
| Generated traces against the reference model | ~38,600 steps, 3 write modes, all agree |
| Conformance vectors, `tests/secrets_vectors/v1` | 115 checks: codec, grammar, 65 policies, 17 traces, envelope |
| Coverage of `aivm_secrets/kernel/` by its own unit tests | **100% of 1,356 statements and 330 branches** |
| `ruff check` on `aivm_secrets`, the adapter and all new tests | clean |
| `ty check` and strict `mypy` on `aivm_secrets` and `aivm/secrets_transport.py` | clean |
| `python dev/devcheck/architecture_docs.py check` | passed, after regenerating import edges |
| `docs/source/secrets.rst` under `sphinx-build` | no warnings from the page (a malformed table it previously contained is fixed) |

The commands were:

```bash
python -m pytest -o addopts='' -q tests/test_secrets_*.py
AIVM_E2E=1 python -m pytest -o addopts='' -v -s tests/e2e/test_secrets.py
python run_tests.py -q
```

Not everything in the repository's gates is green, and none of the following
was introduced or fixed here: `ruff check aivm tests` reports 26 import-order
and unused-name findings in files this change does not touch; `mypy aivm`
reports 27 errors in existing credential and config modules; and `./run_docs.sh` fails on
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
| a write the provider answers 4xx is reported as unknown | The provider receives a `POST`, then answers 409: the guest is told `outcome_unknown (HTTP 409)`, the request is sent exactly once, and the audit records the same verdict; a 403 on a read in the same session stays `upstream_rejected` |
| a state-changing GET is gated as the write it is declared to be | A `GET` declared `effect: write` is `denied` with host writes off (nothing sent, reads unaffected), waits for a one-shot operator approval in `approve` mode, and is then sent exactly once |
| a guest-made link out of the workspace cannot carry a policy | From inside the VM the guest creates `switch -> <host private dir>` in the shared folder. A policy, and separately a token file, named through that link are refused before any guest contact or provider request; the same files named directly open a session |
| guest-written Python cannot become the broker | From inside the VM the guest writes a shadow `aivm_secrets` package and a `sitecustomize.py` into the shared folder. A control run shows a `python -P` launch with `PYTHONPATH` pointing there executes the guest's package. The real session, opened with that same environment and from that directory, serves normally and no guest file ran in the broker |
| gh commands run through the general mechanism on a real VM | The built-in GitHub manifest, with only its destination and credential source replaced, against the local provider: `gh pr view/diff/comments/reviews/checks/comment/edit` in the guest produce exactly the fact fetch plus one request each, with the pinned API version header; a PR in the grant with another author is `resource_mismatch` after one fetch; `gh api`, `gh auth token`, `gh pr merge` and `--web` stop in the client with exit 2 |
| the GitHub shorthand uses the operator's gh login and installs gh | Schema 1 as shipped: the credential is resolved by `gh auth token --hostname github.com` (a stand-in on the operator's `PATH`), the guest gets a `gh` link to the client and a table of exactly the granted operations; every request is refused before egress, including one made around the client |
| measure session and request overhead | See below |

## Measurements

From seven real-VM runs on this machine, five of which created their own VM.
The spread is host load: the slowest runs shared the machine with a second VM
or another test suite.

| Quantity | Observed |
| --- | --- |
| Guest `aivm-secrets invoke` round trip, including the provider request | 64-124 ms, of which 13-29 ms is Python startup in the guest |
| Opening a secret session, first use of a folder | 6.5-13 s |
| Opening a secret session, folder already attached | about 3.3 s |
| Whole e2e suite including VM creation and teardown | 2.5-4.9 minutes |

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

## External review of `42da57f`

An independent review reported four defects. Each was first reproduced
against that commit, then fixed, then pinned by a test that fails without
the fix (and by a mutant in the mutation gate):

| Finding | Reproduced as | Now |
| --- | --- | --- |
| A path through a guest-owned link (`/shared/switch -> /host/private`) passed the workspace check, because only the resolved destination was compared; a verified resolver was then run by its original, re-pointable name | `read_owned('/shared/switch/token')` succeeded; swapping the link after `verify_program` ran a different program | Every location visited while resolving is checked against the untrusted roots; the resolver runs at its verified, link-free location. Unit tests at every link depth, a deterministic swap-after-verify test, and a real guest making the link on a real VM |
| "Private group" was decided from the group's member list, which omits accounts whose *primary* group it is | The check returned "private" for a group that another account had as its primary GID | Group write requires proof: caller's primary group, no other listed member, no other account with that primary GID, and a local (enumerable) account database; anything else is refused |
| Every 4xx was reported as "the service did not apply the request" | A provider that applies a comment and answers 409 produced `upstream_rejected` | Any failure after a write is dispatched is `outcome_unknown`, status preserved as a datum; `upstream_rejected` is for reads. Tested against a real TLS provider that applies then refuses, in-process and from a real VM |
| The broker was started with `python -P -m aivm_secrets` and inherited `PYTHONPATH`, so a shadow package or `sitecustomize.py` in the workspace ran as the broker | Reproduced: the shadow package's `__main__` produced the session announcement | `python -I`, a scrubbed environment, and an in-broker check of interpreter, search path and loaded modules. Tested with a real broker child under a poisoned environment, and with guest-written files on a real VM |

Its architectural concern -- writes classified by `method != 'GET'` -- is
addressed by a required, per-operation `effect` declaration that the kernel
carries into the authorization. Its documentation finding -- the assurance
plan still described revocation as waiting for an active request -- is
corrected in `aivm-secrets-formal-assurance.md`.

Two things the review recommended are **not** done: idempotency keys and
provider reconciliation (so a failed write stays "unknown" rather than
becoming resolvable), and a flat refusal of group-writable paths (which would
refuse stock Ubuntu's per-user group with `umask 0002`; the proof-based rule
above was chosen instead, and refuses whenever the proof is unavailable).

Writing those tests found one further defect: `private_directory` created
the audit directory *before* checking the path, so a path through a
guest-owned link got a directory made on the far side of the link and was
only then refused. It now checks first.

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
* **No second local user.** The shared-primary-group and directory-service
  cases are tested by substituting the account database the check reads, not
  by creating accounts or joining a directory. No test ran as a different
  UID against another user's files.
* **`gh` is a table, not a compatibility layer.** The commands in the
  built-in table were run in a real guest against a local stand-in for the
  GitHub API. Stock `gh` behaviour (`--json`, `gh api`, repository inference
  from the working directory) is deliberately absent.
* **Not implemented:** mTLS or non-exportable instance keys, durable
  revocation or approval state, OAuth refresh, idempotency keys or outcome
  reconciliation for writes, VS Code and detached-session integration,
  stock-`gh` compatibility.
* Testing a finite set of inputs does not establish the absence of timing or
  size side channels, or of defects in the trusted base listed in
  `aivm-secrets-assumptions.json`.
