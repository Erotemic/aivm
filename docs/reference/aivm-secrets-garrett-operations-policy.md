# Garrett identity: operations policy for this release

**Status (2026-10-13): decisions for this release.** This document settles
three open questions: the cross-host scope, what `jti` and a retried write
mean, and how weekly client renewal is supported. Items are marked
**implemented** (true of the code now), **decided** (settled, implementation
pending) or **out of scope**. Companion policies:
[rollback and clone](aivm-secrets-garrett-rollback-clone-policy.md),
[vTPM keys](aivm-secrets-garrett-vtpm-policy.md),
[issuer API authorization](aivm-secrets-garrett-issuer-api.md).

## 1. Scope: one host, one authority per principal

**Implemented model.** Each host principal has its own authority directory
with its own CA, issuer keys and enrollment registry. Each OAuth vault is a
directory on one host, protected by `flock` on that host's filesystem. Every
bridge, broker and verb runs on the host that holds the state it uses.

**Out of scope for this release:**

- durable revocation across hosts;
- more than one trusted root at a time (single-root cutover was chosen
  deliberately, see [CA lifecycle](aivm-secrets-garrett-ca-lifecycle.md)),
  and trust between the authorities of different hosts;
- distributed or replicated issuers, and certificate provenance across hosts;
- replicas of the registry, keyring or vault, and budgets or quotas shared
  across hosts.

**Unsupported, and treated as a fork:**

- copying an authority directory or a vault to a second host. Both copies
  then accept the same enrollments, and a revocation on one is invisible to
  the other.
- sharing one directory between hosts over a network filesystem. `flock` and
  atomic-rename semantics are not assumed there.
- a migrated VM. Live migration keeps the domain UUID, but the destination
  host's authority does not trust the source CA. Re-enroll on the
  destination, and revoke on the source.

**A future cross-host design must provide:**

1. **One linearizable source of truth** for enrollment epochs and
   revocation, consulted by every admitting bridge. It must state a maximum
   revocation latency. When that source is unreachable, admission fails
   closed beyond a bounded lease, never on "last known good".
2. **An explicit trust-root topology:** which roots each bridge trusts, how a
   root is added and withdrawn, and revocation per root. Overlapping roots
   need their own reviewed protocol.
3. **Issuer key custody and distribution:** per-host issuer keys certified by
   a common root, or one issuer service. Never a copied keyring. Key ids must
   not be able to collide across hosts.
4. **Subjects unique across hosts.** Today's subject hashes the spelling of
   the machine-store path, which is the same `/var/lib/aivm/machine` on every
   shared-layout host. A multi-host subject must include a host identity.
5. **No budget amplification.** Budgets are per broker session today
   (BUDGET-01). N hosts serving one grant must not yield N budgets.
6. **Fork detection, not only rollback detection.** Replicas that diverge
   must be caught by a shared witness (anchor D of the rollback policy).
7. **One refresh writer per OAuth grant.** Rotating refresh tokens make two
   hosts refreshing concurrently destroy the grant.
8. **Unchanged boundaries.** AIVM reaches identity only through a local child
   process or local socket that speaks the same closed JSON verbs. Provider
   credentials never leave the host that uses them. Provider knowledge stays
   manifest data.

## 2. `jti` and duplicate writes

### `jti` is informative

**Implemented:**

- Every bound JWT carries a `jti` of 128 random bits, signed with the other
  claims. The issuance audit record stores its SHA-256.
- Nothing persists or checks `jti` when a token is presented. The verifier
  checks signature, AEAD, issuer, audience, subject, epoch, expiry and the
  `cnf` thumbprint, not uniqueness.
- One session's JWT is presented on every call of that session, by design.

**Decided:**

- `jti` identifies an issuance for audit correlation. It is not a replay
  barrier and not a deduplication key, and must not be described as either.
- Replay by a party without the certified key is stopped by the `cnf` binding:
  the TLS client certificate's thumbprint must equal `cnf.x5t#S256`. Replay by
  the key holder is the session working as intended. It is bounded by the
  token's expiry (at most one hour, and at most the certificate's
  `not_after`), the broker's request budget and lifetime, and the registry
  epoch.
- No persisted `jti` set will be added. A one-shot `jti` would need a fresh
  token for every call plus a durable seen-set, which contradicts bound
  sessions. It would not deduplicate writes either: a retry would simply
  carry a new token.

### What a retry may do

**Implemented** broker behavior:

- Every request, including a retry, is a new request. It gets a new
  admission, a new budget debit and a new request id in the audit log.
  Nothing in the bridge, the JWT or the broker recognizes it as a retry.
- In write mode `deny` (the default), a write is refused, whether first or
  retried.
- In write mode `approve`, the first admission consumed the operator's
  one-shot approval. An identical retry stops at `approval_required` under
  the same request digest and waits for the operator again. The operator is
  the reconciliation point: check the service's state before approving the
  same digest a second time.
- In write mode `allow`, a retry is dispatched again and can apply the effect
  a second time.
- Once a write reaches the executor, the only definite failure is
  `unreachable` (no connection was made, so nothing was sent). The broker
  reports every other failure, *any* HTTP status included, as
  `outcome_unknown`: "may have completed; reconcile before retrying". Any
  other failure code *from the broker* therefore means the write was not
  sent.

**Known deviation:** at this writing, a broker reply that misses the
bridge's five-second frame deadline reaches a bound client as
`invalid_request`, even when the write was dispatched. A client-side
transport failure is just as ambiguous. Until the bridge is corrected, a
bound client must treat a write's `invalid_request` or transport failure as
`outcome_unknown`.

**Decided** for this release:

1. Neither clients nor tools retry a write automatically after
   `outcome_unknown`, a transport failure, or the deviation above. The guest
   client already says "do not automatically retry writes". To reconcile,
   read the service's state (with a read operation the manifest grants, where
   one exists), then decide.
2. After `unreachable`, retrying a write cannot duplicate it. It is still a
   new admission.
3. Reads can be retried within the budget.
4. **Idempotency keys are not implemented** and are not claimed. A provider
   that honors them could be supported only by a manifest declaration (data,
   not a provider branch). The broker would then derive the key
   deterministically from the grant and the request digest, so identical
   retries share a key. Until such a declaration exists, a write in `allow`
   mode can be duplicated by a retry.

## 3. Client certificate renewal

### Facts

All **implemented**:

- Lifetimes: a client certificate lasts seven days (`CLIENT_DAYS`), a server
  leaf 30 days, the CA 365 days. A bound JWT lasts at most an hour, capped at
  the client `not_after`. AIVM currently asks for at most 900 seconds.
- `aivm vm identity_renew --vm X` renews one running VM over the forced
  bootstrap channel, with an epoch-and-thumbprint CAS. It never boots a VM.
- The host renews any **active** row, including one whose certificate has
  already expired. `renew-client` checks the active flag, the epoch and the
  thumbprint, not the old `not_after`. A revoked row cannot be renewed. Expiry
  alone does not end an enrollment.
- A bound session refuses to start once the client certificate has expired:
  `public-client` refuses, and AIVM reports only that the identity service
  refused. Nothing warns before expiry.
- A renewal advances the epoch and installs a new certificate. A live bound
  session for that VM fails closed at its next call, because its JWT names
  the previous epoch and thumbprint. It must be restarted. A plain
  `--secrets_policy` session uses no client certificate and is unaffected.
- `renew-client` and `enroll` refuse (`expired`, "host CA requires
  renewal") once the CA has `CLIENT_DAYS` or less of validity left. In the
  CA's last seven days no VM can be enrolled or renewed, however often
  renewal runs, until an operator runs `rotate-ca` and re-enrolls every VM.
  `status` does not report the CA's expiry today, and AIVM reports every
  identity-child refusal only as "identity service refused the operation",
  so nothing tells the user why. (A planned change clamps new certificates
  to the CA's expiry instead, down to a stated minimum validity, below
  which the refusal remains. The CA must still be rotated before then.)
- **Known defect:** after `aivm vm identity_rotate_key`, the guest's
  `client.csr` still holds the CSR of the rotated-away key, and a plain
  renewal certifies whatever key the CSR carries. Every later
  `identity_renew` of that VM therefore re-certifies the rotated-away key
  and installs a certificate that does not match the guest's `client.key`.
  Case 3 of the
  [rollback and clone policy](aivm-secrets-garrett-rollback-clone-policy.md)
  gives the decided fixes and today's workaround.

### Decision

1. **No unattended renewal.** This release adds no daemon, timer, cron
   entry, systemd unit or background thread, and no command renews as a side
   effect. A renewal makes a forced-bootstrap SSH round trip (confirmable,
   and possibly `sudo`), signs with the CA, writes to the guest, and ends any
   live bound session of that VM. All of that must remain something the user
   asked for. Renewal stays host-initiated: a guest cannot renew itself,
   because the bootstrap key lives on the host. Any future unattended mode
   must keep that property.
2. **Bulk renewal:** `aivm vm identity_renew --all` (**decided**).
   **It ships only after both decided fixes for the known defect above:**
   the host rule that a renewal certifies only the enrolled key, and the
   guest change that regenerates `client.csr` from `client.key` and checks
   every installed certificate against it. Without them, one `--all` run
   would re-certify the rotated-away key of every VM that was ever rotated.
   It behaves as follows:
   - It is mutually exclusive with `--vm`. It needs `--identity_root` until
     the decided per-VM enrollment record can supply the default.
   - Candidates are every VM in the resolved machine store whose active
     principal is the caller, where `resolve_managed_identity` succeeds. It
     makes one `status` read of the authority.
   - When that `status` shows the CA has `CLIENT_DAYS` or less left, it
     renews nothing and stops with one message: run `rotate-ca`, then
     re-enroll every VM. Every renewal would be refused otherwise (see
     Facts). With less than `CLIENT_DAYS` plus 48 hours left, it renews as
     usual and warns that renewal will soon be refused. Both need `status`
     to report the CA's `not_after`, which it does not today.
   - A row is **due** when it is active and `not_after - now <= 172800`
     (48 hours). Already-expired active rows count as due.
   - It skips, and reports with its reason:
     - VMs not enrolled or revoked: re-enroll with `identity_enroll`. It
       never enrolls.
     - rows not yet due: reported with their expiry.
     - VMs that are not running: "start it, then renew". It never boots a
       VM.
     - VMs with a live *bound* session: "renew after the session ends, or
       with `--vm`". Renewal would end that session. A bound session is one
       that the read-only child `python -I -m aivm_secrets sessions --json`
       lists with that VM in its `vm` field and whose `directory` contains
       `identity.sock`, the bridge socket AIVM places there when it starts a
       bound session (`run_bound_secrets_ssh`). The listing has no field
       that marks a bound session, and the socket name is AIVM's own
       convention, so the check stays on the AIVM side. A plain
       `--secrets_policy` session does not block renewal.
   - It renews each due VM exactly as `--vm` does, one at a time, with the
     same CAS path and the same confirmations.
   - A `CommandError` or `SecretsError` for one VM is reported, and the batch
     moves on (`mgr.attempt`). A `CommandControlError`, from a declined or
     unavailable approval, stops the batch at once and propagates. A decline
     is never one VM's failure.
   - It prints one line per VM: renewed (new epoch and `not_after`), skipped
     (reason) or failed (reason). It exits nonzero if any VM failed. Run
     twice, it renews nothing the second time.
3. **Warning at session start** (**decided**). `aivm ssh
   --secrets_identity_root` warns, and neither renews nor refuses, when the
   client certificate is due by the same 48-hour rule. It also says when the
   session will end early because the certificate expires before the
   broker's lifetime does. The JWT is issued for the broker's announced
   lifetime (at most 3600 seconds) and capped at `not_after` (decided). An
   already-expired certificate is refused before any broker starts, with the
   actionable message "run `aivm vm identity_renew --vm X`". It also warns
   when the CA has less than `CLIENT_DAYS` plus 48 hours left, because the
   next renewal will be refused: "run `rotate-ca`, then re-enroll every VM".
   That part needs `status` to report the CA's `not_after`.
4. **Cadence: run `identity_renew --all` at least once a day.** A row is
   due only during the last 48 hours of its seven-day certificate, and a run
   renews a VM only if its due check falls inside that window. The interval
   between runs must therefore be shorter than 48 hours minus the time one
   run takes. A daily run renews every running, enrolled VM with one to two
   days to spare.

   A longer interval lets certificates expire before any run sees them due.
   Five days fails even in a steady state: the host stamps the new
   certificate when it signs, after that run's due check, so a VM renewed at
   R + 30 s still has 48 hours and 30 seconds left at R + 5 days. It is
   skipped, expires at R + 7 days + 30 s, and is renewed only at R + 10
   days. A certificate enrolled or renewed by hand between two such runs
   lapses the same way.

   A VM skipped for a whole window (stopped, or holding a bound session)
   lapses under any cadence. It can be renewed, if still active, by a later
   run once it is running and free. Expiry alone never requires
   re-enrollment. No cadence helps in the CA's last `CLIENT_DAYS`: rotate
   the CA before then.
5. **Unchanged:**
   - `CLIENT_DAYS` stays 7. Short certificates bound two things: how long a
     restored registry re-admits an already-issued certificate, and how
     long a copied key together with its certificate stays usable (until
     that certificate expires or the next renewal replaces it). They do not
     bound restored rows. `renew-client` ignores a row's `not_after`, so a
     row that a restored copy holds as active stays renewable whatever the
     copy's age, and `--all` counts it as due: a VM revoked after the copy
     was taken is renewed by the next run. After any known restore, follow
     "What to do today" in the
     [rollback and clone policy](aivm-secrets-garrett-rollback-clone-policy.md)
     before running `--all` again.
   - `renew-server` stays operator-only and needs a bridge restart.
   - CA expiry is handled by an operator `rotate-ca` followed by re-enrolling
     every VM.
