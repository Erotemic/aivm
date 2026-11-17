# Secret broker hardening and bounded CLI compatibility

Status: experimental Python implementation; **no formal proof**. This work
applies on top of AIVM commit `a557928` (2026-10-10). Refer to
[aivm-secrets-kernel-spec.md](aivm-secrets-kernel-spec.md) and
[aivm-secrets-assumptions.json](aivm-secrets-assumptions.json) for the
security contract and the trusted assumptions.

## Goals and constraints

* Fix ambient TLS key export, guest-selected runtime directory placement, and
  import-mode fallback without changing capability wire/session semantics.
* Make a useful *constrained subset* of familiar `gh` commands work in a VM
  for reviewing TauCeti PRs. Preserve repository, PR-number, author and head
  repository restrictions enforced by the host.
* Keep the common kernel and the guest command-table evaluator independent of
  any specific provider; GitHub remains an optional host-authored manifest.
* Support **only operator-fixed** GraphQL query documents and allowlisted
  scalar variables. Never accept a guest-supplied GraphQL document, dynamic
  API URL, arbitrary `gh api`, or the real `gh` authentication token.

## Host isolation changes

1. The AIVM host subprocess drops `SSLKEYLOGFILE` alongside loader-related
   environment variables. The TLS executor constructs an `SSLContext`
   explicitly and forcibly disables `keylog_filename`, including when run in
   standalone mode. Tests check that a TLS exchange does not create a key log.
2. The session runtime root and channel directory use the **same** untrusted
   root exclusions as source-policy checks. `aivm-secrets serve` verifies the
   root before obtaining a credential. In AIVM, the guest workspace is an
   untrusted root. An operator-provided `XDG_RUNTIME_DIR` within that tree
   is rejected even if it is currently mode `0700`. This is a fail-closed
   configuration error, not a reason to fall back silently to `/tmp`.
3. `aivm ssh` always launches the credential broker using Python `-I`.
   User-site installations (which `-I` would not be able to import) are
   refused. Install the broker inside a protected virtualenv or system
   prefix. Reintroducing `-E -P` would expand the trusted import surface.
4. Resolver subprocesses do not inherit `SSLKEYLOGFILE` as an explicitly
   requested environment variable. Resolver code and its dependencies remain
   host-trusted under RES-01, not protected by formal verification.

## Portable declarative CLI compatibility

The schema-1 shorthand preserves its previous canonical policy digest and
CLI table by default. Set ``"gh_compat": 2`` in the host policy to enable
the richer table; the wire authorization and core kernel are unchanged.
A read-only example is at
``docs/examples/aivm-secrets-tauceti-gh2.json``.

`CLICommand` now admits **data-only** rendering/inference metadata:

* `json_fields`: output field name -> JSON object-key pointer into one
  previously authorized result. The guest may select at most 32 distinct
  declared names with `--json field1,field2`, not submit a `--jq` program.
* `json_at` and `json_list`: optional pointer to a nested response, and
  explicit indication of whether that response must be an array. No
  provider-specific output parser belongs in the common kernel.
* `json_rules`: optional allowlisted mapping of one scalar field and a
  fallback pointer; intended for common status translations, not arbitrary
  expressions.
* `json_complete`: refuse list projection if REST page metadata indicates
  there may be more entries.
* `json_alternative`: optionally select a *separately granted read operation*
  for specific fields, with an independent JSON pointer and `incomplete_when`
  marker. Selecting different fields can therefore require additional
  authorization, but never grants it.
* `repository_default`: map a declared request parameter from a local
  environment variable or read-only Git remote URL. The guest uses no
  subprocess and never loads Git config extensions, credential helpers or
  aliases. **Host scope validation always makes the final decision.**

### TauCeti commands

Given a host policy with ``gh_compat: 2`` authorizing PR 13861 and its
expected ownership facts:

```bash
# Stock-shaped syntax with a safe, explicit PR number.
gh pr view 13861 -R TauCetiProject/TauCeti --json title,body,number
gh pr checks 13861 -R TauCetiProject/TauCeti --json name,state,link
gh pr diff 13861 -R TauCetiProject/TauCeti

# This requires the *additional* 'pr.summary' operation in the host policy.
gh pr view 13861 -R TauCetiProject/TauCeti \
  --json title,body,reviews,reviewDecision

# A separate, bounded GraphQL read for unresolved review threads.
aivm-secrets invoke pr.review-threads \
  --arguments '{"repository":"TauCetiProject/TauCeti","pr":13861}'
```

A `GH_REPO=TauCetiProject/TauCeti` environment variable or local upstream
Git remote may supply `-R`, but it does not broaden the permitted repository.
For actual read-only operation, grant `pr.view`, `pr.checks`, and optionally
`pr.summary` or `pr.review-threads`, plus an explicit PR-number allowlist.
Preflights validate base repository, PR author and PR head repository before
fetching the selected data. `pr.summary` and `pr.review-threads` are **not**
automatically added to existing policies.

### Fixed-query GraphQL

A schema-2 HTTPS operation can declare this special case:

```json
{
  "name": "widget.count",
  "effect": "read",
  "method": "POST",
  "path": "/graphql",
  "parameters": {"widget": [7, 8]},
  "graphql": {
    "operation": "WidgetCount",
    "document": "query WidgetCount($widget: Int!) { widget(id: $widget) { count } }",
    "variables": {"widget": "widget"}
  }
}
```

The manifest parser admits only one named query document as a bounded host
constant; it rejects declared mutations and extra operations, and binds the
exact query to the policy digest. It is *not* a general GraphQL parser. The
kernel and executor verify the fixed document, POST method and typed scalar
variables. This makes the request's **shape** inspectable, not the provider's
implementation: a provider could still mutate state in a `query` resolver.
The read-only assumption remains SPEC-02 and must be reviewed for each query.
GraphQL errors in a `200` response fail closed rather than being presented as
valid PR data. `reviewThreads`/`reviews` currently request at most 100 nodes;
where completeness is required, detected pagination is refused rather than
silently accepted as a complete review history. The fixed query does not yet
support following GraphQL cursors.

## Explicit non-goals / remaining gaps

* **Not a stock `gh` replacement.** `gh api`, `gh auth`, `gh run view`,
  workflow-log downloads, `--jq`, `--template`, free-form GraphQL, GitHub
  issue management beyond declared operations, and inferring a PR from the
  current branch are unsupported. The synthetic `gh pr reviews` and
  `gh pr review-threads` are not official `gh` subcommands.
* The supported `gh --json` projections are a reviewed subset and may not
  match all objects/derived fields of the official CLI. Check-run state
  mapping is intentionally limited. Do not replace a campaign's real `gh`
  executable globally without a command-by-command compatibility audit.
* `gh pr checks` currently reads GitHub **check runs** for the validated
  commit; it does not reconcile all commit statuses or retrieve CI logs.
* GitHub GraphQL is subject to its own authentication, resource and rate
  constraints. Live API compatibility and credentialed VM smoke tests remain
  **unverified** in this overlay.
* No Python test is a formal proof. The eventual Rust/Aeneas/Lean model must
  add effect variants for verified fixed queries, predicate on the **declared**
  effect class, and include serializer/executor refinement obligations.

## Proof and security-review obligations

* `HOST-01`/`LAUNCH-01`: checked paths and code origin never traverse a
  guest-writable root, including *runtime* state; host-selected imports and
  resolver dependencies remain a separate trust assumption.
* `ROUTE-01`: a GraphQL request is exactly the fixed document, pinned
  destination, declared variables and authorized resource values.
* `AUTH-01`: a selected alternative read must be in the grant with its own
  preflight, reservation and budget; a CLI row cannot synthesize authority.
* `SPEC-02`: query/resolver read-only semantics are external; proving that the
  query string begins with `query` does **not** prove nonmutation.
* `COMP-01`: the produced `AuthorizedEffect` and the serialized TLS bytes
  correspond to the same policy operation. No arbitrary guest data can be
  inserted as an executable query or as an HTTP destination.

Tests added here are executable evidence for these properties, not proof
artifacts. The safety claim should remain *experimental* until the trusted
interpreter and effect producer are independently verified and exercised
against the real TauCeti workflow.
