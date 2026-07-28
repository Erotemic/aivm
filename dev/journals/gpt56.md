## 2026-07-27 11:30:00 -0400

Built an intentionally unintegrated GitLab deploy-key backend so provider work can proceed without touching the active GitHub credential, VM lifecycle, CLI, schema, or configuration changes. The module uses the standard-library HTTP client, keeps the API token in memory and in the `PRIVATE-TOKEN` header, supports nested GitLab namespaces, performs deploy-key CRUD, and follows pagination without forwarding credentials across origins.

I am confident in the provider API surface and its unit tests, but it is deliberately dormant: no existing module imports it, and no schema kind or provider selector refers to it. Later integration will need to decide how GitLab tokens are configured, how repository resolution admits subgroup paths, and how the service layer chooses a backend. The main risk at that stage is not this HTTP client but accidentally coupling provider selection to the currently GitHub-shaped credential schema.

## 2026-07-27 16:30:00 -0400

Rebased the independent GitLab deploy-key client onto commit 9d76f42 and integrated it behind a provider dispatch seam without replacing the completed GitHub setup/version-gating work. The credential schema now admits GitLab records, repository identities preserve nested GitLab namespaces, guest SSH/Git routing remains shared, and add/status/revoke use the recorded provider kind. GitLab.com is inferred automatically from canonical remotes; self-managed GitLab is explicit. Host authentication is a `GITLAB_TOKEN` sent only in the recommended `PRIVATE-TOKEN` header, with optional `GITLAB_API_URL` for nonstandard self-managed endpoints.

I kept the first integration deliberately local and dependency-free: there is no `glab` requirement and no token persistence in AIVM state. The practical consequence is that GitLab status, add, and revoke commands require the token in the host environment. A future credential-store feature can improve that UX without changing the guest key or provider lifecycle model.

## 2026-07-27 17:45:00 -0400

Rebased the GitLab integration onto commit ab2edad, after the credential lifecycle adopted administrator handoff as settled policy. Provider publication is now uniformly best effort: missing GitHub tooling or login, a missing GitLab token, permission and organization-policy failures, definitive provider refusals, and uncertain transport outcomes all preserve the generated keypair, install the private half in the VM, and record an unregistered credential for manual publication. Only failures in the local credential work itself remain fatal.

The GitLab backend remains a direct v4 REST client with no glab dependency. Provider selection and recorded kinds dispatch add, status, and revoke without changing the shared SSH guest model. Direct GitLab API mutations use CommandManager approval, while setup remains a diagnostic for automation readiness rather than a prerequisite for creating a credential.

## 2026-07-28 11:30:02 -0400

Planned the move from AIVM's mixed per-user/global state into one shared-machine authority with per-host-user guest principals. The key decision is not to productize the tempting shadow-store or shared-single-account workaround. Instead, the hostname-qualified VM remains the natural rendezvous point: the first user creates it, and later users join through `aivm config init` without redefining the machine.

The hardest usability seam is initial guest enrollment. A later user cannot use a personal key before it is authorized, so the plan introduces a narrow machine-scoped bootstrap identity and an idempotent guest helper rather than copying the creator's private key. This is intentionally designed so a future privileged host daemon can take over the transport without changing principals, attachments, or the user-facing join workflow.

I am confident about the scope split and phased ordering. The main implementation risks are group-safe atomic machine-store writes, UID/GID collisions in existing guests, migration conflicts when multiple old stores claim one domain, and ensuring persistent attachment replay is generated only from the complete global inventory. The roadmap keeps each of those behind a separately testable work package and preserves legacy `agent` accounts during migration rather than forcing a risky rename.
