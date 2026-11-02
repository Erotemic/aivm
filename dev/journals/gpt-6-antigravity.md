## 2026-10-29 13:05:00 -0400 - Add optional Antigravity CLI provisioning

Added Antigravity as a disabled-by-default guest tool in the existing registry,
which supplies the named CLI provisioning target, TOML config validation,
required transport packages and status checks. The official shell installer
owns ~/.local/bin/agy, so this feature does not pretend that the shared
`tools.bin_dir` setting can relocate it. AIVM adds a repeat-safe PATH block;
the official installer may also modify shell configuration. Its current
release rejects documented flags to suppress those vendor-side changes. The
separate status probe checks the actual user-local binary because non-login
SSH may lack ~/.local/bin on PATH.

I chose to allow only `latest` because the published installer doesn't document
version pinning. The tradeoff is that a preexisting executable is reused rather
than forcibly upgraded during every provision. A failed curl or incomplete
install must stop provisioning and must not write a misleading PATH block.

The tests use a fake curl executable and a temporary HOME, with no VM, network
or live installer execution. The real VM and upstream installer still need a
manual smoke test after integration. No changes to secrets packaging or host
privilege policy are necessary.

## 2026-10-29 - Correct upstream installer invocation and dry-run libvirt guard

The live Linux installer rejects `--skip-aliases` and `--skip-path` with
`Unknown parameter`; its observed help lists only `--dir` and `--help`.
Run the published no-argument `curl -fsSL ... | bash` form instead. The
installer is still piped under `set -o pipefail`, and AIVM verifies `agy`
exists and responds before recording its own repeat-safe PATH stanza.
Keep the fake installer strict about zero arguments to reproduce this failure.

Separately, if both shared and personal machine-store roots exist, config
loading calls `require_domain_authority`; a dry-run manager previews the
underlying `virsh` capability probe but cannot provide its result. Skip that
live-only authority probe *only* during dry-run. Real commands still verify
ownership before acting. A focused test covers this two-store condition.


## 2026-10-29 13:46:00 -0400 - Comprehensive codebase and UX audit

Conducted an end-to-end repository audit covering architectural invariants, runtime edge cases, test suite health, privilege boundaries, and command ergonomics, writing the detailed findings to `docs/audits/2026-10-29-codebase-issues-and-ux-audit.md`.

Reflecting on the system, AIVM's layered design—specifically its auditable CommandManager, held-descriptor bind mounts, and machine-store lifecycle—is exceptionally thoughtful. However, I found several subtle friction points and state-leakage bugs where read-only commands (`aivm config show` and `aivm config discover`) accidentally mutate disk state on fresh installations, creating personal machine-store roots that lock in placement before the operator ever runs `aivm config init`. Similarly, `aivm config lint` suffered from an uncaught `FileNotFoundError` on nonexistent configs, and `aivm config discover --dry-run` crashed when checking command previews with `check=True`.

The most significant architectural risk I identified is the divergence in unmanaged domain handling between `config init` (which strictly rejects collisions) and `vm create` (which checks only store registration, potentially starting and stamping authority over an unmanaged or third-party libvirt domain). On the UX side, the prominent 9-step plan in `aivm help plan` inadvertently directs users away from the simple, automated `aivm code .` and `aivm ssh .` workflows that the project intends as the primary interface.

I am confident about the reproducibility and exact call-sites of the identified defects (tested empirically against live CLI invocations). The primary tradeoff in remediating the unmanaged domain adoption during `vm create` is ensuring automated test fixtures that intentionally start predefined test domains do not get falsely blocked. Next steps should focus on the immediate stability fixes identified in the audit report before tackling the broader UX enhancements.
