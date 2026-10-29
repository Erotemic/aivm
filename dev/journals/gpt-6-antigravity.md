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
