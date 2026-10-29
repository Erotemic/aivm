## 2026-10-29 13:05:00 -0400 - Add optional Antigravity CLI provisioning

Added Antigravity as a disabled-by-default guest tool in the existing registry,
which supplies the named CLI provisioning target, TOML config validation,
required transport packages and status checks. The official shell installer
owns ~/.local/bin/agy, so this feature does not pretend that the shared
`tools.bin_dir` setting can relocate it. Its automatic profile/alias edits are
suppressed and AIVM maintains its own repeat-safe PATH block. The separate
status probe checks the actual user-local binary because non-login SSH may
lack ~/.local/bin on PATH.

I chose to allow only `latest` because the published installer doesn't document
version pinning. The tradeoff is that a preexisting executable is reused rather
than forcibly upgraded during every provision. A failed curl or incomplete
install must stop provisioning and must not write a misleading PATH block.

The tests use a fake curl executable and a temporary HOME, with no VM, network
or live installer execution. The real VM and upstream installer still need a
manual smoke test after integration. No changes to secrets packaging or host
privilege policy are necessary.
