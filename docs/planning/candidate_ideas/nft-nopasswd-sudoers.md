# Candidate: a narrow NOPASSWD sudoers rule for nftables

Status: **candidate idea. Not implemented, not decided.** Written 2026-07-10.

## The problem this addresses

The managed nftables firewall is the one aivm feature that always requires root
and always will. `nft` needs `CAP_NET_ADMIN`. Under
`behavior.privilege_mode = "as-needed"` — after `aivm host sudoless setup` has
put you in the `libvirt` group and moved VM storage under your own user — the
firewall becomes the last routine source of sudo password prompts.

That is real friction, because the *reads* are frequent. `aivm status` runs
`nft list table inet <table>`, and `aivm code .` does too when the VM's SSH is
not already reachable and `--ensure_firewall` is set. `aivm` auto-approves its
own confirmation for read-only sudo commands (`behavior.auto_approve_readonly_sudo`),
but `sudo` itself still demands a password whenever its credential cache has
expired (~15 minutes by default). The prompt is not aivm's; it is sudo's.

The question is whether a scoped `NOPASSWD` sudoers rule is the right answer.

## What aivm actually runs

There are three shapes, and they do not have the same security properties.

| Command | Where | Frequency |
|---|---|---|
| `nft list table inet <table>` | `status.py:314,324,551`, `firewall.py:253` | every status / firewall probe |
| `nft --json list table inet <table>` | `firewall.py:278` | drift detection |
| `nft delete table inet <table>` | `firewall.py:212,459` | reapply, `fw remove` |
| `nft -f -` (ruleset on **stdin**) | `firewall.py:220` | `fw apply`, `net create` |

`<table>` is `firewall.table`, default `aivm_sandbox`.

## Why not the alternatives

**`setcap cap_net_admin+ep /usr/sbin/nft`.** A system-wide change granting
*every* user on the host the ability to flush the ruleset, redirect traffic,
and disable filtering. `CAP_NET_ADMIN` is root-equivalent for anything
security-relevant. This hands out a strictly larger capability than the sudo it
avoids, permanently, to everyone, to skip a password prompt. No.

**A polkit-mediated or setuid helper.** This is how libvirt does it, but
libvirt ships that helper as a distro package with an upstream security posture
behind it. For nftables, aivm would have to ship its own root-executed binary
and policy file. This repository already has a written rule against exactly
that shape — see the `VirtiofsConfig` docstring in `aivm/config.py` and the
line drawn in `dev/design/future/refactor-before-rootless.md`: aivm must not
generate host-side executables and configure something privileged to run them.

**Guest-side egress filtering.** Avoids host root entirely, but moves the
enforcement point inside the trust boundary it is supposed to enforce: guest
root can undo it. That is a different feature with a weaker guarantee, and it
is scoped separately in `dev/design/future/egress-allowlist.md`. Not a
substitute.

## The candidate

An operator-installed drop-in at `/etc/sudoers.d/aivm-nft`, mode `0440`,
validated with `visudo -cf` before install:

```sudoers
# Read the aivm-managed table without a password.
joncrall ALL=(root) NOPASSWD: /usr/sbin/nft list table inet aivm_sandbox
joncrall ALL=(root) NOPASSWD: /usr/sbin/nft --json list table inet aivm_sandbox
```

sudoers matches on the full argv, so these two lines permit exactly those two
commands and nothing else. They are read-only. This is the entire frequent
path, and it is genuinely narrow.

## The catch, which changes the recommendation

**`nft -f -` cannot be narrowed.** The ruleset arrives on stdin. A sudoers rule
matches the argv, not the input, so:

```sudoers
joncrall ALL=(root) NOPASSWD: /usr/sbin/nft -f -     # DO NOT DO THIS
```

grants the user the ability to load *any* nftables ruleset without a password.
That is full, standing, passwordless control of the host firewall. It is not a
scoped grant that happens to cover aivm's use; it is unrestricted `CAP_NET_ADMIN`
delivered through a different door. It is only marginally better than `setcap`,
in that it is per-user, requires `sudo`, and is logged.

No obvious redesign fixes this:

* Rendering the ruleset to a root-owned file and permitting
  `nft -f /etc/aivm/rules.nft` moves the problem — aivm cannot write a
  root-owned file without root, and if the file is user-writable the user can
  put any ruleset in it, which is the same grant.
* A validating wrapper script that accepts only aivm-shaped rules would work,
  but it is precisely the root-executed generated executable this repo has
  already refused.

So the apply path stays as it is: `apply_firewall` prompts. That is acceptable,
because it is rare — it runs on `aivm host fw apply`, `aivm host net create`,
and firewall drift, not on the `aivm code .` hot path.

## Security accounting

Worth stating plainly, because it cuts both ways depending on posture.

If you are **already in the `libvirt` group** — which `aivm host sudoless setup`
arranges, and which `aivm/privilege.py` documents as *effectively
root-equivalent on the host* — then a `NOPASSWD` rule for reading one nftables
table adds no meaningful capability. You could already control the root libvirt
daemon. The read-only lines above are close to free.

If you are **not** in the `libvirt` group and are using
`privilege_mode = "always"` with interactive sudo, then any `NOPASSWD` entry
converts a per-invocation authorization into a standing one. That is a real
change in posture, even for a read.

Either way, `nft -f -` under `NOPASSWD` is a standing grant of full firewall
control and should not be recommended to anyone.

## If we adopt this

aivm must **print** the recipe, never install it. Installing sudoers rules is
the operator's act, and setup commands do not change system or user
configuration on the user's behalf — the same principle that took the config
writes out of `aivm host sudoless setup` (see commit `71b1904`).

The natural home is `aivm host sudoless check`, which already reports the
firewall as the outstanding blocker to sudo-free operation. It could print the
two read-only lines, substituted with the real `firewall.table` value and the
invoking user, with a note that `nft -f -` is deliberately excluded and why.

## Open questions

1. Is removing a password prompt from a read worth adding a sudoers file to the
   host's attack surface at all? A `sudo -v` at the start of a session achieves
   the same thing for 15 minutes with no persistent state.
2. `nft delete table inet <table>` is narrow in argv and destroys only aivm's
   own table. Should it be in the recipe? It removes guest egress confinement
   without a password, but a user who can `nft -f -` interactively can do that
   anyway. Leaning no, on the grounds that it is not on the frequent path.
3. Should `aivm host sudoless check` detect an existing rule and report the
   firewall as satisfied rather than blocked?
