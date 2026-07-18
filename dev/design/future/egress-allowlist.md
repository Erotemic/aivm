# Egress allowlist networking

Written: 2026-07-02
Status: design ready for implementation; not started

## Problem

The managed firewall (`aivm/firewall.py`) blocks guest access to
host-local/private CIDRs but deliberately allows full WAN egress
(`docs/source/security.rst`, "Current design posture"). For agent
sandboxing this leaves the largest practical risk unaddressed: a
compromised or misbehaving agent can exfiltrate anything it can read
(including attached folders) to any endpoint on the internet.

The differentiating feature is an opt-in per-VM egress policy: "this VM
may reach `api.anthropic.com`, `github.com`, `pypi.org` — and nothing
else."

## Why naive nftables allowlisting is not the design

Domain-based policy cannot be enforced with static IP rules: CDN-backed
domains rotate IPs faster than any resolver snapshot, and one CDN IP
serves both allowed and disallowed hosts. Pure nftables designs leak or
break. The honest architecture separates *name policy* from *packet
policy*.

## Decided direction: filtering proxy + DNS control + firewall backstop

Three cooperating layers, all host-side (the guest is untrusted and gets
no enforcement role):

1. **HTTP(S) forward proxy on the host** (policy enforcement point).
   Guest traffic to 80/443 must traverse it; it allows `CONNECT`/requests
   only to allowlisted domains (suffix match). No TLS interception — SNI/
   CONNECT-target matching is sufficient and keeps trust simple.
   Implementation choice, in preference order:
   * a small built-in proxy (`aivm.netpolicy.proxy`, asyncio, ~300 lines:
     HTTP CONNECT + absolute-form GET, domain suffix check, structured
     deny log). Zero new host dependencies, runs as a user systemd
     service (reuse the unit-management pattern from
     `external-virtiofsd.md`); or
   * system `tinyproxy`/`squid` with a rendered config, if the built-in
     proxy proves insufficient (keep this as fallback, not default —
     host package installs need sudo and vary by distro).
2. **DNS control.** The managed libvirt network's dnsmasq answers guest
   DNS. Two sub-measures:
   * Guests get proxy environment via cloud-init and provisioning
     (`http_proxy`/`https_proxy`/`no_proxy` in `/etc/environment`,
     plus apt/pip/git proxy config) — cooperative, for well-behaved
     tools.
   * DNS for non-allowlisted names returns NXDOMAIN (dnsmasq
     `--server=/allowed.domain/#` + default `address=/#/` sinkhole),
     so casual resolution fails fast. This is defense-in-depth, not the
     enforcement point (a hostile agent can ship its own resolver and
     raw IPs).
3. **nftables backstop** (the actual containment). Extend the existing
   managed table (`aivm/firewall.py::_nft_script`): in egress-policy
   mode, drop all forwarded guest traffic *except* (a) established/
   related, (b) TCP to the host proxy port, (c) UDP/TCP 53 to the
   gateway dnsmasq. With this rule, layers 1–2 are the only ways out,
   so IP rotation and hostile resolvers stop mattering: raw-IP egress is
   simply dropped.

The combination gives domain-level *policy* with packet-level
*enforcement*, at the cost of "only proxy-capable protocols work" — an
acceptable and honest constraint for agent workloads (HTTP(S) covers
package managers, git-over-https, LLM APIs). SSH-to-anywhere etc. is
deliberately not supported in strict mode; document it.

## Config

```toml
[egress]
mode = "open"            # "open" (current behavior) | "allowlist"
allow_domains = ["api.anthropic.com", "github.com", "*.githubusercontent.com", "pypi.org", "files.pythonhosted.org"]
proxy_port = 0            # 0 = auto-allocate per VM, persisted in state
log_denials = true
```

Ships with `mode = "open"` — no behavior change until opted in. Provide a
documented starter allowlist for common agent stacks (Anthropic API,
GitHub, PyPI, npm, apt mirrors) rather than making users discover
endpoints by failure.

## Interaction with existing machinery

* **Firewall module**: egress mode is rendered into the same
  `aivm_sandbox` table by `_nft_script`; `read_firewall_tcp_ports`-style
  drift detection extends to the egress rules (compare rendered vs live,
  as `aivm/vm/drift.py::firewall_drift_report` already does for ports).
* **Privilege model**: nftables and dnsmasq options on the managed
  network are root-side, so `mode="allowlist"` requires the system
  runtime with sudo available — add the guard via
  `aivm/privilege.py::require_sudo_allowed` exactly like
  `apply_firewall` does today, and a config-lint warning for
  `egress.mode="allowlist"` + `privilege_mode="never"`.
* **dnsmasq options**: the managed network XML is rendered in
  `aivm/net.py::ensure_network` — add
  `<dnsmasq:options>` entries (libvirt supports the dnsmasq namespace)
  rather than editing host dnsmasq configs.
* **Status/observability**: `aivm status` gains an egress line (mode +
  proxy health + denial count from the proxy log); `security.rst` future
  work item "fail-closed checks" applies — if `mode="allowlist"` but the
  proxy is down or rules are missing, `code`/`ssh` reconcile must warn
  loudly (or block with `--strict-egress`).

## Implementation plan

1. Config plumbing (`EgressConfig` dataclass, store round-trip, lint).
2. Built-in proxy module + user unit management + unit tests (pytest
   against a live local instance on a random port: allowed CONNECT,
   denied CONNECT, absolute-form request, denial logging).
3. nftables egress rules in `_nft_script` + drift detection + unit tests
   (rendered-script assertions, like existing firewall tests).
4. dnsmasq allowlist options in network XML render + unit tests.
5. Guest proxy environment via cloud-init (create-time) and provisioning
   (retrofit path), mirroring how fdguard handles new-vs-existing VMs.
6. Reconcile integration + status line + fail-closed warning.
7. Docs: security.rst gains an "Egress policy" section (update the
   posture bullets that currently say WAN egress is unrestricted);
   README feature list; quickstart example.
8. E2E (`test_e2e_egress.py`): boot VM with allowlist mode; in-guest
   `curl https://pypi.org` succeeds via proxy; `curl https://example.com`
   fails; raw-IP connect (`curl https://1.1.1.1`) fails at the packet
   layer; flip config to open, `vm update`, verify unrestricted.

## Acceptance criteria

1. With `mode="allowlist"`, in-guest HTTPS to an allowed domain works
   and to a non-allowed domain fails — including with proxy env vars
   stripped and raw IPs (packet backstop holds).
2. `mode="open"` is byte-identical in behavior to today.
3. Drift detection reports and `vm update` repairs missing egress rules
   and a dead proxy service.
4. Denials are visible (log file surfaced by `status --detail`).
5. ``privilege_mode="never"`` + allowlist is rejected with actionable
   guidance, not a deep command failure.
6. Documentation states the protocol limitation (proxy-capable protocols
   only) and the threat it does/doesn't address.
