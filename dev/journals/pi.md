# pi journal

## 2026-09-18 13:56:18 -0400
Added the `pi` agent harness to the guest tool registry so aivm can provision
pi on guests the same way it already does for claude and codex. The
implementation lives in `aivm/vm/guest_tools.py` (`_pi_spec`,
`_build_pi_install_script`, and a new `GuestToolDefinition` in
`GUEST_TOOL_REGISTRY`); everything else — config dump/parse, the `aivm
provision` positional targets, status probing — picked it up automatically
because those surfaces are registry-driven.

The main design decision was to use pi.dev's official installer
(`curl -fsSL https://pi.dev/install.sh | sh`) rather than wrapping the
underlying `npm install -g` directly. That keeps the guest running whatever
the upstream project documents, which matters for a tool that updates faster
than aivm does. Three constraints shaped the script:

- The installer's preflight requires Node.js 22.19.0+ and its own Node
  bootstrap is interactive-only, while aivm's SSH transport never allocates a
  tty. So the script mirrors the installer's exact version check and
  installs Node 22 through NodeSource first, but only when the existing
  toolchain is missing or too old — a guest that already has a suitable Node
  (for example a user-managed one) is not touched.
- In a tty-less session the installer auto-continues with install/reinstall
  and never uninstalls, which makes piping it to `sh` idempotent and safe.
  The script still guards with `command -v pi` so reruns are no-ops.
- The installer lands pi in `~/.local/bin` for ordinary users, but falls back
  to the npm global prefix when that is user-writable (nvm-style setups),
  and in non-tty mode it does not update shell profiles at all. The script
  therefore resolves the actual bin dir after the fact (`PI_BIN_DIR`, with a
  `npm prefix -g` fallback), prepends it, verifies `pi` resolves, and appends
  its own guarded `# >>> aivm pi PATH >>>` profile block.

Spec handling accepts only `latest`/`off` (plus booleans): the official
installer has no version argument, so pinned specs raise `GuestToolSpecError`
and fail as domain errors naming the config value, matching the claude
pattern.

Verification went beyond the unit suite because none of it exercises a real
install. I ran the generated script in a hermetic fake `$HOME` with stub
installers for the three flows (system Node with `~/.local` install, a
user-configured npm prefix, and an already-installed no-op), and then a true
end-to-end run of the real pi.dev installer against an isolated copy of a
Node 22 tree: it proceeded without a tty, installed pi 0.85.1 into the
configured prefix, and the profile block the script wrote made a login shell
find `pi`. `tests/test_vm_guest_tools.py` gained the matching coverage
(registry order, defaults, aggregation, spec rejection, script content,
config round-trip, domain-error wrapping), and the full suite is green
(1312 passed, 11 skipped — the skips are e2e tests that need libvirt, which
this host does not have). Regenerating
`docs/architecture/generated/compatibility-inventory.md` was required because
the new script added one more `AgentVMConfig` reference in guest_tools.py.

Uncertainties and what might break: the script assumes a Debian/Ubuntu guest
(NodeSource is Debian-only, and so is the existing toolset, so that is
consistent); a guest that has Node but no `npm` will get a fresh NodeSource
Node rather than trying to repair the existing install, which is the safe
default but may surprise a partial setup. The `npm prefix -g` fallback trusts
the npm configuration of the guest user, which is correct for nvm-style
layouts but means an oddly configured guest could point the PATH block at an
unexpected directory. Upstream pi changes to the installer's install location
or Node requirement would need to be re-verified — the version check string
in the script is a copy of the installer's, not a reference to it. I am
confident in the registry/config/status integration (all of it reuses the
established machinery and is covered by the suite) and in the script's
idempotency logic as tested; the NodeSource bootstrap path itself was only
exercised in the real E2E in the branch where Node was already adequate, not
in a from-scratch apt install, so a first-run guest should be spot-checked on
a real VM when one is available.

## 2026-09-18 16:27:33 -0400

Finished the execution-testing and bookkeeping that
dev/handoff-pi-rework.md left open (the handoff file is now deleted;
the feature diff itself is left uncommitted for review).

What I did. Added the hermetic shell execution matrix to
tests/test_vm_guest_tools.py that the handoff specified. A
`_PiShellHarness` builds a fake guest tree under tmp_path — stub
npm/curl/sudo/apt-get, a NodeSource staging toolchain, real coreutils
symlinked as the PATH tail, an isolated npm prefix, and a stub
pi.dev/install.sh — and runs the generated shell under a fully custom
env so nothing outside the tree is reachable. Seven install cases
drive `_build_pi_install_script` end to end: clean machine (the
NodeSource bootstrap fires exactly once, then the installer runs and
the profile PATH block is written), node-without-npm, an old user
node being shadowed by the bootstrap's PATH prepend,
@mariozechner/pi-coding-agent migration, a healthy no-op that stays
idempotent across two runs, refusal of a foreign `pi`, and the
below-floor update. Six status cases execute the fragment exactly the
way `aivm/status.py` does (a standalone `set -e` command) and assert
the 0/11/12 exit codes and exact stderr, including the identity line
on stdout for the healthy case. The registry-probe test was extended
to prove pi contributes the identity fragment (not a bare
`command -v`) to the remote provision probe.

One small production change was forced by this work: the healthy
branch of `_pi_status_check` captured the verified identity in a
shell variable but never printed it. Since `status --detail` renders
the fragment's stdout as probe evidence, I added `echo "$aivm_pi_id"`
there; the probe now shows *which* package/version satisfies the
requirement instead of merely that a `pi` binary exists, matching what
the install script's final verification already proves.

Reflections. The handoff's warning about stale file state turned out
to matter more than expected: the read tool served me an *earlier
version* of tests/test_vm_guest_tools.py and aivm/status.py (same
line counts, different content), so my first "ground truth" pass
rested on stale reads. Everything material was re-verified through
bash (sed/grep/wc) and, above all, by running the tests: the real
probe API is `probe_provisioned(cfg, ip)`, which assembles the remote
command internally and runs it via `CommandManager`, and the real
install body has slightly different user-facing strings than the
stale copy showed. Of the thirteen new execution tests, twelve passed
on the first run; the one failure chain was harness defects, not
production defects (the coreutils list was missing `rm`; the
migration run announces itself before printing the version; an empty
`@scope` dir legitimately remains after uninstalling a scoped
package). Lesson for this repo: trust bash and the test run; treat
read output as a hint only.

State. 43/43 module tests; full suite 1331 passed, 11 skipped (the
skips are e2e tests needing libvirt, absent on this host). `ty check
aivm` reports six diagnostics, all in files this work does not touch
(cli/config/lint, credentials/plan, legacy/pre_0_6_0, rc/guest) —
none in guest_tools.py or status.py. The architecture-docs check
(dev/devcheck/architecture_docs.py check) passes, so no inventory
regeneration was needed this session (my edit added no
AgentVMConfig references).

Uncertainties / what might break. The NodeSource bootstrap is
verified through stubs only, never against a live apt, so a
first-run guest should still be spot-checked on a real VM. The stub
npm models just enough npm behavior (prefix -g, ls, uninstall,
--version) that a change in real npm's output shapes could
invalidate the identity probe's sed extraction without any test
here noticing. Post-uninstall, the empty `@scope` dir means any
future "is the old package gone" check must look at the package
dir, not the scope dir.

What I'm confident about: the identity-gated install and the status
fragment now have real execution coverage that would catch a
regression in the shell logic itself, not just in string content,
and the stdout-on-healthy change is small, local, and exercised by
both the execution matrix and the probe test.

## 2026-09-29 17:27:25 -0400

Work: bumped the kwconf floor to 0.12.0 (pyproject.toml,
requirements/runtime.txt, uv.lock, requirements/locks/*) and fixed the
two ty `invalid-method-override` errors in aivm/cli/main.py by giving
the `AgentVMModalCLI.argparse` override the 0.12.0 base signature
(new `short_alias_clusters: bool | None = None` param, threaded through
to `super().argparse`). Also fixed a stale comment: the hardcoded
`--version` (no `-V`) is kwconf behavior in every release through
0.12.0, not a 0.10.x-only quirk, and there is no kwconf hook to
customize the spelling, so the `-V`-restoring override stays.

Context: this started as a "why does CI see fewer ty errors than I
do" question. The local divergence was a stale ty 0.0.38 in
~/.local/bin (42 diagnostics, ~40 of them old stdlib-stub false
positives on `dict.get`) versus CI's latest ty (2). Upgrading the
local ty to 0.0.84 made both agree, and the 2 that remained were the
genuine LSP violation, which this session fixes.

Reflection: the interesting discovery was that the code comment
("kwconf 0.10.x hardcodes...") had fossilized a version-specific
workaround rationale into a general claim. Reading the kwconf source
across 0.10.1/0.11.0/0.12.0 showed the hardcoding is invariant
design, so the comment was both wrong and misleading about whether
the override could ever be dropped. Comments that encode "why we
can't simplify this" deserve the same version-verification as code.

State/verification: `ty check aivm` is clean (0 diagnostics; was 2).
`ty check aivm tests` went 5 to 3; the 3 remaining
(unresolved-attribute on `GuestToolDefinition | None` in
tests/test_vm_guest_tools.py) are pre-existing and out of scope here.
mypy (local strict flags, not run by CI) went 67 to 65; the 65 are
pre-existing mostly-missing-annotation noise in tests. Full non-e2e
suite: 1337 passed, 11 deselected, on kwconf 0.12.0 in the active uv
env. `aivm --version` and `aivm -V` both print 0.6.0; `aivm vm
--version` correctly stays unrecognized.

Uncertainties/risks: the local `.venv` is a dead artifact from another
machine (broken python symlink) and still carries kwconf 0.10.1;
anything that activates it will run against the old kwconf. The
active env (uvpy3.13.2) already had 0.12.0, which is what everything
above was verified against. Passing `short_alias_clusters=` to
`super()` unconditionally requires the 0.12.0 floor, so the two
changes in this commit are coupled; keeping a 0.11.0 floor would
have forced an inspect.signature shim, which I deliberately did not
do.

Confident: the override fix is the minimal correct one (signature
match + pass-through, no behavior change), the lock regeneration
touched only the kwconf entries, and the CLI surface is byte-identical
for users.

## 2026-10-02 19:54:45 -0400
Added a TODO comment to the pi installer body (`_PI_INSTALL_BODY` in
`aivm/vm/guest_tools.py`, the guest script behind `aivm vm provision pi`):
right before the final `pi --version`, it now says TODO: ensure
`pi install -l npm:pi-provider-litellm` also runs to set up the litellm
endpoint (and make sure you have the .llm_resource_tally hook enabled).
Placed it at script completion so the pending post-install step sits where
a future implementation would naturally hook in, without touching any
behavior. Verified: `py_compile` clean, comment present at the end of the
dedented body with `pi --version` still the final line, and all 44 tests in
`tests/test_vm_guest_tools.py` pass (fresh uv env; kwconf 0.12.0).
Confident this is comment-only; no shell logic, PATH blocks, or
verification steps changed.

## 2026-10-02 20:14:46 -0400
Follow-up on the `allow_tcp_ports` discussion: the user asked where the
authority for that config key lives and whether it could be aliased.
Answered from the code: the `FirewallConfig` dataclass in
`aivm/config.py` is the definition; both parse paths (`load()` and
`config_store/parse.py`) enforce exact field names via `hasattr` and
silently drop unknown keys; both renderers emit canonical names from
`asdict()`, so an alias would be read-only by construction. Per request I
added a TODO above the field in `FirewallConfig`: rename to
`allow_any_url_tcp_ports` (or better, make it clear these override the
block CIDRs). Comment-only; no rename or alias implemented yet — that
would be a deliberate schema/terminology change. Verified: `py_compile`
clean and the 75 tests across test_firewall/test_config/test_store/
test_machine_store pass.
