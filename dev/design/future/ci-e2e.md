# E2E suites in CI

Written: 2026-07-02
Status: design ready for implementation; not started

## Problem

The e2e suites (`tests/test_e2e_nested.py`, `test_e2e_full.py`,
`test_e2e_sudoless.py`; opt-in via `AIVM_E2E=1`, see
`run_e2e_tests.sh`) are the project's most effective regression
detector — they have caught real bugs that the 470+ unit tests missed in
nearly every recent development session (silently-wrong URIs, permission
crashes, privilege-model gaps). They currently run only on developer
machines with libvirt/KVM. Nothing guards `main` against regressions in
the real command paths.

## Feasibility facts

* GitHub-hosted `ubuntu-latest` runners support nested virtualization:
  `/dev/kvm` is available on Linux runners (officially since 2023;
  enable with a udev rule or group add in the job). Boot times for the
  aivm guest are small (the full local suite of 3 e2e modules runs in
  ~90 s wall on a 16-core dev VM; expect 2-4x slower on a 4-core
  runner, still well under 10 minutes).
* The 600 MB Ubuntu cloud image is the main network cost; the suites
  already support a local cache (`~/.cache/aivm/e2e/`,
  `AIVM_E2E_SHARED_IMAGE`) — use `actions/cache` keyed on the pinned
  image URL from `aivm/config.py::DEFAULT_UBUNTU_NOBLE_IMG_URL` so the
  download happens roughly once per image bump.
* Sudo: GitHub runners have passwordless sudo, so even the sudo-path
  suites work. The sudoless suite additionally needs libvirt group
  membership for the runner user + re-login semantics — use `sudo -u` a
  fresh login shell or `sg libvirt` to pick up the group without a real
  re-login.

## Design

### Workflow shape (`.github/workflows/e2e.yml`)

```yaml
on:
  pull_request:
  push: {branches: [main]}
jobs:
  e2e:
    runs-on: ubuntu-latest
    timeout-minutes: 30
    steps:
      - uses: actions/checkout@v4
      - name: Enable KVM
        run: |
          echo 'KERNEL=="kvm", GROUP="kvm", MODE="0666", OPTIONS+="static_node=kvm"' \
            | sudo tee /etc/udev/rules.d/99-kvm4all.rules
          sudo udevadm control --reload-rules && sudo udevadm trigger --name-match=kvm
      - name: Install host deps
        run: sudo apt-get update && sudo apt-get install -y --no-install-recommends \
             qemu-kvm libvirt-daemon-system libvirt-clients virtinst \
             cloud-image-utils qemu-utils dnsmasq-base nftables acl
        # keep this list in sync with aivm/host.py::install_deps_debian
      - uses: actions/cache@v4
        with: {path: ~/.cache/aivm/e2e, key: aivm-e2e-image-${{ hashFiles('aivm/config.py') }}}
      - name: Setup libvirt access
        run: sudo usermod -aG libvirt,kvm "$USER" && sudo systemctl start libvirtd
      - name: Run e2e
        run: sg libvirt -c 'AIVM_E2E=1 AIVM_E2E_HOST_CONTEXT=1 pytest tests/test_e2e_nested.py tests/test_e2e_sudoless.py -v'
```

(Sketch, not final: the implementing agent should verify each step
against a real runner run; the udev trick and `sg` group-refresh are the
two fragile spots.)

### Suite tiering

* **PR gate (required)**: `test_e2e_nested.py` (fast smoke) +
  `test_e2e_sudoless.py` (never-sudo guarantee; also the best canary for
  privilege regressions). Budget: < 10 min.
* **main/nightly (non-blocking)**: add `test_e2e_full.py` and, when they
  exist, the external-virtiofsd / egress / snapshot e2e modules.
* Keep `AIVM_E2E_BOOTSTRAP` (outer-VM bootstrap suite) out of CI — it
  nests a second VM level and is too slow/flaky for shared runners.

### Hygiene requirements (learned locally, must be encoded)

1. **Leftover cleanup**: the suites leak per-VM storage under
   `/var/lib/libvirt/aivm-e2e/` and live bind mounts even on success
   (observed repeatedly during development). CI runners are ephemeral so
   it "works", but fix it at the source anyway: add a pytest fixture
   (or `finally` block) that unmounts `*/shared-root/*` and
   `*/persistent-root/*` mounts and removes the per-VM dir. This also
   fixes local disk-bloat (7.7 GB of stale caches were found on one dev
   box).
2. **Failure diagnostics**: on failure, upload `virsh list --all`,
   `virsh net-list --all`, the libvirtd journal, and the pytest output
   as an artifact — e2e failures are undebuggable from the assertion
   alone.
3. **Serialization**: never run e2e modules with `-n`/xdist; the suites
   use unique names but share host libvirt state and image cache locks.

### Unit-test job

While adding workflows: a plain unit job (`run_tests.py`, linter, type
checks, doctests, `docs` build with `-W` on content warnings) on the
same triggers, if not already covered elsewhere. It is cheap and the
repo currently relies on developers running these locally.

## Implementation plan

1. Fix the e2e storage/mount leak (fixture-based cleanup + assert no
   `aivm-e2e` mounts remain at module teardown). Run locally.
2. Add the unit-test workflow; confirm green.
3. Add the e2e workflow with only `test_e2e_nested.py`; iterate on the
   KVM/libvirt setup steps until green (this is the empirical part —
   budget several workflow iterations).
4. Add `test_e2e_sudoless.py` (needs the `sg libvirt` group trick +
   `setfacl` present — the acl package is in the install list).
5. Add the nightly job with `test_e2e_full.py`.
6. Document in README (replace "run them locally" note with local + CI
   description) and mark the required checks in repo settings.

## Acceptance criteria

1. PRs run smoke + sudoless e2e on GitHub-hosted runners in < 15 min
   with the image cache warm.
2. A deliberate regression (e.g. break `virsh_system_cmd` URI) fails the
   PR gate.
3. No `aivm-e2e` mounts or storage survive a suite run (locally
   verifiable: `grep aivm-e2e /proc/mounts` empty after pytest).
4. Failure runs upload actionable diagnostics artifacts.
