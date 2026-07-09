Running aivm under WSL2
=======================

``aivm`` works inside WSL2 — the guest VM runs nested under Hyper-V — but
WSL hosts hit a distinct set of footguns that plain Linux hosts do not.
This page is the checklist. ``aivm host doctor`` performs the load-bearing
checks automatically and prints WSL-specific fixes.

Requirements at a glance
------------------------

* **WSL2, not WSL1.** WSL1 is a syscall translation layer with no real
  kernel and can never provide ``/dev/kvm``. Check with ``wsl -l -v``
  from PowerShell (VERSION column must be 2), or confirm
  ``/proc/version`` mentions ``WSL2``.
* **Nested virtualization** so ``/dev/kvm`` exists inside the distro.
  On current Windows 11 this is usually on by default; otherwise add to
  ``%UserProfile%\.wslconfig`` on the Windows side::

      [wsl2]
      nestedVirtualization=true

  then ``wsl --shutdown`` from PowerShell and reopen the distro. Verify
  with ``ls -la /dev/kvm``. The host CPU must support nested
  virtualization and have VT-x/AMD-V enabled in firmware.
* **A current distro userspace: use Ubuntu 24.04.** WSL kernels are
  shipped by Microsoft and stay current, but the distro userspace is
  whatever you installed — a years-old Ubuntu 20.04 WSL install is
  common and causes exactly the failure below.
* **systemd enabled** (system runtime only). The system libvirt daemon
  is a systemd service; on older WSL installs systemd is off. Enable it
  in ``/etc/wsl.conf`` inside the distro::

      [boot]
      systemd=true

  then ``wsl --shutdown`` and reopen. Verify with
  ``ps -p 1 -o comm=`` printing ``systemd``.

Known footguns and their fixes
------------------------------

**"qemu-kvm : Depends: qemu-system-x86 (= 1:4.2-…) but it is not going
to be installed" / held broken packages.**
You are on an old distro userspace (that version string is Ubuntu 20.04,
which left standard support in 2025) with drifted package lists, and the
``qemu-kvm`` metapackage was retired in later releases anyway. Do not
fight apt on 20.04. Install Ubuntu 24.04 side by side — it does not
touch the existing distro or its files::

    # PowerShell
    wsl --install -d Ubuntu-24.04

Each WSL distro is an isolated filesystem; copy anything you need from
the old one via ``\\wsl$\Ubuntu\home\<user>\...`` (or from within the
new distro), and ``wsl --unregister Ubuntu`` the old one only when you
are sure. Do **not** run ``do-release-upgrade`` in place under WSL — the
upgrader's init/kernel assumptions do not hold there. On 24.04,
``aivm host install_deps`` installs the right packages (the qemu package
is ``qemu-system-x86``; there is no ``qemu-kvm`` metapackage).

**"virtiofsd binary '/var/lib/libvirt/aivm/virtiofsd-wrapper-….sh' is
not executable" when attaching a folder.**
Not WSL-specific, but commonly encountered on machines whose VM was
created by an older aivm: early versions wrote a generated virtiofsd
wrapper script into the VM definition, and that strategy was removed.
``virsh attach-device --config`` re-validates the whole persistent
definition, so the stale reference breaks *new* attaches. Fix without
recreating the VM::

    aivm vm update

which detects the legacy wrapper as drift and strips it from the VM XML.
(Current versions also say this in the attach error message.)

**VMs disappear after closing the laptop / ``wsl --shutdown``.**
WSL2 stops the utility VM (and everything in it, including libvirt and
your aivm guest) when Windows restarts or WSL shuts down. Nothing is
lost — the domain definition and disk persist — but the guest does not
autostart. Run ``aivm vm up`` (or just ``aivm code .`` / ``aivm ssh .``,
which reconcile) to boot it again.

**Keep projects on the Linux filesystem, not ``/mnt/c``.**
Windows drives are mounted through drvfs/9p, which is slow and has weak
inode/permission semantics. Folder attachments (virtiofs or bind-mount
based) exported from ``/mnt/c/...`` are not supported territory — expect
breakage and terrible performance. Keep repos under ``~`` inside the
distro; access them from Windows via ``\\wsl$`` if needed.

**Group membership does not take effect in open shells.**
After ``usermod -aG libvirt ...`` (done by ``aivm host sudoless setup``),
close all distro shells -- or ``wsl --shutdown`` -- and reopen.
``sg libvirt -c '...'`` works for a single command in the meantime.

Recommended setup on WSL2
-------------------------

Enable systemd, install dependencies, then create a VM::

    aivm host install_deps
    aivm host doctor
    aivm vm create

Diagnostics
-----------

``aivm host doctor`` detects WSL and checks the two hard prerequisites
(``/dev/kvm`` present, systemd as PID 1) with WSL-specific fix
instructions, including the ``.wslconfig`` hint when ``/dev/kvm`` is
missing under WSL.
