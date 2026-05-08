Alternatives
============

``aivm`` is not the only way to put a boundary around AI-agent work. It is
currently oriented toward a persistent local libvirt/KVM Ubuntu VM with
VS Code/SSH workflows and explicit folder attachments. Other tools make
different tradeoffs.

Matchlock
---------

`Matchlock <https://github.com/jingkaihe/matchlock>`_ runs AI-agent workloads
in ephemeral microVMs. Its README describes network allowlisting, secret
injection through a host-side proxy, and disposable VM-level isolation.

Choose this direction when ephemeral execution, network policy, and keeping
real secrets out of the guest are more important than re-entering one long-lived
development VM.

JAI
---

`JAI <https://github.com/stanford-scs/jai>`_ is a lightweight Linux jail for AI
CLIs. Its default model gives the command access to the current working
directory, copy-on-write access to the rest of home, private temp directories,
and mostly read-only access elsewhere, with stricter modes available.

Choose this direction when a process-level Linux jail is enough and you want a
lighter setup than a full VM.

aivm
----

``aivm`` is a better fit when you want:

* a persistent Ubuntu VM managed by libvirt/KVM
* explicit folder attachments that can be reopened with ``aivm code .`` or
  ``aivm ssh .``
* host firewall integration and VM lifecycle/config reconciliation
* a workflow that feels close to a local development machine

That convenience comes with explicit tradeoffs: shared folders are a deliberate
trust extension, and long-lived virtiofs-backed attachments currently have a
known file-descriptor growth/retention failure mode that is mitigated but not
solved.
