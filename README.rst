The aivm Module
===============


.. warning::

   This project was written with GPT-5.3 Codex and is still being evaluated
   for correctness and safety. It is for experimental use only.


|Pypi| |PypiDownloads| |ReadTheDocs| |GithubActions| |Codecov|



+---------------+---------------------------------------+
| Read the Docs | http://aivm.readthedocs.io/en/latest/ |
+---------------+---------------------------------------+
| Pypi          | https://pypi.org/project/aivm         |
+---------------+---------------------------------------+

A small Python CLI to **create and manage a local libvirt/KVM Ubuntu 24.04 VM**
designed for running coding agents with a stronger boundary than containers.

Features:

* Explicit libvirt NAT network creation (named, dedicated subnet)
* Optional host firewall isolation via nftables (bridge-scoped)
* Ubuntu 24.04 cloud-image provisioning via cloud-init
* SSH helpers + VS Code Remote-SSH snippet
* Optional virtiofs host directory share (explicit break in default isolation model)
* Optional provisioning inside VM (docker + dev tools)
* Optional host settings sync into VM user profile (git/vscode shell config, etc.)
* Global VM/folder registry and per-directory metadata for attachment tracking

Install
-------

.. code-block:: bash

   uv pip install .

Quickstart
----------

Repo-local config flow:

.. code-block:: bash

   aivm config init --config .aivm.toml
   aivm config discover
   aivm config show
   aivm config edit
   aivm help plan --config .aivm.toml
   aivm help tree
   aivm host doctor
   aivm status --config .aivm.toml
   aivm status --config .aivm.toml --detail
   aivm apply --config .aivm.toml --interactive

No-local-init flow (recommended UX for new repos):

.. code-block:: bash

   aivm code .
   aivm status
   aivm status --sudo   # optional deeper privileged checks

``aivm code .`` auto-selects a VM from directory metadata/global registry
(prompts if ambiguous), auto-attaches the folder if needed, then opens VS Code.
``aivm status`` also resolves from directory metadata/global registry when there
is no local ``.aivm.toml`` (or use ``--vm``).
Global registry/config metadata is stored in a user config appdir
(``ub.Path.appdir(type='config')`` when available), with per-VM configs
under ``vms/<name>.config``.
By default ``status`` avoids sudo and reports limited checks; use
``status --sudo`` for privileged network/firewall/libvirt/image checks.
Privileged host actions prompt for confirmation before sudo blocks; use ``--yes``
to auto-approve in scripted/non-interactive flows.
``aivm code .`` first performs non-sudo probes and only asks for sudo when it
can confirm privileged actions are needed.

Then connect with VS Code Remote-SSH using:

.. code-block:: bash

   aivm vm ssh_config --config .aivm.toml

Or do it in one step (share current project directory and launch VS Code in the VM):

.. code-block:: bash

   # top-level shortcut (works in a new repo with no local init)
   aivm code . --sync_settings
   # equivalent vm-group form
   aivm vm code --config .aivm.toml --host_src . --sync_settings
   # shorthand positional host folder
   aivm vm code . --sync_settings

Open an interactive SSH shell in the mapped guest directory:

.. code-block:: bash

   aivm vm ssh .

List managed resources:

.. code-block:: bash

   aivm list
   aivm vm list
   aivm list --section vms
   aivm list --section networks
   aivm list --section folders

Attach a folder to a managed VM (shared mode):

.. code-block:: bash

   aivm attach .
   # explicit vm-group form
   aivm vm attach --vm aivm-2404 --host_src .

By default, attached folders mount to the same absolute path inside the VM as
on the host. Use ``--guest_dst`` to override.
When possible, ``aivm code .`` live-attaches new shares to existing VMs
(``--live --config`` when running, ``--config`` when stopped) instead of
requiring recreation.

Make VM Feel Like Your Host
---------------------------

Sync selected user settings/files into the VM:

.. code-block:: bash

   aivm vm sync_settings --config .aivm.toml

Override what to sync ad hoc:

.. code-block:: bash

   aivm vm sync-settings --config .aivm.toml \
     --paths "~/.gitconfig,~/.config/Code/User/settings.json,~/.tmux.conf"

You can set defaults in config:

.. code-block:: toml

   [sync]
   enabled = true
   overwrite = true
   paths = [
     "~/.gitconfig",
     "~/.gitignore",
     "~/.config/Code/User/settings.json",
     "~/.config/Code/User/keybindings.json",
     "~/.tmux.conf",
     "~/.bashrc",
   ]

When ``[sync].enabled=true``, ``aivm vm code ...`` will sync those paths
before launching VS Code.

Command Groups
--------------

.. code-block:: bash

   aivm config --help
   aivm host --help
   aivm help --help
   aivm host net --help
   aivm host fw --help
   aivm vm --help

Notes
-----

* This tool assumes **Linux + libvirt**. It focuses on Debian/Ubuntu hosts for dependency installation.
* NAT alone does not prevent VM -> LAN. Enable firewall isolation if you want "internet-only" access.
* virtiofs sharing is optional; it's powerful, but it intentionally exposes that host directory to the VM.
* ``aivm vm code`` requires VS Code's ``code`` CLI and the Remote - SSH extension.


.. |Pypi| image:: https://img.shields.io/pypi/v/aivm.svg
    :target: https://pypi.python.org/pypi/aivm

.. |PypiDownloads| image:: https://img.shields.io/pypi/dm/aivm.svg
    :target: https://pypistats.org/packages/aivm

.. |ReadTheDocs| image:: https://readthedocs.org/projects/aivm/badge/?version=latest
    :target: http://aivm.readthedocs.io/en/latest/

.. |GithubActions| image:: https://github.com/Erotemic/aivm/actions/workflows/tests.yml/badge.svg
    :target: https://github.com/Erotemic/aivm/actions?query=branch%3Amain

.. |Codecov| image:: https://codecov.io/github/Erotemic/aivm/badge.svg?branch=main&service=github
    :target: https://codecov.io/github/Erotemic/aivm?branch=main
