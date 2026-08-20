"""Retired public ssh-agent credential modal.

The user-facing credential surface is :mod:`aivm.cli.vm_creds`. Backend
implementation remains independent under :mod:`aivm.credentials.agent`; this
module intentionally registers no commands.
"""

from __future__ import annotations
