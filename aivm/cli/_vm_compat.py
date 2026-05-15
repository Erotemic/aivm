"""Compatibility helpers for split VM CLI modules."""

from __future__ import annotations

from typing import Any


class LegacyVmProxy:
    """Resolve a dependency from :mod:`aivm.cli.vm` at use time.

    The first CLI split intentionally keeps old private monkeypatch targets
    working.  Several tests patch helpers such as ``aivm.cli.vm._load_cfg`` or
    ``aivm.cli.vm._resolve_attachment``.  Split command modules use this proxy
    while those call sites are migrated to narrower operation-layer seams.
    """

    def __init__(self, name: str) -> None:
        self.name = name

    def _obj(self) -> Any:
        from . import vm as legacy_vm

        return getattr(legacy_vm, self.name)

    def __call__(self, *args: Any, **kwargs: Any) -> Any:
        return self._obj()(*args, **kwargs)

    def __getattr__(self, attr: str) -> Any:
        return getattr(self._obj(), attr)

    def __repr__(self) -> str:
        return f'<LegacyVmProxy {self.name}>'


def legacy(name: str) -> LegacyVmProxy:
    """Return a proxy for a legacy ``aivm.cli.vm`` attribute."""

    return LegacyVmProxy(name)
