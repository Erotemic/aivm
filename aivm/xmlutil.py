"""Shared parsing for libvirt domain and network XML.

Every consumer of ``virsh dumpxml`` / ``net-dumpxml`` output parsed it with
its own ``try: ET.fromstring(...) except ...`` guard.  :func:`parse_domain_xml`
is that guard, extracted once so each caller keeps only its own on-failure
default:

    root = parse_domain_xml(text)
    if root is None:
        return <caller default>

This module imports nothing from :mod:`aivm` so any layer can use it.
"""

from __future__ import annotations

import xml.etree.ElementTree as ET


def parse_domain_xml(text: str | None) -> ET.Element | None:
    """Parse libvirt XML, returning ``None`` for empty or malformed input.

    Fetching the XML (with its own privilege and caching policy) stays with
    the caller; this only turns a text blob into an element tree, treating an
    empty string or a parse error as "no usable XML" rather than raising.
    """
    if not text or not text.strip():
        return None
    try:
        return ET.fromstring(text)
    except ET.ParseError:
        return None
