"""Small parsing and formatting helpers for VM update logic."""

from __future__ import annotations

import json
import re
import xml.etree.ElementTree as ET


def _bytes_to_gib(size_bytes: int) -> float:
    return float(size_bytes) / float(1024**3)


def _parse_qemu_img_virtual_size(info_json: str) -> int | None:
    try:
        raw = json.loads(info_json or '{}')
    except Exception:
        return None
    size = raw.get('virtual-size')
    if isinstance(size, int) and size > 0:
        return size
    return None


def _parse_vm_disk_path_from_dumpxml(dumpxml_text: str) -> str | None:
    try:
        root = ET.fromstring(dumpxml_text)
    except ET.ParseError:
        return None
    devices = root.find('devices')
    if devices is None:
        return None
    for disk in devices.findall('disk'):
        if disk.get('device') != 'disk':
            continue
        source = disk.find('source')
        if source is None:
            continue
        source_file = (source.get('file') or '').strip()
        if source_file:
            return source_file
    return None


def _parse_vm_network_from_dumpxml(dumpxml_text: str) -> str | None:
    try:
        root = ET.fromstring(dumpxml_text)
    except ET.ParseError:
        return None
    devices = root.find('devices')
    if devices is None:
        return None
    for iface in devices.findall('interface'):
        if (iface.get('type') or '').strip() != 'network':
            continue
        source = iface.find('source')
        if source is None:
            continue
        network_name = (source.get('network') or '').strip()
        if network_name:
            return network_name
    return None


def _parse_domblkinfo_capacity(domblkinfo_text: str) -> int | None:
    for line in (domblkinfo_text or '').splitlines():
        if ':' not in line:
            continue
        key, val = [x.strip() for x in line.split(':', 1)]
        if key.lower() == 'capacity':
            m = re.search(r'(\d+)', val)
            if m:
                return int(m.group(1))
    return None
