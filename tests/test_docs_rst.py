"""Structural guard for the reStructuredText docs.

CI does not run Sphinx, and ``./run_docs.sh`` turns every warning into an
error, so a short section underline breaks the documented docs build for
everyone without any test noticing. This is a dependency-free check of the
one rule that has regressed: an adornment must be at least as long as the
title it decorates.
"""

from __future__ import annotations

from pathlib import Path

import pytest

DOCS = Path(__file__).resolve().parent.parent / 'docs' / 'source'
ADORNMENT = set('=-~^"\'`#*+:._')


def _adornment(line: str) -> bool:
    text = line.rstrip('\n')
    return (len(text) >= 3 and text[0] in ADORNMENT
            and text == text[0] * len(text))


def short_underlines(text: str) -> list[tuple[int, str]]:
    """Return ``(underline_line_number, title)`` for each short section title.

    Only unindented titles preceded by a blank line (or a matching overline)
    are considered, which excludes literal blocks, tables and transitions.
    """
    lines = text.splitlines()
    found = []
    for index in range(1, len(lines)):
        underline, title = lines[index], lines[index - 1]
        if not _adornment(underline):
            continue
        if not title.strip() or title[0].isspace() or _adornment(title):
            continue
        before = lines[index - 2] if index >= 2 else ''
        if before.strip() and not _adornment(before):
            continue
        if len(underline.rstrip()) < len(title.rstrip()):
            found.append((index + 1, title.rstrip()))
    return found


def test_detector_flags_short_and_accepts_exact_underlines() -> None:
    sample = 'Intro\n\nGood title\n----------\n\nBad title\n--------\n'
    assert short_underlines(sample) == [(7, 'Bad title')]
    table = 'para\n\n=====  =====\na      b\n=====  =====\n'
    assert short_underlines(table) == []


@pytest.mark.parametrize('path', sorted(DOCS.rglob('*.rst')),
                         ids=lambda p: str(p.relative_to(DOCS)))
def test_section_underlines_cover_their_titles(path: Path) -> None:
    assert short_underlines(path.read_text(encoding='utf-8')) == []
