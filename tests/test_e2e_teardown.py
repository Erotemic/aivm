"""A successful test must not hide unsuccessful disposable-resource cleanup."""

from pathlib import Path
from subprocess import CompletedProcess

import pytest

from tests.e2e import _helpers


@pytest.mark.parametrize('codes', [(0, 0), (1, 0), (0, 1)])
def test_teardown_reports_cleanup_failure(monkeypatch, tmp_path: Path, codes):
    calls = []

    def run(argv, **kwargs):
        code = codes[len(calls)]
        calls.append(argv)
        return CompletedProcess(argv, code, stdout='cleanup diagnostic')

    monkeypatch.setattr(_helpers, '_run_cli', run)
    teardown = _helpers.E2ETeardown(tmp_path / 'config.toml', env={}, timeout_s=10)
    if any(codes):
        with pytest.raises(AssertionError, match='E2E cleanup failed'):
            with teardown:
                pass
    else:
        with teardown:
            pass
    assert calls[0][:2] == ['vm', 'delete']
    assert calls[1][:3] == ['host', 'net', 'destroy']


def test_cleanup_exit_codes_do_not_mask_original_failure(monkeypatch, tmp_path):
    calls = []

    def run(argv, **kwargs):
        calls.append(argv)
        return CompletedProcess(argv, 1, stdout='cleanup failed too')

    monkeypatch.setattr(_helpers, '_run_cli', run)
    with pytest.raises(RuntimeError, match='original failure'):
        with _helpers.E2ETeardown(tmp_path / 'config.toml', env={}, timeout_s=10):
            raise RuntimeError('original failure')
    assert len(calls) == 2
