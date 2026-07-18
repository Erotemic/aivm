"""Smoke test that the top-level ``aivm`` package imports cleanly."""


def test_import() -> None:
    import aivm

    print(f'aivm={aivm}')
