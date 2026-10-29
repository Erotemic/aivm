# GPT-6 CI packaging journal

## 2026-10-29 11:54:27 -0400

Traced a failing GitHub Actions installation to three stale commands in the
AIVM test workflow that attempted to pip-install `./aivm_secrets`, a source
package that has been extracted to its own repository. This is a CI
configuration dependency, not a `pyproject.toml` runtime dependency; the
project's default install and tests extra already exclude the unpublished
package, and conftest already excludes its integration tests when absent.

Removed the three unconditional installs and the associated misleading
comment. Updated local lint/typecheck scripts so they do not require a
nonexistent sibling package path. Added a focused test to prevent the
workflow and developer scripts from accidentally restoring this dependency.
This intentionally does not publish, mock, or silently install the independent
broker, and does not claim that its separate integration test suite is being
run by AIVM CI. Risk is that broker-specific regressions now require their
own CI in the extracted repository and an explicit opt-in cross-repository
integration job in the future. The original test layout deliberately makes
this separation possible today.
