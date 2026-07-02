#!/usr/bin/env bash
# Lint gate: ruff enforces the configured rule set (pyproject [tool.ruff]);
# the flake8 pass mirrors the CI job's syntax-severity floor.
set -e
python -m ruff check aivm tests
flake8 --count --select=E9,F63,F7,F82 --show-source --statistics aivm
flake8 --count --select=E9,F63,F7,F82 --show-source --statistics ./tests
