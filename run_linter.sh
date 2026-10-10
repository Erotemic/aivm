#!/usr/bin/env bash
# Lint gate: architecture drift/rules, ruff configuration, and the CI syntax floor.
set -e
python dev/devcheck/architecture_docs.py check
python -m ruff check aivm aivm_secrets tests dev/devcheck/architecture_docs.py
flake8 --count --select=E9,F63,F7,F82 --show-source --statistics aivm
flake8 --count --select=E9,F63,F7,F82 --show-source --statistics aivm_secrets
flake8 --count --select=E9,F63,F7,F82 --show-source --statistics ./tests
flake8 --count --select=E9,F63,F7,F82 --show-source --statistics ./dev/devcheck/architecture_docs.py
