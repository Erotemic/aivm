#!/usr/bin/env bash
# Docs gate: build the Sphinx site with warnings as errors, so a dangling
# :doc: target or a toctree entry pointing at a renamed page fails here
# instead of silently shipping a broken link (190ed83 renamed
# runtimes.rst -> privilege-modes.rst with nothing to catch the difference).
#
# --keep-going reports every warning in one pass rather than stopping at the
# first. Unreachable intersphinx inventories are exempted in docs/source/conf.py:
# whether objects.inv can be fetched is a property of the network, not of these
# docs, so an offline build must not fail here.
set -e
BUILD_DIR="${1:-docs/build/html}"
sphinx-build -W --keep-going -b html docs/source "$BUILD_DIR"
