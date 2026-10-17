#!/bin/bash
ty check aivm aivm_secrets tests && mypy aivm aivm_secrets tests --disallow-untyped-defs --disallow-incomplete-defs
