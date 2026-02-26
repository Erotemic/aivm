#!/usr/bin/env bash
flake8 --count --select=E9,F63,F7,F82 --show-source --statistics agentvm
flake8 --count --select=E9,F63,F7,F82 --show-source --statistics ./tests