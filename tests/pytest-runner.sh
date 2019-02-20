#!/bin/bash

source "$(dirname "$0")/jenkins-job-include.sh"; show_vars

PYTEST=(
    python -m pytest --color yes
    --log-cli-level INFO
    --log-cli-format "%(asctime)s %(name)17s %(levelname)5s %(message)s"
    --log-cli-date-format "%H:%M:%S"
    tests/unittests
)

vecho "${PYTEST[*]}"
( "${PYTEST[@]}"; echo $? > "${LOGPREFIX}-result.txt" ) | tee "${LOGPREFIX}-output.txt"
exit $(< "${LOGPREFIX}-result.txt")
