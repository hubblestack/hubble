#!/bin/bash

source "$(dirname "$0")/jenkins-job-include.sh"

PYTEST=(
    python -m pytest
    --log-cli-level INFO
    --log-cli-format "%(asctime)s %(name)17s %(levelname)5s %(message)s"
    --log-cli-date-format "%H:%M:%S"
)

# BLACKLIST=""
#     | grep -vE "$BLACKLIST" \

set -x

ls -1 tests/unittests/*.py \
    | tee pytest-manifest.txt \
    | (xargs -r "${PYTEST[@]}"; echo $? > pytest-result.txt) \
    | tee pytest-output.txt

exit $(< pytest-result.txt)
