#!/bin/bash

source "$(dirname "$0")/jenkins-job-include.sh"

set -x

find hubblestack -name "*.py" \
    -exec git diff --name-only "origin/$CHANGE_TARGET" "origin/$BRANCH_NAME" {} + \
    | tee pylint-manifest.txt \
    | (xargs -r pylint -f colorized; echo $? > pylint-result.txt) \
    | tee pylint-output.txt

exit $(< pylint-result.txt)
