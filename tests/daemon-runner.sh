#!/bin/bash

source "$(dirname "$0")/jenkins-job-include.sh"; show_vars

export PYTHONPATH="$(pwd)"
CONFIG="$(pwd)/tests/automation/hubble.rc"
rm -f tests/automation/dumpster.sqlite || true
tests/automation/lrun.py -c "$CONFIG" -vvv 2>&1 | tee $OUTPUT_FILE
