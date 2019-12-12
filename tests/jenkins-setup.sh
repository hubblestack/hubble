#!/bin/bash

source "$(dirname "$0")/jenkins-job-include.sh"

# if virtualenv gets jacked up, and the workspace is persisted,
# this can save the workflow:
rm -rf "$VLIB" "$VENV" || /bin/true

vecho "install local copy of virtualenv"
pip install --cache-dir pip.cache -t "$VLIB" virtualenv
PYTHONPATH="$VLIB" "$VLIB/bin/virtualenv" "$VENV"
source "$VENV/bin/activate"

vecho "install/upgrade venv/bin/pip"
pip install --cache-dir pip.cache -U pip

vecho "install/upgrade pylint bandit pytest"
pip install --cache-dir pip.cache -U pylint bandit pytest

vecho "install/upgrade test-requirements.txt"
pip install --cache-dir pip.cache -U -r test-requirements.txt

show_vars

exit 0
