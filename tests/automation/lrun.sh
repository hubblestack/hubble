#!/bin/bash

if ! cd /hubble || [ ! -d "/hubble/hubblestack" -o ! -d "/hubble/tests" ]; then
    echo "/hubble seems not to be mounted"
    exit 1
fi

set -e

eval "$(pyenv init -)"
pyenv local 2.7.14
pyenv shell 2.7.14

pip-compile setup.py > tests/automation/requirements.txt
pip --cache-dir /hubble/tests/automation/pip.cache install -r tests/automation/requirements.txt

export PYTHONPATH="/hubble"
CONFIG="/hubble/tests/automation/hubble.rc"

rm -f tests/automation/dumpster.sqlite || true
"$(dirname "$0")/$(basename "$0" .sh).py" -c "$CONFIG" -vvv 2>&1 | tee tests/automation/verbose.log
