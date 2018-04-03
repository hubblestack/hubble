#!/bin/bash

ec=0
function runme() {
    PS4='+++'
    (set -x; "$@")
    ec=$(( ec + $? ))
}

if [ -n "$PYTEST_FILES"  ]
then runme pytest "$PYTEST_FILES"
fi

if [ "X$PYLINT_ENABLE" = X1 ]
then runme pylint --confidence HIGH --reports=no hubblestack
fi

exit $ec
