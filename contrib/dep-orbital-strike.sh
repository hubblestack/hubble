#!/bin/bash

THIS_DIR="$(git rev-parse --show-toplevel)"

UNINSTALL=(
    salt-ssh
    jinja2
)

UNDEPEND=(
    "${UNINSTALL[@]}"
    six
)


( set -x
  pip uninstall -y hubblestack "${UNINSTALL[@]}"
)

IFS='|'
KILL="${UNDEPEND[*]}"
unset IFS

( set -x
  find "$THIS_DIR" -type f -name \*req\*.txt \
      | grep -v /abandoned/ \
      | xargs -r sed -i -re "/$KILL/d"
  sed -i -re "/'$KILL.+',/d" setup.py
)
