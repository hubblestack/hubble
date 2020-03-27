#!/bin/bash

PROFILE="$1"; shift
PRIVATE_KEY="${1:-/etc/certs/private.key}"; shift
OK=0

HUBBLE="${HUBBLE:-hubble}"

if [ -n "$PROFILE" -a -d "$PROFILE/hubblestack_pulsar" -a -d "$PROFILE/hubblestack_nova_profiles" ]
then cd "$PROFILE" || exit 1; OK=1
else read -ep "$PROFILE=\"$PROFILE\" doesn't look like profile repo, sign anyway? " YN
    if [[ "$YN" =~ [Yy] ]]
    then cd "$PROFILE" || exit 1; OK=1
    fi
fi

if [ "X$OK" = X1 ]
then readarray -t FILEZ < <( find ./ -name .git -prune -o \( -type f -print \) \
       | grep -vE '^(MANIFEST|SIGNATURE)$' )
    ( set -x -e;
      cd "$PROFILE"
      "$HUBBLE" -vvv signing.msign "${FILEZ[@]}" private_key="$PRIVATE_KEY"
    )
else "usage: $(basename "$0") profile-dir"
fi
