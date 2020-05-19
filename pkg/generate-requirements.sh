#!/bin/bash

setup_py_dir="$(dirname "$0")/../"

python "$setup_py_dir/setup.py" egg_info &>/dev/null

cat "$setup_py_dir/hubblestack.egg-info/requires.txt" \
    "$setup_py_dir/optional-requirements.txt" \
    "$setup_py_dir/package-requirements.txt" \
    "$setup_py_dir/test-requirements.txt" \
    \
    | tr A-Z a-z | grep -v ^# | grep . | sort -u \
    | perl -ne 'chomp; $P{$1} = $_ if m/^([^<>=]+)/ and length($_) > length($P{$1});
      END { print "$_\n" for sort values %P }'
