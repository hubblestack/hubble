#!/usr/bin/env bash

hubble="$(which hubble)"
profile="${1:-/tmp/profile}"

# python -m cProfile -o "$profile" "$hubble"
python -c "import pstats; p = pstats.Stats('$profile'); p.strip_dirs().sort_stats(-1).print_stats()"
