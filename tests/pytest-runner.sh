#!/bin/bash

source "$(dirname "$0")/jenkins-job-include.sh"; show_vars

PYTEST=(
    python -m pytest --color yes
    --log-cli-level INFO
    --log-cli-format "%(asctime)s %(name)17s %(levelname)5s %(message)s"
    --log-cli-date-format "%H:%M:%S"
    tests/unittests
)

vecho "${PYTEST[*]}"
( set +e; "${PYTEST[@]}"; echo $? > "$RESULT_FILE" ) | tee "$OUTPUT_FILE"
clean_colors_output_file
exit $(< "$RESULT_FILE")
