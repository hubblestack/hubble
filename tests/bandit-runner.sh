#!/bin/bash

source "$(dirname "$0")/jenkins-job-include.sh"; show_vars

relevant-files > "$MANIFEST_FILE"
readarray -t FILES < "$MANIFEST_FILE"

vecho "running bandit: ${FILES[*]}"
( set +e; bandit -lif screen "${FILES[@]}"; echo $? > "$RESULT_FILE" ) | tee "$OUTPUT_FILE"
clean_colors_output_file
exit $(< "$RESULT_FILE")
