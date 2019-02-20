#!/bin/bash

source "$(dirname "$0")/jenkins-job-include.sh"; show_vars

relevant-files > "${LOGPREFIX}-manifest.txt"
readarray -t FILES < "${LOGPREFIX}-manifest.txt"

vecho "running bandit: ${FILES[*]}"
( bandit -lif screen "${FILES[@]}"
  echo $? > "${LOGPREFIX}-result.txt" ) | tee "${LOGPREFIX}-output.txt"
exit $(< "${LOGPREFIX}-result.txt")
