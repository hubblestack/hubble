#!/bin/bash

cd scripts/
bash pyinstaller-installessentials.sh
bash libgit2-build.sh
bash osquery-build.sh
bash pyinstaller-hubble.sh
