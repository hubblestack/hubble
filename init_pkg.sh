#!/bin/bash

cd scripts/
sudo bash installessentials.sh
sudo bash libgit2-build.sh
bash osquery-build.sh
sudo bash pip-install.sh
sudo bash pyinstaller-hubble.sh pkg_clean
sudo bash pyinstaller-hubble.sh pkg_init
sudo bash pyinstaller-hubble.sh pkg_create
