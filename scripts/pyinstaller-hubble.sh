#!/bin/bash

pushd ../
_SOURCE_DIR="./"
_BINARY_LOG_LEVEL="INFO"

function pkg_init {
_INCLUDE_PATH=""

pyinstaller --onefile \
  --noconfirm \
  --log-level $_BINARY_LOG_LEVEL \
  --additional-hooks-dir=$_SOURCE_DIR \
  $_INCLUDE_PATH \
  hubble.py
}

function pkg_clean {
  rm -rf *spec *pyc build dist
}

function pkg_create {
cp -rf conf/hubble /etc/hubble/
cp -rf conf/hubble-profile.sh /etc/profile.d/
mv dist/hubble /opt/hubble/
cp -rf conf/hubble /etc/hubble/
tar -cPvzf /etc/hubble /etc/osquery /opt/hubble /opt/osquery /var/log/osquery //etc/profile.d/hubble-profile.sh
}

$1
popd
