#!/bin/bash

_SOURCE_DIR="./"
_BINARY_LOG_LEVEL="INFO"

function pkg_create {
_INCLUDE_PATH=""
for i in `find $_SOURCE_DIR -type d`
do
   _INCLUDE_PATH=$_INCLUDE_PATH"    --path=$i"
done
  
#pyinstaller --onefile \
pyinstaller \
  --noconfirm \
  --log-level $_BINARY_LOG_LEVEL \
  --additional-hooks-dir=$_SOURCE_DIR \
  $_INCLUDE_PATH \
  telescope.py
}

function pkg_clean {
  rm -rf *spec *pyc build dist
}

$1
