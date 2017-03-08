#!/bin/bash

_check_auto_deletion=$2
pushd ../../
_SOURCE_DIR="./"
_BINARY_LOG_LEVEL="INFO"

function pkg_init {
_INCLUDE_PATH=""

pyinstaller --onedir \
  --noconfirm \
  --log-level $_BINARY_LOG_LEVEL \
  --additional-hooks-dir=$_SOURCE_DIR \
  $_INCLUDE_PATH \
  hubble.py
}

function pkg_clean {
  declare -a check_folders=('build' 'dist' '/opt/hubble' '/opt/osquery')

  for i in "${check_folders[@]}"
  do
    if [[ -f $i ]];
    then

      if [[ "$_check_auto_deletion" == "-y" ]];
      then
        _input="y"
      else
        read -r -p "The file $i will be deleted, do you agree : [y/n]" _input
      fi

      if [[ "$_input" == "y" ]];
      then
        echo "removing $i ..."
        rm -rf $i
      else
        echo "skipping deletion of $i"
      fi

    elif [[ -d $i ]];
    then

      if [[ "$_check_auto_deletion" == "-y" ]];
      then
        _input="y"
      else
        read -r -p "The folder $i will be deleted, do you agree : [y/n]" _input
      fi

      if [[ "$_input" == "y" ]];
      then
        echo "removing $i/* ..."
        rm -rf $i/*
      else
        echo "skipping deletion of $i"
      fi

    else 
      rm -f $i
    fi
  done

}

function pkg_create {
cp -rf conf/hubble /etc/hubble/
cp -rf conf/hubble-profile.sh /etc/profile.d/
cp -pr dist/hubble /opt/hubble/hubble-libs
ln -s /opt/hubble/hubble-libs/hubble /opt/hubble/hubble
cp -rf conf/hubble /etc/hubble/
tar -cPvzf hubble.tar.gz /etc/hubble /etc/osquery /opt/hubble /opt/osquery /var/log/osquery /etc/profile.d/hubble-profile.sh
}

$1
popd
