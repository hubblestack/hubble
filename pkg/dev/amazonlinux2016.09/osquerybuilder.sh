#!/bin/bash

build_osquery=$1
build_osquery_locally=$2

if [ $build_osquery != true ]
then
  tar -C /opt/ -zxvf osquery_*_tob_amazonlinux2016.09.tar
  echo $build_osquery
else
  echo $build_osquery_locally
  if [ $build_osquery_locally == true ]
  then
    echo "Building osquery from local folder"
  else
    rm -rf /osquery
    OSQUERY_SRC_VERSION=3.3.2
    OSQUERY_GIT_URL=https://github.com/facebook/osquery.git
    cd /
    git clone "$OSQUERY_GIT_URL"
    cd osquery/
    git checkout "$OSQUERY_SRC_VERSION"
    echo "Fetching osquery from git"
    echo $OSQUERY_SRC_VERSION
  fi
  mkdir /home/"$OSQUERY_BUILD_USER"/osquery
  cp -r /osquery/ /home/"$OSQUERY_BUILD_USER"/
  mkdir -p /usr/local/osquery/
  chown "$OSQUERY_BUILD_USER":"$OSQUERY_BUILD_USER" -R /usr/local/osquery/
  chown "$OSQUERY_BUILD_USER":"$OSQUERY_BUILD_USER" -R /home/"$OSQUERY_BUILD_USER"/osquery
  
  export SKIP_TESTS=1
  cd /home/"$OSQUERY_BUILD_USER"/osquery 
  sudo -u "$OSQUERY_BUILD_USER" make sysprep
  sudo -u "$OSQUERY_BUILD_USER" sed -i '/augeas_lenses,/,/\"Directory\ that\ contains\ augeas\ lenses\ files\"\\)\;/ s/\/usr\/share\/osquery\/lenses/\/opt\/osquery\/lenses/' osquery/tables/system/posix/augeas.cpp
  sudo -u "$OSQUERY_BUILD_USER" make deps
  sudo -u "$OSQUERY_BUILD_USER" make
  sudo -u "$OSQUERY_BUILD_USER" make strip
  cp -pr /home/"$OSQUERY_BUILD_USER"/osquery/build/linux/osquery/osqueryi /opt/osquery/osqueryi
  cp -pr /home/"$OSQUERY_BUILD_USER"/osquery/build/linux/osquery/osqueryd /opt/osquery/hubble_osqueryd
  mkdir -p /opt/osquery/lenses
  cp -r /usr/local/osquery/share/augeas/lenses/dist/* /opt/osquery/lenses
fi
chown -R root. /opt/osquery
chmod -R 500 /opt/osquery/*
chmod -R 400 /opt/osquery/lenses/*
ls -lahR /opt/osquery/ && /opt/osquery/osqueryi --version
