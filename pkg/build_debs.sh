#!/bin/bash

set -x # echo on

_user=`id -u`

# Check if the current user is root
if [ "$_user" == "0" ]
then
  echo "This script should not be run as root ..."
  echo "Please run this script as regular user with sudo privileges ..."
  echo "Exiting ..."
  exit
fi

rm -rf build
rm -rf dist

mkdir -p build
mkdir -p dist

bash ./init_pkg.sh -y
cp ../hubble.tar.gz dist/hubble.tar.gz
mv ../hubble.tar.gz build/hubble.tar.gz
mkdir build/hubblestack-2.1.7
tar -xzvf build/hubble.tar.gz -C build/hubblestack-2.1.7
mkdir -p build/hubblestack-2.1.7/etc/init.d
cp ./hubble build/hubblestack-2.1.7/etc/init.d
mkdir -p build/hubblestack-2.1.7/usr/lib/systemd/system
cp ./hubble.service build/hubblestack-2.1.7/usr/lib/systemd/system
cp -f ../conf/hubble build/hubblestack-2.1.7/etc/hubble/hubble
cd build/hubblestack-2.1.7

sudo apt-get install -y ruby ruby-dev rubygems gcc make
sudo gem install --no-ri --no-rdoc fpm
mkdir -p usr/bin
ln -s /opt/hubble/hubble usr/bin/hubble
ln -s /opt/osquery/osqueryd usr/bin/osqueryd
ln -s /opt/osquery/osqueryi usr/bin/osqueryi
fpm -s dir -t deb \
    -n hubblestack \
    -v 2.1.7-1 \
    -d 'git' \
    --config-files /etc/hubble/hubble --config-files /etc/osquery/osquery.conf \
    --deb-no-default-config-files \
    etc/hubble etc/osquery etc/init.d opt usr/bin
cp hubblestack_2.1.7-1_amd64.deb ../../dist/
