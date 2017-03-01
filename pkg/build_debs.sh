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

cd ..

bash init_pkg.sh -y
cp hubble.tar.gz ~/hubble.tar.gz
rm -rf ~/hubblestack-2.1.3
rm -rf ~/hubblestack-2.1.3.tar.gz
mkdir ~/hubblestack-2.1.3
tar -xzvf ~/hubble.tar.gz -C ~/hubblestack-2.1.3
mkdir -p ~/hubblestack-2.1.3/etc/init.d
cp pkg/hubble ~/hubblestack-2.1.3/etc/init.d
mkdir -p ~/hubblestack-2.1.3/usr/lib/systemd/system
cp pkg/hubble.service ~/hubblestack-2.1.3/usr/lib/systemd/system
cp -f conf/hubble ~/hubblestack-2.1.3/etc/hubble/hubble
cd ~/hubblestack-2.1.3

sudo apt-get install -y ruby ruby-dev rubygems gcc make
sudo gem install --no-ri --no-rdoc fpm
mkdir -p usr/bin
ln -s /opt/hubble/hubble usr/bin/hubble
ln -s /opt/osquery/osqueryd usr/bin/osqueryd
ln -s /opt/osquery/osqueryi usr/bin/osqueryi
fpm -s dir -t deb \
    -n hubblestack \
    -v 2.1.3-1 \
    -d 'git' \
    --config-files /etc/hubble/hubble --config-files /etc/osquery/osquery.conf \
    --deb-no-default-config-files \
    etc/hubble etc/osquery etc/init.d opt usr/bin
cp hubblestack_2.1.3-1_amd64.deb ~/
