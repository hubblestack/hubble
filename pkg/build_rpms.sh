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
mkdir build/hubblestack-2.2.2
tar -xzvf build/hubble.tar.gz -C build/hubblestack-2.2.2
mkdir -p build/hubblestack-2.2.2/etc/init.d
cp ./hubble build/hubblestack-2.2.2/etc/init.d
mkdir -p build/hubblestack-2.2.2/usr/lib/systemd/system
cp ./hubble.service build/hubblestack-2.2.2/usr/lib/systemd/system
cp -f ../conf/hubble build/hubblestack-2.2.2/etc/hubble/hubble
cd build
tar -czvf hubblestack-2.2.2.tar.gz hubblestack-2.2.2/
mkdir -p rpmbuild/{RPMS,SRPMS,BUILD,SOURCES,SPECS,tmp}

cp hubblestack-2.2.2.tar.gz rpmbuild/SOURCES/
cd rpmbuild

cp ../../specs/* SPECS/

rpmbuild --define "_topdir $(pwd)" --define "_tmppath %{_topdir}/tmp" -ba SPECS/hubblestack-el6.spec
cp RPMS/x86_64/hubblestack-2.2.2-1.x86_64.rpm ../../dist/hubblestack-2.2.2-1.el6.x86_64.rpm
rpmbuild --define "_topdir $(pwd)" --define "_tmppath %{_topdir}/tmp" -ba SPECS/hubblestack-el7.spec
cp RPMS/x86_64/hubblestack-2.2.2-1.x86_64.rpm ../../dist/hubblestack-2.2.2-1.el7.x86_64.rpm
