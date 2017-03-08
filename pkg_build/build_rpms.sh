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
mkdir build/hubblestack-2.1.4
tar -xzvf build/hubble.tar.gz -C build/hubblestack-2.1.4
mkdir -p build/hubblestack-2.1.4/etc/init.d
cp ../pkg/hubble build/hubblestack-2.1.4/etc/init.d
mkdir -p build/hubblestack-2.1.4/usr/lib/systemd/system
cp ../pkg/hubble.service build/hubblestack-2.1.4/usr/lib/systemd/system
cp -f ../conf/hubble build/hubblestack-2.1.4/etc/hubble/hubble
cd build
tar -czvf hubblestack-2.1.4.tar.gz hubblestack-2.1.4/
mkdir -p rpmbuild/{RPMS,SRPMS,BUILD,SOURCES,SPECS,tmp}

cp hubblestack-2.1.4.tar.gz rpmbuild/SOURCES/
cd rpmbuild

cp ../../specs/* SPECS/

rpmbuild --define "_topdir $(pwd)" --define "_tmppath %{_topdir}/tmp" -ba SPECS/hubblestack-el6.spec
mkdir -p ../../dist/el6
cp RPMS/x86_64/* ../../dist/el6/
rpmbuild --define "_topdir $(pwd)" --define "_tmppath %{_topdir}/tmp" -ba SPECS/hubblestack-el7.spec
mkdir -p ../../dist/el7
cp RPMS/x86_64/* ../../dist/el7/
