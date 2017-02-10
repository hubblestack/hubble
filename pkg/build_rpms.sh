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

bash init_pkg.sh
mv hubble.tar.gz ~/hubble.tar.gz
mkdir ~/hubblestack
tar -xzvf ~/hubble.tar.gz -C ~/hubblestack
mkdir -p ~/hubblestack/etc/init.d
cp pkg/hubble ~/hubblestack/etc/init.d
mkdir -p ~/hubblestack/usr/lib/systemd/system
cp pkg/hubble.service ~/hubblestack/usr/lib/systemd/system
tar -czvf ~/hubbblestack.tar.gz ~/hubblestack/
mkdir -p ~/rpmbuild/{RPMS,SRPMS,BUILD,SOURCES,SPECS,tmp}

cat <<EOF >~/.rpmmacros
%_topdir   %(echo $HOME)/rpmbuild
%_tmppath  %{_topdir}/tmp
EOF

mv ~/hubblestack.tar.gz ~/rpmbuild/SOURCES/
cd ~/rpmbuild

cp ~/hubble/pkg/specs/* SPECS/

rpmbuild -ba SPECS/hubblestack-el6.spec
mkdir ~/el6
mv ~/rpmbuild/RPMS/x86_64/* ~/el6/
rpmbuild -ba SPECS/hubblestack-el7.spec
mkdir ~/el7
mv ~/rpmbuild/RPMS/x86_64/* ~/el7/
