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
rm -rf ~/hubblestack-2.1.0
rm -rf ~/hubblestack-2.1.0.tar.gz
mkdir ~/hubblestack-2.1.0
tar -xzvf ~/hubble.tar.gz -C ~/hubblestack-2.1.0
mkdir -p ~/hubblestack-2.1.0/etc/init.d
cp pkg/hubble ~/hubblestack-2.1.0/etc/init.d
mkdir -p ~/hubblestack-2.1.0/usr/lib/systemd/system
cp pkg/hubble.service ~/hubblestack-2.1.0/usr/lib/systemd/system
cd ~
tar -czvf hubblestack-2.1.0.tar.gz hubblestack-2.1.0/
rm -rf ~/rpmbuild
mkdir -p ~/rpmbuild/{RPMS,SRPMS,BUILD,SOURCES,SPECS,tmp}

cat <<EOF >~/.rpmmacros
%_topdir   %(echo $HOME)/rpmbuild
%_tmppath  %{_topdir}/tmp
EOF

cp ~/hubblestack-2.1.0.tar.gz ~/rpmbuild/SOURCES/
cd ~/rpmbuild

cp ~/hubble/pkg/specs/* SPECS/

rpmbuild -ba SPECS/hubblestack-el6.spec
rm -rf ~/el6
mkdir ~/el6
cp ~/rpmbuild/RPMS/x86_64/* ~/el6/
rpmbuild -ba SPECS/hubblestack-el7.spec
rm -rf ~/el7
mkdir ~/el7
cp ~/rpmbuild/RPMS/x86_64/* ~/el7/
