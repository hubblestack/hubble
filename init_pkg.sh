#!/bin/bash

_user=`id -u`

# Installing minimum of python 2.7
_python_version=`python -c 'import sys; version=sys.version_info[:3]; print("{0}.{1}.{2}".format(*version))'`

read -r -d "" _PYTHON_HELP <<EOF

You are running an older version python ... \n \n

Please run the following commands to setup python27 \n \n

sudo yum update \n
sudo yum install centos-release-scl \n
sudo yum install python27 \n
scl enable python27 bash \n

EOF

# Check if the python version is 2.6.6
if [ "$_python_version" == "2.6.6" ]
then
  echo -e $_PYTHON_HELP
  exit
fi

# Check if the current user is root
if [ "$_user" == "0" ]
then
  echo "This script should not be run as root ..."
  echo "Please run this script as regular user with sudo privileges ..."
  echo "Exiting ..."
  exit
fi

cd scripts/
sudo bash installessentials.sh
sudo bash pyinstaller-hubble.sh pkg_clean $1
sudo bash libgit2-build.sh
bash osquery-build.sh
sudo bash pip-install.sh
sudo bash pyinstaller-hubble.sh pkg_init
sudo bash pyinstaller-hubble.sh pkg_create
