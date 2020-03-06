#!/bin/bash
# NOTE: after running this script check the diff to fix any 
# unintended changes 

directories=`find pkg -type d | egrep -v "source|scripts|pyinstaller*|dev$|pkg$"`

for i in $directories;
do
  cp -f pyinstaller-requirements.txt $i
done
