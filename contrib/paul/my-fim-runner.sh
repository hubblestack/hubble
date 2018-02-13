#!/usr/bin/env bash

# hi is App:HI on the CPAN
# todo and lime are colors in Term::ANSIColorx::ColorNicknames
# cpanm Term::ANSIColorx::ColorNicknames App::HI

sudo sysctl -w fs.inotify.max_user_watches=${1:-${watches:-1000000}}
sudo killall -v hubble
sudo bash -c 'umask 022
  python setup.py install
  rm -rf hubblestack.egg-info build dist
  [ -f /etc/hubble.bak ] && cp -va /etc/hubble.bak /etc/hubble/hubble
  ' && sudo hubble -vvv 2>&1 \
    | grep --line-buffered -vE "(xecuting.schedule|job.data.to.splunk|ob.returned|^\[\])" \
    | hi 'IN_\w+' todo '\w+_CREATE' lime '\w+_DELETE' red WTF todo 'file-watch.totals.*' yellow \
         '\S+ file-watch' magenta 'stopped.watching.*' red home/jettero/bin lime "creating new watch manager" \
         red "(?i:wtf)" todo
