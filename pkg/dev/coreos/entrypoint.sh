#!/bin/bash

# use the global pyenv version
eval "$(pyenv init -)"

# if ENTRYPOINT is given a CMD other than nothing
# abort here and do that other CMD
if [ $# -gt 0 ]
then exec "$@"
fi

# from now on, exit on error (rather than && every little thing)
set -x -e

cp -rf "$HUBBLE_SRC_PATH"/* /hubble_build/

# possibly replace the version file
if [ -f /data/hubble_buildinfo ]; then
    echo >> /hubble_build/hubblestack/__init__.py
    cat /data/hubble_buildinfo >> /hubble_build/hubblestack/__init__.py
fi


cd /hubble_build || exit 1 # we already exit by set -e, but ...

pip install --upgrade -r optional-requirements.txt
pip install .

ln -svf $(pyenv prefix)/bin/hubble /opt/hubble/hubble

mkdir -p /var/log/hubble_osquery/backuplogs

rm -rf /opt/hubble/hubble-libs/librpm*
rm -rf /opt/pyenv/.git

cp -va /usr/lib/x86_64-linux-gnu/libssh2.so.1 /opt/hubble/hubble-libs

mkdir -p /etc/system
mkdir -p /etc/profile.d
mkdir -p /etc/hubble

cp -v /hubble_build/pkg/hubble.service /etc/systemd/system
cp -v /hubble_build/conf/hubble-profile.sh /etc/profile.d/
cp -v /hubble_build/conf/hubble /etc/hubble/

# during container run, if a configuration file exists in a /data copy it over
# the existing one so it would be possile to optionally include a custom one
# with the package
if [ -f /data/hubble ]
then cp /data/hubble /hubble_build/debbuild/hubblestack-${HUBBLE_VERSION}/etc/hubble/
fi

# also bring in anything from a /data/opt/ directory so we can bundle other executables if needed
if [ -d /data/opt ]
then cp -r /data/opt/* /hubble_build/debbuild/hubblestack-${HUBBLE_VERSION}/opt/
fi

tar -cPvzf /data/hubblestack-${HUBBLE_VERSION}-${HUBBLE_ITERATION}.coreos.tar.gz \
    /etc/hubble /opt/hubble /opt/pyenv /opt/osquery \
    /etc/profile.d/hubble-profile.sh \
    /etc/systemd/system \
    /var/log/hubble_osquery/backuplogs

openssl dgst -sha256 /data/hubblestack-${HUBBLE_VERSION}-${HUBBLE_ITERATION}.coreos.tar.gz \
    > /data/hubblestack-${HUBBLE_VERSION}-${HUBBLE_ITERATION}.coreos.tar.gz.sha256
