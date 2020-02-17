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

# rpm pkg start
tar -cPvvzf /data/hubblestack-${HUBBLE_VERSION}.tar.gz /etc/hubble \
    /opt/hubble /opt/osquery /etc/profile.d/hubble-profile.sh \
    /var/log/hubble_osquery/backuplogs \
    /opt/pyenv 2>&1 \
    | tee /hubble_build/rpm-pkg-start-tar.log

mkdir -p /hubble_build/debbuild/hubblestack-${HUBBLE_VERSION}
tar -xzvvf /data/hubblestack-${HUBBLE_VERSION}.tar.gz -C \
    /hubble_build/debbuild/hubblestack-${HUBBLE_VERSION}

mkdir -p /hubble_build/debbuild/hubblestack-${HUBBLE_VERSION}/etc/init.d
cp /hubble_build/pkg/hubble /hubble_build/debbuild/hubblestack-${HUBBLE_VERSION}/etc/init.d/

cp -f /hubble_build/conf/hubble \
    /hubble_build/debbuild/hubblestack-${HUBBLE_VERSION}/etc/hubble/

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

# symlink to have hubble binary in path
cd /hubble_build/debbuild/hubblestack-${HUBBLE_VERSION}
mkdir -p usr/bin
ln -s /opt/hubble/hubble usr/bin/hubble

# fpm start
fpm -s dir -t deb \
    -n hubblestack \
    -v ${HUBBLE_VERSION} \
    --iteration ${HUBBLE_ITERATION} \
    --url ${HUBBLE_URL} \
    --deb-no-default-config-files \
    --after-install /hubble_build/conf/afterinstall-systemd.sh \
    --after-upgrade /hubble_build/conf/afterupgrade-systemd.sh \
    --before-remove /hubble_build/conf/beforeremove.sh \
    etc/hubble etc/init.d opt usr /var/log/hubble_osquery/backuplogs

# edit to change iteration number, if necessary
cp hubblestack_${HUBBLE_VERSION}-${HUBBLE_ITERATION}_amd64.deb \
    /data/hubblestack-${HUBBLE_VERSION}-${HUBBLE_ITERATION}.deb8.amd64.deb

openssl dgst -sha256 /data/hubblestack-${HUBBLE_VERSION}-${HUBBLE_ITERATION}.deb8.amd64.deb \
    > /data/hubblestack-${HUBBLE_VERSION}-${HUBBLE_ITERATION}.deb8.amd64.deb.sha256
