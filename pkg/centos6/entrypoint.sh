#!/bin/bash

eval "$(pyenv init -)"

# locate some pyenv things
pyenv_prefix="$(pyenv prefix)"
python_binary="$(pyenv which python)"
while [ -L "$python_binary" ]
do python_binary="$(readlink -f "$python_binary")"
done

# if ENTRYPOINT is given a CMD other than nothing
# abort here and do that other CMD
if [ $# -gt 0 ]
then exec "$@"
fi

# from now on, exit on error (rather than && every little thing)
PS4=$'-------------=: '
set -x -e

# possibly replace the version file
if [ -f /data/hubble_buildinfo ]; then
    echo >> /hubble_build/hubblestack/__init__.py
    cat /data/hubble_buildinfo >> /hubble_build/hubblestack/__init__.py
fi 2>/dev/null

cat > /data/pre_packaged_certificates.py << EOF
ca_crt = list()
public_crt = list()
EOF
do_pkg_crts=0
if [ -f /data/certs/ca-root.crt ]; then
    echo "ca_crt.append('''$(< /data/certs/ca-root.crt)''')" \
        >> /data/pre_packaged_certificates.py
        do_pkg_crts=$(( do_pkg_crts + 1 ))
    for item in /data/certs/int*.crt; do
        if [ -f "$item" ]
        then echo "ca_crt.append('''$(< "$item")''')" \
            >> /data/pre_packaged_certificates.py
            do_pkg_crts=$(( do_pkg_crts + 1 ))
        fi
    done
fi
for item in /data/certs/{pub,sign}*.crt; do
    if [ -f "$item" ]
    then echo "public_crt.append('''$(< "$item")''')" \
        >> /data/pre_packaged_certificates.py
        do_pkg_crts=$(( do_pkg_crts + 1 ))
    fi
done
if [ $do_pkg_crts -gt 0 ]
then cp /data/pre_packaged_certificates.py /hubble_build/hubblestack
fi

cd /hubble_build

# we may have preinstalled requirements that may need upgrading
# pip install . might not upgrade/downgrade the requirements
python setup.py egg_info
pip install --upgrade \
    -r hubblestack.egg-info/requires.txt \
    -r optional-requirements.txt \
    -r package-requirements.txt

[ -f ${_HOOK_DIR:-./pkg}/hook-hubblestack.py ] || exit 1

rm -rf build dist /opt/hubble/hubble-libs /hubble_build/hubble.spec
export LD_LIBRARY_PATH=$pyenv_prefix/lib:/opt/hubble/lib:/opt/hubble-libs
export LD_RUN_PATH=$LD_LIBRARY_PATH
pyinstaller --onedir --noconfirm --log-level ${_BINARY_LOG_LEVEL:-INFO} \
    --additional-hooks-dir ${_HOOK_DIR:-./pkg} \
    --runtime-hook pkg/runtime-hooks.py \
    ./hubble.py 2>&1 | tee /tmp/pyinstaller.log

cp -pr dist/hubble /opt/hubble/hubble-libs

cat > /opt/hubble/hubble << EOF
#!/bin/bash
exec /opt/hubble/hubble-libs/hubble "\$@"
exit 1
EOF
chmod 0755 /opt/hubble/hubble

[ -d /data/last-build.4 ] && rm -rf /data/last-build.4
[ -d /data/last-build.3 ] && mv -v /data/last-build.3 /data/last-build.4
[ -d /data/last-build.2 ] && mv -v /data/last-build.2 /data/last-build.3
[ -d /data/last-build.1 ] && mv -v /data/last-build.1 /data/last-build.2
cp -va build/ /data/last-build.1
mv /tmp/pyinstaller.log /data/last-build.1
cp -va /entrypoint.sh /data/last-build.1

mkdir -p /var/log/hubble_osquery/backuplogs

mkdir -p /etc/init.d
mkdir -p /etc/profile.d
mkdir -p /etc/hubble

cp -v /hubble_build/pkg/hubble /etc/init.d
cp -v /hubble_build/conf/hubble-profile.sh /etc/profile.d/

if [ -f /data/hubble ]
then cp -v /data/hubble /etc/hubble/
else cp -v /hubble_build/conf/hubble /etc/hubble/
fi

if [ "X$TEST_BINARIES" = X1 ]; then
    # weakly test the new bin
    ./dist/hubble/hubble --version

    # does it still work if we call it in its new home?
    /opt/hubble/hubble-libs/hubble --version

    # how about if it's via non-home location?
    /opt/hubble/hubble --version

    # lastly, can we actually use salt grains and other lazy loader items?
    /opt/hubble/hubble-libs/hubble -vvv grains.get hubble_version
    /opt/hubble/hubble -vvv grains.get hubble_version
fi

if [ "X$NO_TAR" = X1 ]; then
    echo "exiting (as requested by NO_TAR=$NO_TAR) without pre-tar-ing package"
    exit 0
fi 2>/dev/null

# rpm pkg start
tar -cSPvvzf /data/hubblestack-${HUBBLE_VERSION}.tar.gz \
    --exclude opt/hubble/pyenv \
    /etc/hubble /opt/hubble /opt/osquery \
    /etc/profile.d/hubble-profile.sh \
    /etc/init.d/hubble \
    /var/log/hubble_osquery/backuplogs \
    2>&1 | tee /hubble_build/rpm-pkg-start-tar.log

PKG_STRUCT_DIR=/hubble_build/debbuild/hubblestack-${HUBBLE_VERSION}
mkdir -p /hubble_build/debbuild/hubblestack-${HUBBLE_VERSION}
tar -xSzvvf /data/hubblestack-${HUBBLE_VERSION}.tar.gz -C $PKG_STRUCT_DIR

# also bring in anything from a /data/opt/ directory so we can bundle other executables if needed
if [ -d /data/opt ]
then cp -r /data/opt/* /hubble_build/debbuild/hubblestack-${HUBBLE_VERSION}/opt/
fi

# symlink to have hubble binary in path
cd /hubble_build/debbuild/hubblestack-${HUBBLE_VERSION}
mkdir -p usr/bin
ln -s /opt/hubble/hubble usr/bin/hubble

if [ "X$NO_FPM" = X1 ]; then
    echo "exiting (as requested by NO_FPM=$NO_FPM) without building package"
    exit 0
fi

# fpm start
scl enable rh-ruby23 'fpm -s dir -t rpm \
    -n hubblestack \
    -v ${HUBBLE_VERSION} \
    --iteration ${HUBBLE_ITERATION} \
    --url ${HUBBLE_URL} \
    --description "${HUBBLE_DESCRIPTION}" \
    --rpm-summary "${HUBBLE_SUMMARY}" \
    --after-install /hubble_build/conf/afterinstall.sh \
    --after-upgrade /hubble_build/conf/afterupgrade.sh \
    --before-remove /hubble_build/conf/beforeremove.sh \
    etc/hubble etc/init.d opt usr /var/log/hubble_osquery/backuplogs'

# edit to change iteration number, if necessary
PKG_BASE_NAME=hubblestack-${HUBBLE_VERSION}-${HUBBLE_ITERATION}
PKG_OUT_EXT=x86_64.rpm
PKG_FIN_EXT=el6.$PKG_OUT_EXT
PKG_ONAME="$PKG_BASE_NAME.$PKG_OUT_EXT"
PKG_FNAME="$PKG_BASE_NAME.$PKG_FIN_EXT"

cp -va "$PKG_ONAME" /data/"$PKG_FNAME"
openssl dgst -sha256 /data/"$PKG_FNAME" > /data/"$PKG_FNAME".sha256
