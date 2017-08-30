# This Dockerfile aims to make building Hubble v2 packages easier.
# To build an image: 1. copy pkg/scripts/pyinstaller-requirements.txt to directory with this Dockerfile
#                    2. docker build -t <image_name> .
# The resulting image is ready to run the pyinstaller on container start and drop hubble<version>-coreos.tar.gz
# in the /data directory. Mount /data volume into a directory on the host to access the package.
# To run the container:  docker run -it --rm -v `pwd`:/data <image_name>

FROM debian:8

RUN apt-get update     \
 && apt-get -y upgrade

#paths that hubble or hubble parts need in the package
RUN mkdir -p /etc/osquery /var/log/osquery /etc/hubble/hubble.d /opt/hubble /opt/osquery /var/osquery

#osquery build start
#osquery should be built first since requirements for other packages can interfere with osquery dependencies
#to build, osquery scripts want sudo and a user to sudo with.
#to pin to a different version change the following envirnment variable
ENV OSQUERY_SRC_VERSION=2.6.0
ENV OSQUERY_BUILD_USER=osquerybuilder
ENV OSQUERY_GIT_URL=https://github.com/facebook/osquery.git
RUN apt-get -y install git make python ruby sudo locales
RUN useradd --shell /bin/bash --create-home --user-group --groups sudo "$OSQUERY_BUILD_USER" \
 && sed -i 's/^%sudo.*/%sudo\ ALL=\(ALL\)\ NOPASSWD:\ ALL/' /etc/sudoers
RUN mkdir -p /usr/local/osquery/ \
 && chown "$OSQUERY_BUILD_USER":"$OSQUERY_BUILD_USER" -R /usr/local/osquery/ \
 && echo "LC_ALL=en_US.UTF-8" >> /etc/default/locale \
 && sed -i '/en_US.UTF-8\ UTF-8/s/^#//' /etc/locale.gen \
 && locale-gen
USER $OSQUERY_BUILD_USER
ENV SKIP_TESTS=1
RUN cd /home/"$OSQUERY_BUILD_USER" \
 && git clone "$OSQUERY_GIT_URL" \
 && cd osquery/ \
 && git checkout "$OSQUERY_SRC_VERSION" \
#these homebrew hashes need to be current. hashes in osquery git repo are often out of date for the tags we check out and try to build.
#this is a problem and they are aware of it. let the magic hashes commence:
 && sed -i 's,^\(HOMEBREW_CORE=\).*,\1'941ca36839ea354031846d73ad538e1e44e673f4',' tools/provision.sh \
 && sed -i 's,^\(LINUXBREW_CORE=\).*,\1'abc5c5782c5850f2deff1f3d463945f90f2feaac',' tools/provision.sh \
 && sed -i 's,^\(HOMEBREW_BREW=\).*,\1'ac2cbd2137006ebfe84d8584ccdcb5d78c1130d9',' tools/provision.sh \
 && sed -i 's,^\(LINUXBREW_BREW=\).*,\1'20bcce2c176469cec271b46d523eef1510217436',' tools/provision.sh \
 && make sysprep \
#have the default augeas lenses directory point to /opt/osquery/lenses, must be done after sysprep
 && sed -i '/augeas_lenses,/,/\"Directory\ that\ contains\ augeas\ lenses\ files\"\\)\;/ s/\/usr\/share\/osquery\/lenses/\/opt\/osquery\/lenses/' osquery/tables/system/posix/augeas.cpp \
 && make deps \
 && make \
 && make strip
USER root
RUN cp -pr /home/"$OSQUERY_BUILD_USER"/osquery/build/linux/osquery/osqueryi /home/"$OSQUERY_BUILD_USER"/osquery/build/linux/osquery/osqueryd /opt/osquery \
 && chown -R root. /opt/osquery \
 && chmod -R 500 /opt/osquery/* \
#put augeas lenses into the default directory that we changed earlier
 && mkdir -p /opt/osquery/lenses \
 && cp -r /usr/local/osquery/share/augeas/lenses/dist/* /opt/osquery/lenses \
 && chmod -R 400 /opt/osquery/lenses/*
RUN ls -lahR /opt/osquery/ && /opt/osquery/osqueryi --version

#install packages that should be needed for ligbit2 compilation and successful pyinstaller run
RUN apt-get -y install  \
               python-dev libffi-dev libssl-dev libyaml-dev \
               libxml2-dev libxslt1-dev zlib1g-dev cmake python-setuptools \
               gcc wget openssl \
 && apt-get clean

#libgit2 install start
#must precede pyinstaller requirements
ENV LIBGIT2_SRC_URL=https://github.com/libgit2/libgit2/archive/v0.26.0.tar.gz
ENV LIBGIT2_SRC_SHA256=4ac70a2bbdf7a304ad2a9fb2c53ad3c8694be0dbec4f1fce0f3cd0cda14fb3b9
ENV LIBGIT2_SRC_VERSION=0.26.0
ENV LIBGIT2TEMP=/tmp/libgit2temp
RUN mkdir -p "$LIBGIT2TEMP" \
 && cd "$LIBGIT2TEMP" \
 && wget -q "$LIBGIT2_SRC_URL" -O libgit2.tar.gz \
 && echo "$LIBGIT2_SRC_SHA256  libgit2.tar.gz" | sha256sum -c - \
 && tar xzf libgit2.tar.gz \
 && cd libgit2-"$LIBGIT2_SRC_VERSION"/ \
 && export LIBGIT2=/usr/local/ \
 && cmake . -DCMAKE_INSTALL_PREFIX=$LIBGIT2 \
 && make \
 && make install

#pyinstaller requirements start
#must be preceded by libgit2 install
COPY pyinstaller-requirements.txt /
#default python-pip from yum does not like upgrading itself from pip. looking for better options other than wget.
RUN wget -c https://bootstrap.pypa.io/get-pip.py \
 && python get-pip.py \
 && pip -v install -r pyinstaller-requirements.txt

#deb package making requirements start
RUN apt-get install -y ruby ruby-dev rubygems gcc make \
 && gem install --no-ri --no-rdoc fpm

#pyinstaller start
#commands specified for ENTRYPOINT and CMD are executed when the container is run, not when the image is built
#use the following variables to choose the version of hubble
ENV HUBBLE_CHECKOUT=v2.2.3
ENV HUBBLE_VERSION=2.2.3
ENV HUBBLE_GIT_URL=https://github.com/hubblestack/hubble.git
ENV HUBBLE_SRC_PATH=/hubble_src
ENV _HOOK_DIR="./pkg/"
ENV _BINARY_LOG_LEVEL="INFO"
ENV _INCLUDE_PATH=""
RUN git clone "$HUBBLE_GIT_URL" "$HUBBLE_SRC_PATH" \
 && cd "$HUBBLE_SRC_PATH" \
 && git checkout "$HUBBLE_CHECKOUT" \
 && cp -rf "$HUBBLE_SRC_PATH" /hubble_build
RUN mkdir /data
VOLUME /data
WORKDIR /hubble_build
ENTRYPOINT [ "/bin/bash", "-o", "xtrace", "-c" ]
CMD [ "pyinstaller --onedir --noconfirm --log-level ${_BINARY_LOG_LEVEL} --additional-hooks-dir=${_HOOK_DIR} hubble.py \
    && cp /hubble_build/conf/osquery.conf /etc/osquery/ \
    && cp /hubble_build/conf/osquery.flags /etc/osquery/ \
# hubble default configuration file
    && cp -rf /hubble_build/conf/hubble /etc/hubble/ \
    && cp -rf /hubble_build/conf/hubble-profile.sh /etc/profile.d/ \
    && cp -pr /hubble_build/dist/hubble /opt/hubble/hubble-libs \
    && ln -s /opt/hubble/hubble-libs/hubble /opt/hubble/hubble \
    # make sure rpm shared libs are taken out to avoid mismatch between rpm database and shared libs that pyinstaller includes
    && rm -rf /opt/hubble/hubble-libs/librpm* \
#debian pkg start
    && tar -cPvzf /data/hubblestack-${HUBBLE_VERSION}.tar.gz /etc/hubble /etc/osquery /opt/hubble /opt/osquery /var/log/osquery /etc/profile.d/hubble-profile.sh \
    && mkdir -p /hubble_build/debbuild/hubblestack-${HUBBLE_VERSION} \
    && tar -xzvf /data/hubblestack-${HUBBLE_VERSION}.tar.gz -C /hubble_build/debbuild/hubblestack-${HUBBLE_VERSION} \
    && mkdir -p /hubble_build/debbuild/hubblestack-${HUBBLE_VERSION}/etc/init.d \
    && cp /hubble_build/pkg/hubble /hubble_build/debbuild/hubblestack-${HUBBLE_VERSION}/etc/init.d/ \
    && mkdir -p /hubble_build/debbuild/hubblestack-${HUBBLE_VERSION}/usr/lib/systemd/system \
    && cp /hubble_build/pkg/hubble.service /hubble_build/debbuild/hubblestack-${HUBBLE_VERSION}/usr/lib/systemd/system/ \
    && cp -f /hubble_build/conf/hubble /hubble_build/debbuild/hubblestack-${HUBBLE_VERSION}/etc/hubble/ \
#during container run, if a configuration file exists in a /data copy it over the existing one so it would be
#possile to optionally include a custom one with the package
    && if [ -f /data/hubble ] ; then cp /data/hubble /hubble_build/debbuild/hubblestack-${HUBBLE_VERSION}/etc/hubble/ ; fi \
    && cd /hubble_build/debbuild/hubblestack-${HUBBLE_VERSION} \
    && mkdir -p usr/bin \
#symlink to have hubble binary in path
    && ln -s /opt/hubble/hubble usr/bin/hubble \
#fpm start
    && fpm -s dir -t deb \
       -n hubblestack \
       -v ${HUBBLE_VERSION}-1 \
    #todo: get rid of the git dependency with static bin in the future
       -d 'git' \
       --config-files /etc/hubble --config-files /etc/osquery/osquery.conf \
       --deb-no-default-config-files \
       etc/hubble etc/osquery etc/init.d opt usr \
    && cp hubblestack_${HUBBLE_VERSION}-1_amd64.deb /data/hubblestack_${HUBBLE_VERSION}-1deb8_amd64.deb" ]

