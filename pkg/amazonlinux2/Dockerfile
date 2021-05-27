# This Dockerfile aims to make building Hubble v4 packages easier.
# Starting with version 4 building osquery is removed from individual Dockerfiles to its own.
# osquery needs to be built once. Resulting tar file can be used in hubblev4 Dockerfiles.
# Before building hubble, build osquery using a Dockerfile in pkg/osquery/ directory.
# To build this image: 1. copy previously built osquery_4hubble.tar to directory with this Dockerfile
#                      2. docker build -t <image_name> --build-arg HUBBLE_CHECKOUT=<tag or commit> --build-arg HUBBLE_VERSION=<Hubble Version> .
# The resulting image is ready to build and run pyinstaller on container start that should 
# create hubble<version>-centos8.tar.gz in the /data directory inside the container.
# Mount /data volume into a directory on the host to access the package.
# To run the container:  docker run -it --rm -v `pwd`:/data <image_name>

FROM amazonlinux:2

RUN yum -y update && yum clean all && rm -rf /var/cache/yum

# paths that hubble or hubble parts need in the package
RUN mkdir -p /etc/hubble/hubble.d /opt/hubble /opt/osquery /var/log/hubble_osquery/backuplogs

# install packages that should be needed for ligbit2 compilation and successful pyinstaller run
RUN yum -y install git \
    libffi-devel openssl-devel libffi libssh-devel autoconf automake libtool \
    libxml2-devel libxslt-devel libjpeg-devel zlib-devel \
    libssh2-devel \
    make gcc python3-devel wget openssl \
    && yum clean all \
    && rm -rf /var/cache/yum

ARG ARCH=x86_64

# libcurl install start
# install libcurl to avoid depending on host version
# requires autoconf libtool libssh2-devel zlib-devel autoconf
ENV LIBCURL_SRC_URL=https://github.com/curl/curl.git
ENV LIBCURL_SRC_VERSION=curl-7_64_1
ENV LIBCURL_TEMP=/tmp/libcurl
ENV PATH=/opt/hubble/bin/:/opt/hubble/include:/opt/hubble/lib:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
RUN mkdir -p "$LIBCURL_TEMP" \
 && cd "$LIBCURL_TEMP" \
 && git clone "$LIBCURL_SRC_URL" \
 && cd curl \
 && git checkout "$LIBCURL_SRC_VERSION" \
 && ./buildconf \
 && ./configure --prefix=/opt/hubble --disable-ldap \
        --without-nss --disable-manual --disable-gopher \
        --disable-smtp --disable-smb --disable-imap \
        --disable-pop3 --disable-tftp --disable-telnet \
        --disable-dict --disable-ldaps --disable-ldap \
        --disable-rtsp \
        --with-libssh2 \
 && make \
 && make install \
 && rm -rf "$LIBCURL_TEMP"

# git install start
# install git so that git package won't be a package dependency
# requires make git libcurl-devel autoconf zlib-devel gcc
ENV GIT_SRC_URL=https://github.com/git/git.git
ENV GIT_SRC_VERSION=v2.21.0
ENV GITTEMP=/tmp/gittemp
RUN mkdir -p "$GITTEMP" \
 && cd "$GITTEMP" \
 && git clone "$GIT_SRC_URL" \
 && cd git \
 && git checkout "$GIT_SRC_VERSION" \
 && make configure \
 && ./configure --prefix=/opt/hubble --with-tcltk=no --with-expat=no --with-python=no  --with-curl=/opt/hubble \
 && echo "NO_TCLTK=YesPlease" >> config.mak.autogen \
 && echo "NO_PERL=YesPlease" >> config.mak.autogen \
 && sed -i '0,/^NO_GETTEXT/s/^NO_GETTEXT.*/NO_GETTEXT=YesPlease/' config.mak.autogen \
 && make \
 && make install \
 && rm -rf "$GITTEMP"

# clean up of /opt/hubble
RUN rm /opt/hubble/bin/curl* \
 && rm -rf /opt/hubble/include /opt/hubble/share

ENV CMAKE_SRC_URL=https://github.com/Kitware/CMake/releases/download/v3.20.2/cmake-3.20.2-linux-$ARCH.tar.gz
COPY $ARCH.cmake.sums /root
RUN wget -q "$CMAKE_SRC_URL"
RUN sha256sum -c /root/$ARCH.cmake.sums
RUN tar xf cmake-*.tar.gz -C /usr/local --strip 1

# libgit2 install start
# must precede pyinstaller requirements
ENV LIBGIT2_SRC_VERSION=1.1.0
ENV LIBGIT2_SRC_URL=https://github.com/libgit2/libgit2/archive/v$LIBGIT2_SRC_VERSION.tar.gz
# it turns out github provided release files can change. so even though the code hopefully hasn't changed, the hash has.
ENV LIBGIT2_SRC_SHA256=41a6d5d740fd608674c7db8685685f45535323e73e784062cf000a633d420d1e
ENV LIBGIT2TEMP=/tmp/libgit2temp
RUN mkdir -p "$LIBGIT2TEMP" \
 && cd "$LIBGIT2TEMP" \
 && wget -q "$LIBGIT2_SRC_URL" -O libgit2.tar.gz \
 && echo "$LIBGIT2_SRC_SHA256  libgit2.tar.gz" | sha256sum -c - \
 && tar xzf libgit2.tar.gz \
 && cd libgit2-"$LIBGIT2_SRC_VERSION"/ \
 && cmake . -DCMAKE_INSTALL_PREFIX=/usr/local/ \
 && make \
 && make install \
 && rm -rf "$LIBGIT2TEMP"

# things we may need to build python and get fpm working
RUN yum -y update \
 && yum install -y ruby ruby-devel rpm-build rubygems gcc make bzip2-devel sqlite-devel \
 && yum clean all \
 && rm -rf /var/cache/yum

# install fpm
RUN gem install --no-ri --no-rdoc ffi --version 1.12.2 \
 && gem install --no-ri --no-rdoc fpm --version 1.11

# use pyenv
ARG PYENV_VERSION=3.7.9
ENV PYENV_INSTALLER_URL=https://raw.githubusercontent.com/pyenv/pyenv-installer/master/bin/pyenv-installer
ENV PYENV_ROOT=/opt/hubble/pyenv
ENV PATH=$PYENV_ROOT/bin:$PATH
ENV PYTHON_CONFIGURE_OPTS="--enable-shared"
RUN umask 022 \
 && curl -s -S -L "$PYENV_INSTALLER_URL" -o /usr/bin/pyenv-installer \
 && chmod 0755 /usr/bin/pyenv-installer \
 && /usr/bin/pyenv-installer \
 && eval "$(pyenv init --path)" \ 
 && pyenv install $PYENV_VERSION \
 && pyenv global $PYENV_VERSION

RUN eval "$(pyenv init --path)" \ 
 && pip -v install --upgrade pip

# extract osquery files. optionally pass in osquery filename with OSQUERY_TAR_FILENAME build-arg
ARG OSQUERY_TAR_FILENAME=osquery_4hubble.$ARCH.tar
ADD ${OSQUERY_TAR_FILENAME} /opt/osquery/
RUN /opt/osquery/osqueryi --version

# pyinstaller start
# commands specified for ENTRYPOINT and CMD are executed when the container is run, not when the image is built
# use the following variables to choose the version of hubble
ARG HUBBLE_CHECKOUT=v4.5.1
ARG HUBBLE_VERSION=4.5.1
ENV HUBBLE_ITERATION=1
ENV HUBBLE_URL=https://github.com/hubblestack/hubble
ENV HUBBLE_DESCRIPTION="Hubble is a modular, open-source, security & compliance auditing framework which is built in python, using SaltStack as a library."
ENV HUBBLE_SUMMARY="Profile based on-demand auditing and monitoring tool"
ARG HUBBLE_GIT_URL=https://github.com/hubblestack/hubble.git
ENV HUBBLE_SRC_PATH=/hubble_src
ENV _HOOK_DIR="./pkg/"
ENV _BINARY_LOG_LEVEL="INFO"
ENV _INCLUDE_PATH=""
ENV LD_LIBRARY_PATH=/opt/hubble/lib:/lib:/lib64:/usr/lib:/usr/lib64:/usr/local/lib:/usr/local/lib64

RUN mkdir /data
VOLUME /data

WORKDIR /hubble_build

COPY entrypoint.sh /entrypoint.sh
ENV ARCH=$ARCH
ENV HUBBLE_CHECKOUT=$HUBBLE_CHECKOUT
ENV HUBBLE_VERSION=$HUBBLE_VERSION
ENV HUBBLE_GIT_URL=$HUBBLE_GIT_URL
ENTRYPOINT [ "/bin/bash", "/entrypoint.sh" ]
