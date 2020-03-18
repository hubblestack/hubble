# This Dockerfile aims to make building Hubble v2 packages easier.
# To build an image: 1. copy pkg/scripts/pyinstaller-requirements.txt to directory with this Dockerfile
#                    2. docker build -t <image_name> .
# The resulting image is ready to run the pyinstaller on container start and drop hubble<version>-coreos.tar.gz
# in the /data directory. Mount /data volume into a directory on the host to access the package.
# To run the container:  docker run -it --rm -v `pwd`:/data <image_name>
# Requires docker 17.05 or higher

# Set this argument to "local" if you want to build osquery for local code.
# In that case, osquery folder must exist besides Dockerfile
ARG OSQUERY_BUILD_ENV=remote

#--------------- TEMP CONTAINER FOR LOCAL OSQUERY -------------------------
FROM alpine as osquery_local
ONBUILD COPY osquery /osquery
ONBUILD RUN echo "Copying osquery from local folder"



#--------------- TEMP CONTAINER FOR GIT OSQUERY ----------------------------
FROM alpine/git as osquery_remote
#to pin osquery to a different version change the following envirnment variable
ENV OSQUERY_SRC_VERSION=3.3.2
ENV OSQUERY_GIT_URL=https://github.com/facebook/osquery.git
ONBUILD RUN cd / \
 && git clone "$OSQUERY_GIT_URL" \
 && cd osquery/ \
 && git checkout "$OSQUERY_SRC_VERSION" \
 && echo "Fetching osquery from git"


#--------------- TEMP CONTAINER FOR OSQUERY ( BASED ON ARGUMENT ) ---------------
FROM osquery_"$OSQUERY_BUILD_ENV" as osquery_image


#--------------- ACTUAL DOCKERFILE FOR BUILD CREATION  --------------------------
FROM centos:7

RUN yum makecache fast && yum -y update

#paths that hubble or hubble parts need in the package
RUN mkdir -p /etc/hubble/hubble.d /opt/hubble /opt/osquery /var/log/hubble_osquery/backuplogs
#osquery build start
#osquery should be built first since requirements for other packages can interfere with osquery dependencies
#to build, osquery scripts want sudo and a user to sudo with.
ENV OSQUERY_BUILD_USER=osquerybuilder
RUN yum -y install git make python ruby sudo which
RUN useradd --shell /bin/bash --create-home --user-group --groups wheel "$OSQUERY_BUILD_USER" \
 && sed -i '0,/^#\ %wheel/s/^#\ %wheel.*/%wheel\ ALL=\(ALL\)\ NOPASSWD:\ ALL/' /etc/sudoers
COPY --from=osquery_image /osquery /home/"$OSQUERY_BUILD_USER"/osquery
RUN mkdir -p /usr/local/osquery/ \
 && chown "$OSQUERY_BUILD_USER":"$OSQUERY_BUILD_USER" -R /usr/local/osquery/ \
 && chown "$OSQUERY_BUILD_USER":"$OSQUERY_BUILD_USER" -R /home/"$OSQUERY_BUILD_USER"/osquery
USER $OSQUERY_BUILD_USER
ENV SKIP_TESTS=1
RUN cd /home/"$OSQUERY_BUILD_USER"/osquery \
 && make sysprep \
#have the default augeas lenses directory point to /opt/osquery/lenses, must be done after sysprep
 && sed -i '/augeas_lenses,/,/\"Directory\ that\ contains\ augeas\ lenses\ files\"\\)\;/ s/\/usr\/share\/osquery\/lenses/\/opt\/osquery\/lenses/' osquery/tables/system/posix/augeas.cpp \
 && make deps \
 && make \
 && make strip
USER root
RUN cp -pr /home/"$OSQUERY_BUILD_USER"/osquery/build/linux/osquery/osqueryi /opt/osquery \
 && cp -pr /home/"$OSQUERY_BUILD_USER"/osquery/build/linux/osquery/osqueryd /opt/osquery/hubble_osqueryd \
 && chown -R root. /opt/osquery \
 && chmod -R 500 /opt/osquery/* \
#put augeas lenses into the default directory that we changed earlier
 && mkdir -p /opt/osquery/lenses \
 && cp -r /usr/local/osquery/share/augeas/lenses/dist/* /opt/osquery/lenses \
 && chmod -R 400 /opt/osquery/lenses/*
RUN ls -lahR /opt/osquery/ && /opt/osquery/osqueryi --version

#install packages that should be needed for ligbit2 compilation and successful pyinstaller run
RUN yum -y install  \
               libffi-devel openssl-devel libffi libssh2-devel autoconf automake libtool \
               libxml2-devel libxslt-devel libjpeg-devel zlib-devel \
               make cmake gcc python-devel python-setuptools wget openssl

#libcurl install start
#install libcurl to avoid depending on host version
#requires autoconf libtool libssh2-devel zlib-devel autoconf
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
 && ./configure --prefix=/opt/hubble --disable-ldap --without-nss --disable-manual --disable-gopher --disable-smtp --disable-smb --disable-imap --disable-pop3 --disable-tftp --disable-telnet --disable-dict --disable-ldaps --disable-ldap --disable-rtsp --with-libssh2 \
 && make \
 && make install

#git install start
#install git so that git package won't be a package dependency
#requires make git libcurl-devel autoconf zlib-devel gcc
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
 && make install

#clean up of /opt/hubble
RUN rm /opt/hubble/bin/curl* \
 && rm -rf /opt/hubble/include /opt/hubble/share

#libgit2 install start
#must precede pyinstaller requirements
ENV LIBGIT2_SRC_URL=https://github.com/libgit2/libgit2/archive/v0.26.5.tar.gz
#it turns out github provided release files can change. so even though the code hopefully hasn't changed, the hash has.
ENV LIBGIT2_SRC_SHA256=52e28a5166564bc4365a2e4112f5e5c6e334708dbf13596241b2fd34efc1b0a9
ENV LIBGIT2_SRC_VERSION=0.26.5
ENV LIBGIT2TEMP=/tmp/libgit2temp
RUN mkdir -p "$LIBGIT2TEMP" \
 && cd "$LIBGIT2TEMP" \
 && wget -q "$LIBGIT2_SRC_URL" -O libgit2.tar.gz \
 && echo "$LIBGIT2_SRC_SHA256  libgit2.tar.gz" | sha256sum -c - \
 && tar xzf libgit2.tar.gz \
 && cd libgit2-"$LIBGIT2_SRC_VERSION"/ \
 && cmake . -DCMAKE_INSTALL_PREFIX=/usr/local/ \
 && make \
 && make install

#fpm package making requirements start
RUN yum install -y ruby ruby-devel rpmbuild rpm-build rubygems gcc make \
 && gem install --no-ri --no-rdoc fpm

# things we may need to build a python
RUN yum install -y bzip2-devel

# use pyenv
ARG PYENV_VERSION=3.6.10
ENV PYENV_INSTALLER_URL=https://raw.githubusercontent.com/pyenv/pyenv-installer/master/bin/pyenv-installer
ENV PYENV_ROOT=/opt/hubble/pyenv
ENV PATH=$PYENV_ROOT/bin:$PATH
ENV PYTHON_CONFIGURE_OPTS="--enable-shared"
RUN umask 022 \
 && curl -s -S -L "$PYENV_INSTALLER_URL" -o /usr/bin/pyenv-installer \
 && chmod 0755 /usr/bin/pyenv-installer \
 && /usr/bin/pyenv-installer \
 && eval "$(pyenv init -)" \
 && pyenv install $PYENV_VERSION \
 && pyenv global $PYENV_VERSION

RUN eval "$(pyenv init -)" \
 && pip -v install --upgrade pip

#pyinstaller start
#commands specified for ENTRYPOINT and CMD are executed when the container is run, not when the image is built
#use the following variables to choose the version of hubble
ARG HUBBLE_CHECKOUT=v4.0.0
ENV HUBBLE_VERSION=4.0.0
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

RUN set -x; git clone "$HUBBLE_GIT_URL" "$HUBBLE_SRC_PATH" \
 && cd "$HUBBLE_SRC_PATH" \
 && git checkout -B hubble-build && git reset --hard "$HUBBLE_CHECKOUT" && git clean -dfx

RUN cp -rf "$HUBBLE_SRC_PATH" /hubble_build \
 && rm -rf /hubble_build/.git

RUN cp /hubble_build/hubblestack/__init__.py /hubble_build/hubblestack/__init__.orig \
 && sed -i -e "s/BRANCH_NOT_SET/${HUBBLE_CHECKOUT}/g" \
           -e "s/COMMIT_NOT_SET/$(cd $HUBBLE_SRC_PATH; git describe --long --always --tags)/g" \
           /hubble_build/hubblestack/__init__.py \
 && cp /hubble_build/hubblestack/__init__.py /hubble_build/hubblestack/__init__.fixed

RUN mkdir /data
VOLUME /data

WORKDIR /hubble_build

COPY entrypoint.sh /entrypoint.sh
ENTRYPOINT [ "/bin/bash", "/entrypoint.sh" ]
