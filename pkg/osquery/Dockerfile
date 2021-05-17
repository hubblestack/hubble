# This dockerfile builds the osquery binary and files that will run on majority of current Linux distributions.
# To build the image: docker build -t <image_name> .
# The image can be used to include the needed osquery files in Hubble packaging process.
# To override the name of the tar file pass in OSQUERY_TAR_FILENAME environment variable with the desired value.
# To create the file run the container: docker run -it --rm -v `pwd`:/data <image_name>

FROM ubuntu:18.04

# osquery build start
ENV OSQUERY_BUILD_USER=osquerybuilder
ENV OSQUERY_GIT_URL=https://github.com/osquery/osquery.git
ENV OSQUERY_SRC_VERSION=4.7.0

# prepare the requirements for building
RUN apt-get -y update && apt-get -y upgrade \
 && apt-get -y install --no-install-recommends wget ca-certificates xz-utils git python3 bison flex make \
 && apt-get clean && rm -rf /var/lib/apt/lists/* \
 && useradd --shell /bin/bash --create-home --user-group "$OSQUERY_BUILD_USER"

# building osquery requires osquery-toolchain and cmake
# make sure osquery-toolchain is compatible with the osquery version you want to build
# ARCH has the boring default of x86_64, but for arm we'd pick aarch64
ARG ARCH=x86_64
ENV OSQUERY_TOOLCHAIN_SRC_URL=https://github.com/osquery/osquery-toolchain/releases/download/1.1.0/osquery-toolchain-1.1.0-$ARCH.tar.xz
ENV CMAKE_SRC_URL=https://github.com/Kitware/CMake/releases/download/v3.20.2/cmake-3.20.2-linux-$ARCH.tar.gz

COPY $ARCH.sums /root

RUN wget -q "$OSQUERY_TOOLCHAIN_SRC_URL"
RUN wget -q "$CMAKE_SRC_URL"
RUN sha256sum -c /root/$ARCH.sums
RUN tar xf osquery-toolchain-*.tar.xz -C /usr/local
RUN tar xf cmake-*.tar.gz -C /usr/local --strip 1

USER $OSQUERY_BUILD_USER

ENV OSQUERY_IGNORE_CMAKE_MAX_VERSION_CHECK=TRUE
RUN cd /home/"$OSQUERY_BUILD_USER" \
 && git clone "$OSQUERY_GIT_URL" \
 && cd osquery/ \
 && git checkout "$OSQUERY_SRC_VERSION" \
 && mkdir build \
 && cd build \
 && cmake -DOSQUERY_IGNORE_CMAKE_MAX_VERSION_CHECK=TRUE \
          -DOSQUERY_TOOLCHAIN_SYSROOT=/usr/local/osquery-toolchain .. \
 && cmake --build . -j`nproc` \
 && /usr/local/osquery-toolchain/usr/bin/strip osquery/osqueryd

USER root

# collect all files and prepare them into a tar file
RUN mkdir -p /opt/osquery/lenses /opt/osquery/yara /opt/osquery/extensions \
 && cp /home/"$OSQUERY_BUILD_USER"/osquery/build/osquery/osqueryd /opt/osquery/hubble_osqueryd \
 && cp /home/"$OSQUERY_BUILD_USER"/osquery/build/osquery/osqueryd /opt/osquery/osqueryi \
 && cp -r /home/"$OSQUERY_BUILD_USER"/osquery/libraries/cmake/source/augeas/src/lenses /opt/osquery/ \
 && rm -rf /opt/osquery/lenses/tests/ \
 && chown -R root. /opt/osquery \
 && chmod -R 500 /opt/osquery/*

ENV ARCH=$ARCH
CMD [ "/bin/bash", "-c", "cd /opt/osquery ; tar -cvf /data/${OSQUERY_TAR_FILENAME:-osquery_4hubble.$ARCH.tar} *" ]
