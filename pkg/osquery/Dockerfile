# This dockerfile builds the osquery binary and files that will run on majority of current Linux distributions.
# To build the image: docker build -t <image_name> .
# The image can be used to include the needed osquery files in Hubble packaging process.
# To override the name of the tar file pass in OSQUERY_TAR_FILENAME environment variable with the desired value.
# To create the file run the container: docker run -it --rm -v `pwd`:/data <image_name>

FROM ubuntu:18.04

# prepare the requirements for building
RUN apt-get -y update && apt-get -y upgrade \
 && apt-get -y update && apt-get -y install --no-install-recommends \
    wget ca-certificates xz-utils git python3 bison flex make build-essential openssl libssl-dev \
    ccache cppcheck \
 && apt-get clean && rm -rf /var/lib/apt/lists/*

# osquery build start
ENV OSQUERY_BUILD_USER=osquerybuilder

ENV OSQUERY_GIT_URL=https://github.com/osquery/osquery.git
ENV OSQUERY_SRC_VERSION=4.8.0
ENV CMAKE_SRC_VERSION=3.20.2
ENV CMAKE_URL_SVER=3.20
ENV OSQUERY_TOOLCHAIN_VERSION=1.1.0

# building osquery requires osquery-toolchain and cmake
# make sure osquery-toolchain is compatible with the osquery version you want to build
ENV OSQUERY_TOOLCHAIN_SRC_URL=https://github.com/osquery/osquery-toolchain/releases/download/$OSQUERY_TOOLCHAIN_VERSION/osquery-toolchain-$OSQUERY_TOOLCHAIN_VERSION-XARCHX.tar.xz
ENV CMAKE_BNAME=cmake-$CMAKE_SRC_VERSION
ENV CMAKE_FNAME=$CMAKE_BNAME.tar.gz
ENV CMAKE_SRC_URL=https://cmake.org/files/v$CMAKE_URL_SVER/$CMAKE_FNAME

RUN useradd --shell /bin/bash --create-home --user-group "$OSQUERY_BUILD_USER"

# buildx gives us "TARGETPLATFORM", but we need x86_64/aarch64 rather than linux/amd64 / linux/arm64
# so we just use uname -m

COPY aarch64.sums x86_64.sums /root/

WORKDIR /root

RUN ARCH=$(uname -m) \
  ; OSQUERY_TOOLCHAIN_SRC_URL=$(echo $OSQUERY_TOOLCHAIN_SRC_URL | sed s/XARCHX/$ARCH/) \
  ; set -x \
  ; wget -q "$CMAKE_SRC_URL" \
 && wget -q "$OSQUERY_TOOLCHAIN_SRC_URL" -O osquery-toolchain-$ARCH.tar.xz \
 && sha256sum -c /root/$ARCH.sums \
 && tar -xf osquery-toolchain-$ARCH.tar.xz -C /usr/local \
 && rm osquery-toolchain-$ARCH.tar.xz \
 && tar -xf $CMAKE_FNAME \
 && rm $CMAKE_FNAME

RUN cd $CMAKE_BNAME && ./bootstrap -- -DCMAKE_BUILD_TYPE:STRING=Release \
 && make -j`nproc` \
 && make install \
 && make clean

USER $OSQUERY_BUILD_USER
WORKDIR /home/$OSQUERY_BUILD_USER

RUN git clone "$OSQUERY_GIT_URL" \
 && cd osquery/ \
 && git checkout "$OSQUERY_SRC_VERSION" \
 && mkdir -vp build

WORKDIR /home/$OSQUERY_BUILD_USER/osquery/build

RUN cmake -DOSQUERY_IGNORE_CMAKE_MAX_VERSION_CHECK=TRUE \
          -DOSQUERY_TOOLCHAIN_SYSROOT=/usr/local/osquery-toolchain \
          -DOSQUERY_NO_DEBUG_SYMBOLS=FALSE \
          -DOSQUERY_BUILD_TESTS=OFF \
          -DOSQUERY_BUILD_ROOT_TESTS=OFF \
          -DCPACK_GENERATOR=productbuild ..

RUN cmake --build . -j`nproc`
RUN /usr/local/osquery-toolchain/usr/bin/strip osquery/osqueryd

USER root

# collect all files and prepare them into a tar file
RUN mkdir -p /opt/osquery/lenses /opt/osquery/yara /opt/osquery/extensions \
 && cp /home/"$OSQUERY_BUILD_USER"/osquery/build/osquery/osqueryd /opt/osquery/hubble_osqueryd \
 && cp /home/"$OSQUERY_BUILD_USER"/osquery/build/osquery/osqueryd /opt/osquery/osqueryi \
 && cp -r /home/"$OSQUERY_BUILD_USER"/osquery/libraries/cmake/source/augeas/src/lenses /opt/osquery/ \
 && rm -rf /opt/osquery/lenses/tests/ \
 && chown -R root. /opt/osquery \
 && chmod -R 500 /opt/osquery/*

VOLUME /data
WORKDIR /opt/osquery

CMD [ "/bin/bash", "-c", "tar -cvf /data/${OSQUERY_TAR_FILENAME:-osquery_4hubble.$(uname -m).tar} *" ]
