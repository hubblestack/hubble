# This dockerfile builds the osquery binary and files that will run on majority of current Linux distributions.
# To build the image: docker build -t <image_name> .
# The image can be used to include the needed osquery files in Hubble packaging process.
# To override the name of the tar file pass in OSQUERY_TAR_FILENAME environment variable with the desired value.
# To create the file run the container: docker run -it --rm -v `pwd`:/data <image_name>

FROM ubuntu:18.04

#osquery build start
ENV OSQUERY_BUILD_USER=osquerybuilder
ENV OSQUERY_GIT_URL=https://github.com/osquery/osquery.git
ENV OSQUERY_SRC_VERSION=4.3.0

#building osquery requires osquery-toolchain and cmake
#make sure osquery-toolchain is compatible with the osquery version you want to build
ENV OSQUERY_TOOLCHAIN_SRC_URL=https://github.com/osquery/osquery-toolchain/releases/download/1.1.0/osquery-toolchain-1.1.0-x86_64.tar.xz
ENV OSQUERY_TOOLCHAIN_SRC_SHA256=9cc3980383e0626276d3762af60035f36ada5886389a1292774e89db013a2353
ENV CMAKE_SRC_URL=https://github.com/Kitware/CMake/releases/download/v3.14.6/cmake-3.14.6-Linux-x86_64.tar.gz
ENV CMAKE_SRC_SHA256=82e08e50ba921035efa82b859c74c5fbe27d3e49a4003020e3c77618a4e912cd
#prepare the requirements for building
RUN apt-get -y update && apt-get -y upgrade \
 && apt-get -y install --no-install-recommends wget ca-certificates xz-utils git python3 bison flex make \
 && apt-get clean && rm -rf /var/lib/apt/lists/* \
 && useradd --shell /bin/bash --create-home --user-group "$OSQUERY_BUILD_USER"

RUN wget -q "$OSQUERY_TOOLCHAIN_SRC_URL" -O osquery-toolchain-x86_64.tar.xz \
 && echo "$OSQUERY_TOOLCHAIN_SRC_SHA256 osquery-toolchain-x86_64.tar.xz" | sha256sum -c - \
 && tar xf osquery-toolchain-x86_64.tar.xz -C /usr/local \
 && wget -q "$CMAKE_SRC_URL" -O cmake-Linux-x86_64.tar.gz \
 && echo "$CMAKE_SRC_SHA256 cmake-Linux-x86_64.tar.gz" | sha256sum -c - \
 && tar xf cmake-Linux-x86_64.tar.gz -C /usr/local --strip 1 

USER $OSQUERY_BUILD_USER

RUN cd /home/"$OSQUERY_BUILD_USER" \
 && git clone "$OSQUERY_GIT_URL" \
 && cd osquery/ \
 && git checkout "$OSQUERY_SRC_VERSION" \
 && mkdir build \
 && cd build \
 && cmake -DOSQUERY_TOOLCHAIN_SYSROOT=/usr/local/osquery-toolchain .. \
#adjust j to number of cores available for building
 && cmake --build . -j4 \
 && /usr/local/osquery-toolchain/usr/bin/strip osquery/osqueryd

USER root

#collect all files and prepare them into a tar file
RUN mkdir -p /opt/osquery/lenses /opt/osquery/yara /opt/osquery/extensions \
 && cp /home/"$OSQUERY_BUILD_USER"/osquery/build/osquery/osqueryd /opt/osquery/hubble_osqueryd \
 && cp /home/"$OSQUERY_BUILD_USER"/osquery/build/osquery/osqueryd /opt/osquery/osqueryi \
 && cp -r /home/"$OSQUERY_BUILD_USER"/osquery/libraries/cmake/source/augeas/src/lenses /opt/osquery/ \
 && rm -rf /opt/osquery/lenses/tests/ \
 && chown -R root. /opt/osquery \
 && chmod -R 500 /opt/osquery/*

CMD [ "/bin/bash", "-c", "cd /opt/osquery ; tar -cvf /data/${OSQUERY_TAR_FILENAME:-osquery_4hubble.tar} *" ]
