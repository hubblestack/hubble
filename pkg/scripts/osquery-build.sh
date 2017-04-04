# Building osquery
mkdir -p temp
sudo chown -R $USER. temp
cd temp
if [[ -n "$(python -mplatform | grep debian-7)" && -f ./ncurses-6.0/install/lib/libncursesw.so.6.0 ]]; then
    wget http://ftp.gnu.org/gnu/ncurses/ncurses-6.0.tar.gz
    tar -xzvf ncurses-6.0.tar.gz
    cd ncurses-6.0
    ./configure --prefix=$(pwd)/install --with-shared --enable-widec
    make
    make install
    export LD_LIBRARY_PATH=$(pwd)/install/lib
fi
git clone https://github.com/facebook/osquery.git
cd osquery
git checkout 2.3.2
make sysprep
make deps
SKIP_TESTS=1 make -j 4
make strip
sudo cp -pr ./build/linux/osquery/osqueryi ./build/linux/osquery/osqueryd /opt/osquery
sudo chown -R root. /opt/osquery
cd ../../
sudo cp ../../conf/osquery.conf /etc/osquery/
sudo cp ../../conf/osquery.flags /etc/osquery/
#rm -rf temp
