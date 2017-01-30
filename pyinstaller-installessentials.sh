apt-get install python-dev libffi-dev libssl-dev libxml2-dev libxslt1-dev libjpeg8-dev zlib1g-dev
export LIBGIT2=/usr/local/
mkdir temp
cd temp
wget https://github.com/libgit2/libgit2/archive/v0.25.0.tar.gz
tar xzf v0.25.0.tar.gz
cd libgit2-0.25.0/
cmake . -DCMAKE_INSTALL_PREFIX=$LIBGIT2
make
make install
export LDFLAGS="-Wl,-rpath='$LIBGIT2/lib',--enable-new-dtags $LDFLAGS"
cd ../../
rm -rf temp
pip install -r pyinstaller-requirements.txt

