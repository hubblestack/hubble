# Building libgit2
mkdir -p temp
export LIBGIT2=/usr/local/
cd temp
wget https://github.com/libgit2/libgit2/archive/v0.25.0.tar.gz
tar xzf v0.25.0.tar.gz
cd libgit2-0.25.0/
cmake . -DCMAKE_INSTALL_PREFIX=$LIBGIT2
make
make install
export LDFLAGS="-Wl,-rpath='$LIBGIT2/lib',--enable-new-dtags $LDFLAGS"

# Destroying the build directory
cd ../../
#rm -rf temp
