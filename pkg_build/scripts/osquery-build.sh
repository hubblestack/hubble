# Building osquery
mkdir -p temp
sudo chown -R $USER. temp
cd temp
git clone https://github.com/facebook/osquery.git
cd osquery
make sysprep
make deps
SKIP_TESTS=1 make -j 4
make strip
sudo cp -pr ./build/linux/osquery/osqueryi ./build/linux/osquery/osqueryd /opt/osquery
sudo chown -R root. /opt/osquery
cd ../../
sudo cp ../conf/osquery.conf /etc/osquery/
sudo cp ../conf/osquery.flags /etc/osquery/
#rm -rf temp
