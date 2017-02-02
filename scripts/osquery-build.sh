# Building osquery
mkdir -p temp
cd temp
git clone https://github.com/facebook/osquery.git
cd osquery
make sysprep
make deps
make
sudo mv ./build/linux/osquery /opt/
sudo chown -R root. /opt/osquery
cd ../../
sudo cp ../conf/osquery.conf /etc/osquery/
sudo cp ../conf/osquery.flags /etc/osquery/
#rm -rf temp
