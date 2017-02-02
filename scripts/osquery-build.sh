# Building osquery
mkdir -p temp
cd temp
git clone https://github.com/facebook/osquery.git
cd osquery
make sysprep
make deps
make
mv ./build/linux/osquery /opt/
cp conf/osquery.conf /etc/osquery/
cp conf/osquery.flags /etc/osquery/
cd ../../
rm -rf temp
