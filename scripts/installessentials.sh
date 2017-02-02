# Installing required packages
apt-get install python-dev libffi-dev libssl-dev libxml2-dev libxslt1-dev libjpeg8-dev zlib1g-dev make cmake python-setuptools gcc -y
easy_install pip

# Creating required directories
mkdir -p /etc/osquery /var/log/osquery /etc/hubble /opt/hubble
