# Installing required packages
apt-get install python-dev libffi-dev libssl-dev libxml2-dev libxslt1-dev libjpeg8-dev zlib1g-dev make cmake python-setuptools -y
easy_install pip
pip install -r pyinstaller-requirements.txt

# Creating required directories
mkdir -p /etc/osquery /var/log/osquery /etc/hubble /opt/hubble
