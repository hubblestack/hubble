FROM centos:7
RUN curl -L https://pkg.osquery.io/rpm/GPG | tee /etc/pki/rpm-gpg/RPM-GPG-KEY-osquery \
    && yum-config-manager --add-repo https://pkg.osquery.io/rpm/osquery-s3-rpm.repo \
    && yum-config-manager --enable osquery-s3-rpm
RUN yum install wget git vim python-setuptools net-tools unzip osquery gcc python-devel -y
WORKDIR /root
RUN easy_install pip \
    && pip install -U setuptools
RUN git clone --bare https://github.com/hubblestack/hubble repo
ADD https://github.com/hubblestack/hubble/archive/develop.zip /tmp
RUN unzip /tmp/develop.zip \
    && mv hubble-develop hubble \
    && mv repo hubble/.git
WORKDIR /root/hubble
RUN git init \
    && git pull \
    && git reset HEAD
RUN python setup.py install --force
