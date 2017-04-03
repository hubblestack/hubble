# Don't try fancy stuff like debuginfo, which is useless on binary-only
# packages. Don't strip binary too
# Be sure buildpolicy set to do nothing
%define        __spec_install_post %{nil}
%define          debug_package %{nil}
%define        __os_install_post %{_dbpath}/brp-compress
# Don't fail out because we're not packaging the other distro's service files
%define        _unpackaged_files_terminate_build 0

Summary: Hubblestack is a module, open-source security compliance framework
Name: hubblestack
Version: 2.1.6
Release: 1
License: Apache 2.0
Group: Development/Tools
SOURCE0: %{name}-%{version}.tar.gz
URL: https://hubblestack.io
Autoreq: 0
Requires: git

BuildRoot: %{_tmppath}/%{name}-%{version}-%{release}-root

%description
%{summary}

%prep
%setup -q

%build
# Empty section.

%install
rm -rf %{buildroot}
mkdir -p  %{buildroot}
mkdir -p  %{buildroot}/usr/bin
ln -s /opt/hubble/hubble %{buildroot}/usr/bin/hubble
ln -s /opt/osquery/osqueryi %{buildroot}/usr/bin/osqueryi
ln -s /opt/osquery/osqueryd %{buildroot}/usr/bin/osqueryd

# in builddir
cp -a * %{buildroot}


%clean
rm -rf %{buildroot}


%files
%config(noreplace) /etc/hubble/hubble
%config /etc/osquery/osquery.conf
%config /etc/osquery/osquery.flags
/opt/*
/usr/bin/*
/usr/lib/*

%changelog
* Mon Apr 3 2017  Colton Myers <colton.myers@gmail.com> 2.1.6-1
- Fix pulsar loading
- Fix splay in scheduler

* Wed Mar 22 2017  Colton Myers <colton.myers@gmail.com> 2.1.5-1
- Reduce fileserver frequency by default
- Fix pidfile management
- Add %config macros
- Multi-endpoint support in splunk returners

* Tue Mar 7 2017  Colton Myers <colton.myers@gmail.com> 2.1.4-1
- Consolidate pillar and allow for multiple splunk endpoints in splunk returners
- Move output formatting code out of nova modules into hubble.py
- Add error handling for problems in config file

* Tue Feb 28 2017  Colton Myers <colton.myers@gmail.com> 2.1.3-1
- Add Debian packaging
- Add uptime fallback query
- Fix for blank hosts when fqdn doesn't return anything in returners
- Add AWS information to events from splunk returners
- Turn off http_event_collector_debug everywhere

* Mon Feb 13 2017  Colton Myers <colton.myers@gmail.com> 2.1.2-1
- Fix the changelog order

* Mon Feb 13 2017  Colton Myers <colton.myers@gmail.com> 2.1.1-1
- Remove autoreq, add unit files

* Wed Feb 8 2017  Colton Myers <colton.myers@gmail.com> 2.1.0-1
- First Build
