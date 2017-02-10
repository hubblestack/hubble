# Don't try fancy stuff like debuginfo, which is useless on binary-only
# packages. Don't strip binary too
# Be sure buildpolicy set to do nothing
%define        __spec_install_post %{nil}
%define          debug_package %{nil}
%define        __os_install_post %{_dbpath}/brp-compress

Summary: Hubblestack is a module, open-source security compliance framework
Name: hubblestack
Version: 2.1.0
Release: 1
License: Apache 2.0
Group: Development/Tools
SOURCE0: %{name}.tar.gz
URL: https://hubblestack.io
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
%{_sysconfdir}/hubble
%{_sysconfdir}/hubble/hubble
%{_sysconfdir}/osquery
%{_sysconfdir}/osquery/osquery.flags
%{_sysconfdir}/osquery/osquery.conf
%{_sysconfdir}/init.d/hubble
/opt/*
/usr/bin/*

%changelog
* Wed Feb 8 2017  Colton Myers <colton.myers@gmail.com> 2.1.0-1
- First Build
