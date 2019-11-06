%define _unpackaged_files_terminate_build 0
%global  sum Python-based SSO server used by the Software Factory project

Name:    cauth
Version: 0.14.0
Release: 6%{?dist}
Summary: %{sum}

License: ASL 2.0
URL:     https://softwarefactory-project.io/r/p/%{name}
Source0: https://github.com/redhat-cip/%{name}/archive/%{version}.tar.gz
Source1: cauth_logrotate.conf

Obsoletes: python2-cauth

BuildArch: noarch

BuildRequires: python3-pbr
BuildRequires: python3-setuptools

Requires: httpd
Requires: mod_auth_pubtkt
Requires: mod_auth_mellon
Requires: python3-crypto
Requires: python3-sphinx
Requires: python3-sqlalchemy
Requires: python3-future
Requires: python3-ldap
Requires: python3-basicauth
Requires: python3-oic
Requires: python3-pbr
Requires: python3-pecan
Requires: python3-requests
Requires: python3-stevedore
Requires: python3-PyMySQL
Requires: policycoreutils
Requires: python3-jwt
Requires(pre): shadow-utils
Requires:  yaml-cpp
Requires: python3-pyyaml

%description
%{sum}

%prep
%autosetup -n %{name}-%{version}

%build
export PBR_VERSION=%{version}
%{__python3} setup.py build

%install
export PBR_VERSION=%{version}
%{__python3} setup.py install --skip-build --root %{buildroot}
install -d %{buildroot}/%{_var}/www/%{name}
install -d %{buildroot}/%{_var}/log/%{name}
install -d %{buildroot}/%{_var}/lib/%{name}/keys
install -d %{buildroot}/%{_sysconfdir}/logrotate.d
install -p -m 644 %{SOURCE1} %{buildroot}/%{_sysconfdir}/logrotate.d/cauth.conf
install -p -D -m 444 etc/config.py %{buildroot}/%{_sysconfdir}/%{name}/config.py
install -p -D -m 444 cauth/templates/login.html %{buildroot}/%{_sysconfdir}/%{name}/templates/login.html
install -p -D -m 444 app.wsgi %{buildroot}/%{_var}/www/%{name}/app.wsgi

%pre
getent group cauth >/dev/null || groupadd -r cauth
if ! getent passwd cauth >/dev/null; then
    useradd -r -g cauth -G cauth -d %{_sharedstatedir}/cauth -s /sbin/nologin -c "Cauth Daemon" cauth
fi
exit 0

%post
semanage fcontext -a -t httpd_sys_content_t %{buildroot}/%{_sysconfdir}/%{name}
semanage fcontext -a -t httpd_sys_content_t %{buildroot}/%{_var}/www/%{name}
restorecon -rv  %{buildroot}/%{_sysconfdir}/%{name}
restorecon -rv  %{buildroot}/%{_var}/www/%{name}

%files
%doc LICENSE
%{python3_sitelib}/*
%exclude %{python3_sitelib}/*/tests
%attr(0770, apache, apache) %{_var}/lib/%{name}
%attr(0750, apache, apache) %{_var}/log/%{name}
%attr(0770, apache, apache) %{_var}/www/%{name}
%attr(0550, apache, apache) %{_sysconfdir}/%{name}
%attr(0644, root, root) %config(noreplace) %{_sysconfdir}/logrotate.d/cauth.conf
%attr(0444, root, cauth) %config(noreplace) %{_sysconfdir}/cauth/config.py
%attr(0444, root, cauth) %config(noreplace) %{_sysconfdir}/cauth/templates/login.html
%attr(0444, apache, apache) %config(noreplace) %{_var}/www/%{name}/app.wsgi

%changelog
* Wed Nov  6 2019 Tristan Cacqueray <tdecacqu@redhat.com> - 0.14.0-6
- Switch to python3

* Tue Jun 27 2019 Fabien Boucher <fboucher@redhat.com> - 0.14.0-5
- Add missing python-ldap requirements

* Thu May 16 2019 Matthieu Huin <mhuin@redhat.com> - 0.14.0-4
- Add python-crypto

* Wed May 15 2019 Tristan Cacqueray <tdecacqu@redhat.com> - 0.14.0-3
- Add python-crypto

* Thu Mar 21 2019 Matthieu Huin <mhuin@redhat.com> - 0.14.0-2
- Add pyYAML dependency

* Tue Nov 27 2018 Tristan Cacqueray <tdecacqu@redhat.com> - 0.14.0-1
- Remove pygerrit requirements

* Thu Sep 13 2018 Matthieu Huin <mhuin@redhat.com> - 0.7.1-9
- Add python-jwt dependency.

* Sat May 19 2018 Fabien Boucher <fboucher@redhat.com> - 0.7.1-8
- Add missing dependency for python-future.

* Mon May 14 2018 Fabien Boucher <fboucher@redhat.com> - 0.7.1-7
- Remove obsolete MySQL-python dependency.

* Mon May 14 2018 Fabien Boucher <fboucher@redhat.com> - 0.7.1-6
- Add dependency for PyMySQL, still temporary keep MySQL-python
  for CI purpose.

* Mon Apr 16 2018 Matthieu Huin <mhuin@redhat.com> - 0.7.1-5
- Add mod_auth_mellon dependency

* Tue Mar 13 2018 Tristan Cacqueray <tdecacqu@redhat.com> - 0.7.1-4
- Fix /var/log permission
- Remove redmine requirements

* Tue Apr 18 2017 Tristan Cacqueray <tdecacqu@redhat.com> - 0.7.1-3
- Use python-future instead of python2-future

* Mon Mar 6 2017 Nicolas Hicher <nhicher@redhat.com> 0.7.1-2
- Create directories in packages
- Add logrotate config file

* Mon Mar 6 2017 Nicolas Hicher <nhicher@redhat.com> 0.7.1-1
- Initial packaging
