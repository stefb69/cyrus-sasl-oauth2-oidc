Name:           cyrus-sasl-oauth2-oidc
Version:        1.0.2
Release:        1%{?dist}
Summary:        OAuth2/OIDC SASL plugin for Cyrus SASL

License:        MIT
URL:            https://github.com/stefb/cyrus-sasl-oauth2-oidc
Source0:        %{name}-%{version}.tar.gz

BuildRequires:  gcc
BuildRequires:  make
BuildRequires:  autoconf
BuildRequires:  automake
BuildRequires:  libtool
BuildRequires:  pkgconfig
BuildRequires:  cyrus-sasl-devel
BuildRequires:  liboauth2-devel
BuildRequires:  cjose-devel
BuildRequires:  jansson-devel
BuildRequires:  libcurl-devel
BuildRequires:  openssl-devel

Requires:       cyrus-sasl
Requires:       liboauth2
Requires:       cjose
Requires:       jansson
Requires:       libcurl
Requires:       openssl-libs

%description
This package provides an OAuth2/OIDC authentication mechanism plugin
for Cyrus SASL. It allows applications using SASL to authenticate
users via OAuth2/OpenID Connect providers.

The plugin supports various OAuth2 flows and integrates seamlessly
with existing SASL-enabled applications like mail servers, LDAP
servers, and other network services.

%prep
%autosetup

%build
autoreconf -fiv
%configure --disable-tests
%make_build

%install
%make_install

%files
%license LICENSE
%doc README.md
%{_libdir}/sasl2/liboauth2.so*
%{_libdir}/sasl2/liboauth2.a
%{_libdir}/sasl2/liboauthbearer.so*
%{_libdir}/sasl2/libxoauth2.so*

%post
/sbin/ldconfig
if systemctl is-active --quiet saslauthd; then
    systemctl restart saslauthd || :
fi

%postun
/sbin/ldconfig
if [ $1 -eq 0 ] && systemctl is-active --quiet saslauthd; then
    systemctl restart saslauthd || :
fi

%changelog
* Thu Feb 27 2026 Stephane Benoit <stefb@wizzz.net> - 1.0.2-1
- Extend fallback config file to support all OAuth2 options
- Fix memory leaks in fallback config (singular/plural forms)
- Secure clearing of client_secret before freeing memory
- Consistent config priority: SASL getopt > fallback > defaults

* Wed Dec 03 2025 Stephane Benoit <stefb@wizzz.net> - 1.0.1-1
- Fix plugin initialization failure with SASL tools
- Add fallback configuration file support (/etc/sasl2/oauth2.conf)
- Detect XOAUTH2 vs OAUTHBEARER authentication type
- Fix liboauth2 >= 2.2.0 API compatibility
- Fix configure.ac API detection for RPM builds

* Mon Aug 12 2024 Stephane Benoit <stephane.benoit@example.com> - 1.0.0-1
- Initial RPM package for cyrus-sasl-oauth2-oidc
- OAuth2/OIDC SASL authentication plugin
- Support for Fedora and RHEL/CentOS via EPEL
