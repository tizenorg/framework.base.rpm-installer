Name:       rpm-installer
Summary:    Native rpm installer
Version:    0.1.37
Release:    1
Group:      System/Libraries
License:    Apache License, Version 2.0
Source0:    %{name}-%{version}.tar.gz
Requires(post): /sbin/ldconfig
Requires(postun): /sbin/ldconfig
BuildRequires:  cmake
BuildRequires:  edje-bin
BuildRequires:  rpm-devel
BuildRequires:  popt-devel
BuildRequires:  pkgconfig(glib-2.0)
BuildRequires:  pkgconfig(dbus-glib-1)
BuildRequires:  pkgconfig(sqlite3)
BuildRequires:  pkgconfig(dlog)
BuildRequires:  pkgconfig(vconf)
BuildRequires:  pkgconfig(db-util)
BuildRequires:  pkgconfig(pkgmgr-types)
BuildRequires:  pkgconfig(pkgmgr-installer)
BuildRequires:  pkgconfig(pkgmgr-parser)
BuildRequires:  pkgconfig(pkgmgr)
BuildRequires:	pkgconfig(pkgmgr-info)
BuildRequires:  pkgconfig(app2sd)
BuildRequires:  pkgconfig(libxml-2.0)
BuildRequires:  pkgconfig(security-server)
BuildRequires:  pkgconfig(elementary)
BuildRequires:  pkgconfig(appcore-efl)
BuildRequires:  pkgconfig(cert-svc)
BuildRequires:  pkgconfig(xmlsec1)
BuildRequires:  pkgconfig(libxslt)
BuildRequires:  pkgconfig(evas)
BuildRequires:  pkgconfig(ecore)
BuildRequires:  pkgconfig(edje)
BuildRequires:  gettext-tools
Requires:  /bin/cpio

%description
Native rpm installer

%prep
%setup -q

%build
CFLAGS+=" -fpic"

%if 0%{?tizen_build_binary_release_type_eng}
export CFLAGS="$CFLAGS -DTIZEN_ENGINEER_MODE"
export CXXFLAGS="$CXXFLAGS ?DTIZEN_ENGINEER_MODE"
export FFLAGS="$FFLAGS -DTIZEN_ENGINEER_MODE"
%endif

cmake . -DCMAKE_INSTALL_PREFIX=%{_prefix}

make %{?jobs:-j%jobs}

%install
rm -rf %{buildroot}
%make_install

%post
mkdir -p /usr/etc/package-manager/backend
mkdir -p /usr/etc/package-manager/backendlib
ln -sf /usr/bin/rpm-backend /usr/etc/package-manager/backend/rpm
ln -sf /usr/lib/libnativerpm.so /usr/etc/package-manager/backendlib/librpm.so

chmod 700 /usr/bin/rpm-backend

vconftool set -t int db/private/rpm-installer/state "0" -f
vconftool set -t int db/private/rpm-installer/stateinfo "0" -f
vconftool set -t int db/private/rpm-installer/requestinfo/command "0" -f
vconftool set -t string db/private/rpm-installer/requestinfo/pkgname "" -f
vconftool set -t int db/private/rpm-installer/requestinfo/options "0" -f

%files
%manifest rpm-installer.manifest
%attr(0700,-,-) /usr/bin/rpm-backend
%attr(0700,-,-) /usr/bin/install_rpm_package.sh
%attr(0755,-,-) /usr/bin/query_rpm_package.sh
%attr(0700,-,-) /usr/bin/uninstall_rpm_package.sh
%attr(0700,-,-) /usr/bin/upgrade_rpm_package.sh
%attr(0744,-,-) /usr/etc/rpm-installer-config.ini
%attr(0644,-,-) /usr/share/locale/en_GB/LC_MESSAGES/rpm-installer.mo
%attr(0644,-,-) /usr/share/locale/ja_JP/LC_MESSAGES/rpm-installer.mo
%attr(0644,-,-) /usr/share/locale/zh_CN/LC_MESSAGES/rpm-installer.mo
%attr(0644,-,-) /usr/share/locale/en_US/LC_MESSAGES/rpm-installer.mo
%attr(0644,-,-) /usr/share/locale/ko_KR/LC_MESSAGES/rpm-installer.mo
%attr(0644,-,-) /usr/lib/libnativerpm.so
