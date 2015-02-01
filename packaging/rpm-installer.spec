Name:       rpm-installer
Summary:    Native rpm installer
Version:    0.1.146
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
BuildRequires:  pkgconfig(cert-svc)
BuildRequires:  pkgconfig(xmlsec1)
BuildRequires:  pkgconfig(libxslt)
BuildRequires:  pkgconfig(edje)
BuildRequires:	pkgconfig(libprivilege-control)
BuildRequires:  pkgconfig(capi-appfw-app-manager)
BuildRequires:  pkgconfig(capi-security-privilege-manager)
BuildRequires:  pkgconfig(capi-system-device)
BuildRequires:	pkgconfig(aul)
BuildRequires:  pkgconfig(openssl)
BuildRequires:  pkgconfig(minizip)
BuildRequires:  gettext-tools
Requires:  /bin/cpio

%description
Native rpm installer

Requires(post): pkgmgr

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

mkdir -p %{buildroot}/usr/share/license
cp LICENSE %{buildroot}/usr/share/license/%{name}

%post
mkdir -p /usr/etc/package-manager/backend
mkdir -p /usr/etc/package-manager/backendlib
mkdir -p /opt/share/packages/.pkgmgr/rpm-installer/

ln -sf /usr/bin/rpm-backend /usr/etc/package-manager/backend/coretpk
ln -sf /usr/bin/rpm-backend /usr/etc/package-manager/backend/rpm
ln -sf /usr/lib/libnativerpm.so /usr/etc/package-manager/backendlib/librpm.so
ln -sf /usr/lib/libnativerpm.so /usr/etc/package-manager/backendlib/libcoretpk.so

chmod 700 /usr/bin/rpm-backend

vconftool set -t int db/private/rpm-installer/state "0" -f -s system::vconf_inhouse
vconftool set -t int db/private/rpm-installer/stateinfo "0" -f -s system::vconf_inhouse
vconftool set -t int db/private/rpm-installer/requestinfo/command "0" -f -s system::vconf_inhouse
vconftool set -t string db/private/rpm-installer/requestinfo/pkgname "" -f -s system::vconf_inhouse
vconftool set -t int db/private/rpm-installer/requestinfo/options "0" -f -s system::vconf_inhouse

%files
%manifest rpm-installer.manifest
%attr(0700,-,-) /usr/bin/rpm-backend
%attr(0700,-,-) /usr/bin/install_rpm_package.sh
%attr(0700,-,-) /usr/bin/install_rpm_package_with_dbpath_ro.sh
%attr(0700,-,-) /usr/bin/install_rpm_package_with_dbpath_rw.sh
%attr(0755,-,-) /usr/bin/query_rpm_package.sh
%attr(0700,-,-) /usr/bin/uninstall_rpm_package.sh
%attr(0700,-,-) /usr/bin/upgrade_rpm_package.sh
%attr(0700,-,-) /usr/bin/upgrade_rpm_package_with_dbpath_ro.sh
%attr(0700,-,-) /usr/bin/upgrade_rpm_package_with_dbpath_rw.sh
%attr(0700,-,-) /usr/bin/cpio_rpm_package.sh
%attr(0700,-,-) /usr/bin/cpio_rpm_package_update_xml.sh
%attr(0700,-,-) /usr/bin/coretpk_ro_xml_converter.sh
%attr(0700,-,-) /usr/bin/coretpk_rw_xml_converter.sh
%attr(0700,-,-) /usr/bin/coretpk_category_converter.sh
%attr(0700,-,-) /usr/bin/rpm_update_xml.sh
%attr(0744,-,-) /usr/etc/rpm-installer-config.ini
%attr(0744,-,-) /usr/etc/coretpk-installer-config.ini
%attr(0644,-,-) /usr/lib/libnativerpm.so
%attr(0755,-,-) /opt/share/packages/.pkgmgr/rpm-installer/rpm_installer_deactvation_list.txt
/usr/share/license/%{name}
