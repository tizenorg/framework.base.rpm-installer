Name:       rpm-installer
Summary:    Native rpm installer
Version:    0.1.213
Release:    1
Group:      System/Libraries
License:    Apache-2.0
Source0:    %{name}-%{version}.tar.gz
Requires(post): /sbin/ldconfig
Requires(postun): /sbin/ldconfig
BuildRequires:  cmake
BuildRequires:  edje-bin
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
BuildRequires:	pkgconfig(capi-appfw-application)
BuildRequires:	pkgconfig(aul)
BuildRequires:  pkgconfig(openssl)
BuildRequires:  pkgconfig(minizip)
BuildRequires:  gettext-tools
Requires:	cpio

%define appfw_feature_expansion_pkg_install 1
%define appfw_feature_delta_update 1
%define appfw_feature_sysman_mmc 0
%define appfw_feature_mount_install 0

%if "%{?tizen_profile_name}" == "tv"
%define appfw_feature_support_onlycap 0
%define appfw_feature_support_debugmode_for_sdk 0
%define appfw_feature_pkgname_restriction 0
%define appfw_feature_directory_permission_opt_only 1
%else
%define appfw_feature_support_onlycap 1
%define appfw_feature_support_debugmode_for_sdk 1
%define appfw_feature_pkgname_restriction 1
%define appfw_feature_directory_permission_opt_only 0
%endif

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

%if 0%{?appfw_feature_expansion_pkg_install}
_EXPANSION_PKG_INSTALL=ON
%else
_EXPANSION_PKG_INSTALL=OFF
%endif

%if 0%{?appfw_feature_mount_install}
_MOUNT_INSTALL=ON
%else
_MOUNT_INSTALL=OFF
%endif

%if 0%{?appfw_feature_delta_update}
_DELTA_UPDATE=ON
%else
_DELTA_UPDATE=OFF
%endif

%if 0%{?appfw_feature_sysman_mmc}
_SYSMAN_MMC=ON
%else
_SYSMAN_MMC=OFF
%endif

%if 0%{?appfw_feature_support_onlycap}
_SUPPORT_ONLYCAP=ON
%else
_SUPPORT_ONLYCAP=OFF
%endif

%if 0%{?appfw_feature_support_debugmode_for_sdk}
_SUPPORT_DEBUGMODE_FOR_SDK=ON
%else
_SUPPORT_DEBUGMODE_FOR_SDK=OFF
%endif

%if 0%{?appfw_feature_pkgname_restriction}
_APPFW_FEATURE_PKGNAME_RESTRICTION=ON
%endif

%if 0%{?appfw_feature_directory_permission_opt_only}
_APPFW_FEATURE_DIRECTORY_PERMISSION_OPT_ONLY=ON
%else
_APPFW_FEATURE_DIRECTORY_PERMISSION_OPT_ONLY=OFF
%endif


%if "%{?tizen_profile_name}" == "wearable"
export CFLAGS="$CFLAGS -DWEARABLE"
%else
%if "%{?tizen_profile_name}" == "mobile"
export CFLAGS="$CFLAGS -DMOBILE"
%endif

%endif

cmake . -DCMAKE_INSTALL_PREFIX=%{_prefix} \
				-DTIZEN_FULL_VERSION=%{tizen_full_version} \
                -D_APPFW_FEATURE_EXPANSION_PKG_INSTALL:BOOL=${_EXPANSION_PKG_INSTALL} \
				-D_APPFW_FEATURE_DELTA_UPDATE:BOOL=${_DELTA_UPDATE} \
				-D_APPFW_FEATURE_SYSMAN_MMC:BOOL=${_SYSMAN_MMC} \
				-D_APPFW_FEATURE_MOUNT_INSTALL:BOOL=${_MOUNT_INSTALL} \
				-D_APPFW_FEATURE_SUPPORT_DEBUGMODE_FOR_SDK:BOOL=${_SUPPORT_DEBUGMODE_FOR_SDK} \
				-D_APPFW_FEATURE_SUPPORT_ONLYCAP:BOOL=${_SUPPORT_ONLYCAP} \
				-D_APPFW_FEATURE_PKGNAME_RESTRICTION:BOOL=${_APPFW_FEATURE_PKGNAME_RESTRICTION} \
				-D_APPFW_FEATURE_DIRECTORY_PERMISSION_OPT_ONLY:BOOL=${_APPFW_FEATURE_DIRECTORY_PERMISSION_OPT_ONLY}

make %{?jobs:-j%jobs}

%install
rm -rf %{buildroot}
%make_install

mkdir -p %{buildroot}/usr/share/license
cp LICENSE %{buildroot}/usr/share/license/%{name}

%post
mkdir -p /usr/etc/package-manager/backend
mkdir -p /usr/etc/package-manager/backendlib
mkdir -p /usr/etc/package-manager/rpm-installer

ln -sf /usr/bin/rpm-backend /usr/etc/package-manager/backend/rpm
ln -sf /usr/bin/rpm-backend /usr/etc/package-manager/backend/coretpk
ln -sf /usr/lib/libnativerpm.so /usr/etc/package-manager/backendlib/librpm.so
ln -sf /usr/lib/libnativerpm.so /usr/etc/package-manager/backendlib/libcoretpk.so

chmod 700 /usr/bin/rpm-backend

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
%attr(0700,-,-) /usr/bin/coretpk_category_converter.sh
%attr(0700,-,-) /usr/bin/rpm_update_xml.sh
%attr(0744,-,-) /usr/etc/rpm-installer-config.ini
%attr(0744,-,-) /usr/etc/coretpk-installer-config.ini
%attr(0644,-,-) /usr/lib/libnativerpm.so
/usr/share/license/%{name}
