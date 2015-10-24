#
# Copyright (c) 2008 ~ 2010 Samsung Electronics Co., Ltd.
# All rights reserved
#

CMAKE_MINIMUM_REQUIRED(VERSION 2.6)
set(CMAKE_SKIP_BUILD_RPATH true)

IF(_APPFW_FEATURE_EXPANSION_PKG_INSTALL)
        ADD_DEFINITIONS("-D_APPFW_FEATURE_EXPANSION_PKG_INSTALL")
ENDIF(_APPFW_FEATURE_EXPANSION_PKG_INSTALL)

#Verbose
INCLUDE_DIRECTORIES(${CMAKE_SOURCE_DIR}/inc ${CMAKE_SOURCE_DIR}/backend/inc ${CMAKE_SOURCE_DIR}/backend/src/inc ${CMAKE_CURRENT_SOURCE_DIR}/inc)

INCLUDE(FindPkgConfig)
pkg_check_modules(pkgs REQUIRED pkgmgr pkgmgr-installer pkgmgr-parser pkgmgr-info pkgmgr-installer-status-broadcast-server security-server vconf sqlite3 dbus-glib-1 glib-2.0 db-util libxml-2.0 app2sd cert-svc
xmlsec1 libprivilege-control capi-appfw-app-manager aul capi-security-privilege-manager capi-system-device minizip capi-appfw-application)

FOREACH(flag ${pkgs_CFLAGS})
	SET(EXTRA_CFLAGS "${EXTRA_CFLAGS} ${flag}")
ENDFOREACH(flag)

pkg_check_modules(libpkgs REQUIRED security-server pkgmgr pkgmgr-installer pkgmgr-parser pkgmgr-info pkgmgr-installer-status-broadcast-server vconf sqlite3 dbus-glib-1 glib-2.0 db-util libxml-2.0 app2sd cert-svc
xmlsec1 libprivilege-control capi-appfw-app-manager aul capi-security-privilege-manager capi-system-device minizip capi-appfw-application)

FOREACH(flag ${libpkgs_CFLAGS})
	SET(EXTRA_CFLAGS "${EXTRA_CFLAGS} ${flag}")
ENDFOREACH(flag)

pkg_check_modules(STATUS pkgmgr-installer-status-broadcast-server pkgmgr pkgmgr-installer pkgmgr-parser libxml-2.0 app2sd pkgmgr-info cert-svc
xmlsec1 libprivilege-control capi-appfw-app-manager aul capi-security-privilege-manager capi-system-device minizip capi-appfw-application)
link_directories (${STATUS_LIBRARY_DIRS})
include_directories (${STATUS_INCLUDE_DIRS})

pkg_check_modules(COMMCLIENT pkgmgr-installer-client)
link_directories (${COMMCLIENT_LIBRARY_DIRS})
include_directories (${COMMCLIENT_INCLUDE_DIRS})

pkg_check_modules(SECURITYSERVER security-server)
link_directories (${SECURITYSERVER_LIBRARY_DIRS})
include_directories (${SECURITYSERVER_INCLUDE_DIRS})

## DEFINITIONS
ADD_DEFINITIONS("-DAPP_DIR=\"${CMAKE_INSTALL_PREFIX}\"")
ADD_DEFINITIONS("-DPACKAGE=\"${PROJECT_NAME}\"")
ADD_DEFINITIONS("-DXMLSEC_CRYPTO_OPENSSL")

SET(common_c_src_dir "${CMAKE_CURRENT_SOURCE_DIR}/../common")

SET(backend_dir "${CMAKE_CURRENT_SOURCE_DIR}/../backend")
SET(backend_inc_dir "${backend_dir}/inc")
SET(backend_c_src_dir "${backend_dir}/src")
SET(backend_c_src_rpm_inc_dir "${backend_dir}/src/rpm/inc")
SET(backend_c_src_coretpk_inc_dir "${backend_dir}/src/coretpk/inc")
SET(backend_script_dir "${backend_dir}/scripts")
SET(SCRIPTS_DIR "${backend_script_dir}")

SET(frontend_dir "${CMAKE_CURRENT_SOURCE_DIR}")
SET(frontend_inc_dir "${frontend_dir}/inc")
SET(frontend_c_src_dir "${frontend_dir}/src")

## Additional flag
SET(EXTRA_CFLAGS "${EXTRA_CFLAGS} -fvisibility=hidden")
SET(EXTRA_CFLAGS "${EXTRA_CFLAGS} -g -Wall -rdynamic")
SET(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} ${EXTRA_CFLAGS}")

####################################################################################################
## for rpm-backend (binary)
SET(rpm-backend_SOURCES ${backend_c_src_dir}/rpm/rpm-installer-core.c ${backend_c_src_dir}/rpm/rpm-installer-tool.c ${backend_c_src_dir}/rpm/rpm-installer.c
						${backend_c_src_dir}/rpm/rpm-installer-signature.c ${backend_c_src_dir}/rpm/rpm-installer-privilege.c
						${backend_c_src_dir}/coretpk/coretpk-installer.c
						${backend_c_src_dir}/coretpk/coretpk-dbus.c
						${backend_c_src_dir}/coretpk/xml-parser/coretpk-parser-hybrid.c
						${backend_c_src_dir}/coretpk/xml-parser/coretpk-parser.c
						${backend_c_src_dir}/vconf/rpm-vconf-intf.c
						${frontend_c_src_dir}/rpm-appcore-intf.c  ${frontend_c_src_dir}/rpm-cmdline.c  
						${common_c_src_dir}/installer-util.c )

SET(rpm-backend_CFLAGS " -I. -I${backend_inc_dir} -I${backend_c_src_rpm_inc_dir} -I${backend_c_src_coretpk_inc_dir} -I${frontend_inc_dir}} ${pkg_CFLAGS}")
SET(rpm-backend_LDFLAGS ${pkgs_LDFLAGS})

ADD_EXECUTABLE(rpm-backend ${rpm-backend_SOURCES})
TARGET_LINK_LIBRARIES(rpm-backend "dl")
TARGET_LINK_LIBRARIES(rpm-backend ${libpkgs_LDFLAGS})
TARGET_LINK_LIBRARIES(rpm-backend ${COMMCLIENT_LIBRARIES})
TARGET_LINK_LIBRARIES(rpm-backend ${APPCODEEFL_LIBRARIES})
TARGET_LINK_LIBRARIES(rpm-backend ${SECURITYSERVER_LIBRARIES})
TARGET_LINK_LIBRARIES(rpm-backend ${STATUS_LIBRARIES})

SET_TARGET_PROPERTIES(rpm-backend PROPERTIES COMPILE_FLAGS "${rpm-backend_CFLAGS} -fPIE")
SET_TARGET_PROPERTIES(rpm-backend PROPERTIES LINK_FLAGS "-pie")
####################################################################################################

#SET(RESOURCE_DIR "${CMAKE_CURRENT_SOURCE_DIR}/ui/res")

# INSTALL

MESSAGE("${CLEAN_FILE_LIST}")
SET_DIRECTORY_PROPERTIES(PROPERTIES ADDITIONAL_MAKE_CLEAN_FILES "${CLEAN_FILE_LIST}")



###################################################################################################i
configure_file(${backend_script_dir}/install_rpm_package.sh.in ${CMAKE_CURRENT_BINARY_DIR}/install_rpm_package.sh @ONLY)
configure_file(${backend_script_dir}/install_rpm_package_with_dbpath_ro.sh.in ${CMAKE_CURRENT_BINARY_DIR}/install_rpm_package_with_dbpath_ro.sh @ONLY)
configure_file(${backend_script_dir}/install_rpm_package_with_dbpath_rw.sh.in ${CMAKE_CURRENT_BINARY_DIR}/install_rpm_package_with_dbpath_rw.sh @ONLY)
configure_file(${backend_script_dir}/uninstall_rpm_package.sh.in ${CMAKE_CURRENT_BINARY_DIR}/uninstall_rpm_package.sh @ONLY)
configure_file(${backend_script_dir}/upgrade_rpm_package.sh.in ${CMAKE_CURRENT_BINARY_DIR}/upgrade_rpm_package.sh @ONLY)
configure_file(${backend_script_dir}/upgrade_rpm_package_with_dbpath_ro.sh.in ${CMAKE_CURRENT_BINARY_DIR}/upgrade_rpm_package_with_dbpath_ro.sh @ONLY)
configure_file(${backend_script_dir}/upgrade_rpm_package_with_dbpath_rw.sh.in ${CMAKE_CURRENT_BINARY_DIR}/upgrade_rpm_package_with_dbpath_rw.sh @ONLY)
configure_file(${backend_script_dir}/query_rpm_package.sh.in ${CMAKE_CURRENT_BINARY_DIR}/query_rpm_package.sh @ONLY)
configure_file(${backend_script_dir}/cpio_rpm_package.sh.in ${CMAKE_CURRENT_BINARY_DIR}/cpio_rpm_package.sh @ONLY)
configure_file(${backend_script_dir}/cpio_rpm_package_update_xml.sh.in ${CMAKE_CURRENT_BINARY_DIR}/cpio_rpm_package_update_xml.sh @ONLY)
configure_file(${backend_script_dir}/rpm_update_xml.sh.in ${CMAKE_CURRENT_BINARY_DIR}/rpm_update_xml.sh @ONLY)
configure_file(${backend_script_dir}/coretpk_category_converter.sh.in ${CMAKE_CURRENT_BINARY_DIR}/coretpk_category_converter.sh @ONLY)

INSTALL(FILES
                ${CMAKE_CURRENT_BINARY_DIR}/install_rpm_package.sh
                ${CMAKE_CURRENT_BINARY_DIR}/install_rpm_package_with_dbpath_ro.sh
                ${CMAKE_CURRENT_BINARY_DIR}/install_rpm_package_with_dbpath_rw.sh
                ${CMAKE_CURRENT_BINARY_DIR}/uninstall_rpm_package.sh
                ${CMAKE_CURRENT_BINARY_DIR}/upgrade_rpm_package.sh
                ${CMAKE_CURRENT_BINARY_DIR}/upgrade_rpm_package_with_dbpath_ro.sh
                ${CMAKE_CURRENT_BINARY_DIR}/upgrade_rpm_package_with_dbpath_rw.sh
                ${CMAKE_CURRENT_BINARY_DIR}/query_rpm_package.sh
                ${CMAKE_CURRENT_BINARY_DIR}/cpio_rpm_package.sh
                ${CMAKE_CURRENT_BINARY_DIR}/cpio_rpm_package_update_xml.sh
                ${CMAKE_CURRENT_BINARY_DIR}/rpm_update_xml.sh
                ${CMAKE_CURRENT_BINARY_DIR}/coretpk_category_converter.sh
                DESTINATION bin)

INSTALL(FILES ${CMAKE_CURRENT_SOURCE_DIR}/rpm-installer-config.ini DESTINATION /usr/etc)
INSTALL(FILES ${CMAKE_CURRENT_SOURCE_DIR}/coretpk-installer-config.ini DESTINATION /usr/etc)
INSTALL(TARGETS rpm-backend DESTINATION bin PERMISSIONS OWNER_READ OWNER_WRITE OWNER_EXECUTE GROUP_READ GROUP_WRITE)

