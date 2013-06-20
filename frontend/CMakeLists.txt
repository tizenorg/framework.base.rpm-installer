#
# Copyright (c) 2008 ~ 2010 Samsung Electronics Co., Ltd.
# All rights reserved
#

CMAKE_MINIMUM_REQUIRED(VERSION 2.6)
set(CMAKE_SKIP_BUILD_RPATH true)

#Verbose
INCLUDE_DIRECTORIES(${CMAKE_SOURCE_DIR}/inc ${CMAKE_SOURCE_DIR}/backend/inc ${CMAKE_CURRENT_SOURCE_DIR}/inc)

INCLUDE(FindPkgConfig)
pkg_check_modules(pkgs REQUIRED pkgmgr pkgmgr-installer pkgmgr-parser pkgmgr-info pkgmgr-installer-status-broadcast-server security-server vconf sqlite3 dbus-glib-1 glib-2.0 db-util elementary appcore-efl libxml-2.0 app2sd)

FOREACH(flag ${pkgs_CFLAGS})
	SET(EXTRA_CFLAGS "${EXTRA_CFLAGS} ${flag}")
ENDFOREACH(flag)

pkg_check_modules(libpkgs REQUIRED security-server pkgmgr pkgmgr-installer pkgmgr-parser pkgmgr-info pkgmgr-installer-status-broadcast-server vconf sqlite3 dbus-glib-1 glib-2.0 db-util elementary appcore-efl libxml-2.0 app2sd)

FOREACH(flag ${libpkgs_CFLAGS})
	SET(EXTRA_CFLAGS "${EXTRA_CFLAGS} ${flag}")
ENDFOREACH(flag)

pkg_check_modules(STATUS pkgmgr-installer-status-broadcast-server pkgmgr pkgmgr-installer pkgmgr-parser libxml-2.0 app2sd pkgmgr-info)
link_directories (${STATUS_LIBRARY_DIRS})
include_directories (${STATUS_INCLUDE_DIRS})

pkg_check_modules(COMMCLIENT pkgmgr-installer-client)
link_directories (${COMMCLIENT_LIBRARY_DIRS})
include_directories (${COMMCLIENT_INCLUDE_DIRS})

pkg_check_modules(APPCODEEFL appcore-efl evas ecore edje ecore-input ecore-x)
link_directories (${APPCODEEFL_LIBRARY_DIRS})
include_directories (${APPCODEEFL_INCLUDE_DIRS})

pkg_check_modules(SECURITYSERVER security-server)
link_directories (${SECURITYSERVER_LIBRARY_DIRS})
include_directories (${SECURITYSERVER_INCLUDE_DIRS})

## DEFINITIONS
ADD_DEFINITIONS("-DAPP_DIR=\"${CMAKE_INSTALL_PREFIX}\"")
ADD_DEFINITIONS("-DPACKAGE=\"${PROJECT_NAME}\"")

link_directories ("${STATUS_LIBRARY_DIRS} /usr/lib")
include_directories (${STATUS_INCLUDE_DIRS})
find_library(RPM_LIBRARY rpm "/usr/lib")


SET(backend_dir "${CMAKE_CURRENT_SOURCE_DIR}/../backend")
SET(backend_inc_dir "${backend_dir}/include")
SET(backend_c_src_dir "${backend_dir}/src")
SET(backend_script_dir "${backend_dir}/scripts")
SET(SCRIPTS_DIR "${backend_script_dir}")

SET(frontend_dir "${CMAKE_CURRENT_SOURCE_DIR}")
SET(frontend_inc_dir "${frontend_dir}/inc")
SET(frontend_c_src_dir "${frontend_dir}/src")
SET(frontend_c_ui_src_dir "${frontend_dir}/ui/src")
SET(frontend_c_ui_inc_dir "${frontend_dir}/ui/include")



## Additional flag
SET(EXTRA_CFLAGS "${EXTRA_CFLAGS} -fvisibility=hidden")
SET(EXTRA_CFLAGS "${EXTRA_CFLAGS} -g -Wall -rdynamic")
SET(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} ${EXTRA_CFLAGS}")

####################################################################################################
## for rpm-backend (binary)
SET(rpm-backend_SOURCES ${backend_c_src_dir}/core/rpm-installer-core.c ${backend_c_src_dir}/core/rpm-installer-tool.c ${backend_c_src_dir}/rpm/rpm-installer.c ${backend_c_src_dir}/rpm/rpm-installer-privilege.c ${backend_c_src_dir}/vconf/rpm-vconf-intf.c ${frontend_c_src_dir}/rpm-appcore-intf.c  ${frontend_c_src_dir}/rpm-cmdline.c  ${frontend_c_ui_src_dir}/rpm-homeview.c)

SET(rpm-backend_CFLAGS " -I. -I/usr/include/rpm -I${backend_inc_dir} -I${frontend_inc_dir} -I${frontend_c_ui_inc_dir} ${pkg_CFLAGS}")
SET(rpm-backend_LDFLAGS ${pkgs_LDFLAGS})

ADD_EXECUTABLE(rpm-backend ${rpm-backend_SOURCES})
TARGET_LINK_LIBRARIES(rpm-backend rpm-util "rpm" "rpmio" "dl")
TARGET_LINK_LIBRARIES(rpm-backend ${libpkgs_LDFLAGS})
TARGET_LINK_LIBRARIES(rpm-backend ${COMMCLIENT_LIBRARIES})
TARGET_LINK_LIBRARIES(rpm-backend ${APPCODEEFL_LIBRARIES})
TARGET_LINK_LIBRARIES(rpm-backend ${SECURITYSERVER_LIBRARIES})
TARGET_LINK_LIBRARIES(rpm-backend ${STATUS_LIBRARIES})

SET_TARGET_PROPERTIES(rpm-backend PROPERTIES COMPILE_FLAGS "${rpm-backend_CFLAGS}")
####################################################################################################

#SET(RESOURCE_DIR "${CMAKE_CURRENT_SOURCE_DIR}/ui/res")

# INSTALL

MESSAGE("${CLEAN_FILE_LIST}")
SET_DIRECTORY_PROPERTIES(PROPERTIES ADDITIONAL_MAKE_CLEAN_FILES "${CLEAN_FILE_LIST}")



###################################################################################################i
configure_file(${backend_script_dir}/install_rpm_package.sh.in ${CMAKE_CURRENT_BINARY_DIR}/install_rpm_package.sh @ONLY)
configure_file(${backend_script_dir}/uninstall_rpm_package.sh.in ${CMAKE_CURRENT_BINARY_DIR}/uninstall_rpm_package.sh @ONLY)
configure_file(${backend_script_dir}/upgrade_rpm_package.sh.in ${CMAKE_CURRENT_BINARY_DIR}/upgrade_rpm_package.sh @ONLY)
configure_file(${backend_script_dir}/query_rpm_package.sh.in ${CMAKE_CURRENT_BINARY_DIR}/query_rpm_package.sh @ONLY)

INSTALL(FILES
                ${CMAKE_CURRENT_BINARY_DIR}/install_rpm_package.sh
                ${CMAKE_CURRENT_BINARY_DIR}/uninstall_rpm_package.sh
                ${CMAKE_CURRENT_BINARY_DIR}/upgrade_rpm_package.sh
                ${CMAKE_CURRENT_BINARY_DIR}/query_rpm_package.sh
                DESTINATION bin)


INSTALL(TARGETS rpm-backend DESTINATION bin PERMISSIONS OWNER_READ OWNER_WRITE OWNER_EXECUTE GROUP_READ GROUP_WRITE)

