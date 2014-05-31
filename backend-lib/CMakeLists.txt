#
# Copyright (c) 2008 ~ 2010 Samsung Electronics Co., Ltd.
# All rights reserved
#

CMAKE_MINIMUM_REQUIRED(VERSION 2.6)
set(CMAKE_SKIP_BUILD_RPATH true)

#Verbose
INCLUDE_DIRECTORIES(${CMAKE_SOURCE_DIR}/inc ${CMAKE_CURRENT_SOURCE_DIR}/inc )

INCLUDE(FindPkgConfig)
pkg_check_modules(pkgs REQUIRED dbus-glib-1 pkgmgr-types vconf)
#pkg_check_modules(pkgs REQUIRED pkgmgr-installer-status-broadcast-server security-server vconf sqlite3 dbus-glib-1 glib-2.0 db-util )

FOREACH(flag ${pkgs_CFLAGS})
	SET(EXTRA_CFLAGS "${EXTRA_CFLAGS} ${flag}")
ENDFOREACH(flag)

pkg_check_modules(libpkgs REQUIRED dbus-glib-1 pkgmgr-types vconf)

FOREACH(flag ${libpkgs_CFLAGS})
	SET(EXTRA_CFLAGS "${EXTRA_CFLAGS} ${flag}")
ENDFOREACH(flag)

pkg_check_modules(STATUS pkgmgr-installer-status-broadcast-server pkgmgr-types vconf)

link_directories ("${STATUS_LIBRARY_DIRS} /usr/lib")
include_directories (${STATUS_INCLUDE_DIRS})
find_library(RPM_LIBRARY rpm "/usr/lib")

SET(backend_lib_dir "${CMAKE_CURRENT_SOURCE_DIR}")
SET(backend_lib_inc_dir "${backend_lib_dir}/inc")
SET(backend_lib_c_src_dir "${backend_lib_dir}/src")

## Additional flag
SET(EXTRA_CFLAGS "${EXTRA_CFLAGS} -fvisibility=hidden")
SET(EXTRA_CFLAGS "${EXTRA_CFLAGS} -g -Wall")
SET(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} ${EXTRA_CFLAGS}")
###################################################################################################
## for backend_lib (binary)
SET(backend_lib_SOURCES ${backend_lib_c_src_dir}/librpminternals.c ${backend_lib_c_src_dir}/librpm.c)
SET(backend_lib_CFLAGS " -I. -I/usr/include/rpm -I${backend_lib_inc_dir} ${pkg_CFLAGS}")
SET(backend_lib_LDFLAGS ${pkgs_LDFLAGS})

ADD_LIBRARY(nativerpm SHARED ${backend_lib_SOURCES})
#TARGET_LINK_LIBRARIES(nativerpm ${RPM_LIB})
TARGET_LINK_LIBRARIES(nativerpm "rpm")
SET_TARGET_PROPERTIES(nativerpm PROPERTIES COMPILE_FLAGS "${backend_lib_CFLAGS}")
####################################################################################################

INSTALL(TARGETS nativerpm DESTINATION lib COMPONENT RuntimeLibraries)

####################################################################################################
