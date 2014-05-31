#
# Copyright (c) 2008 ~ 2010 Samsung Electronics Co., Ltd.
# All rights reserved
#

CMAKE_MINIMUM_REQUIRED(VERSION 2.6)
set(CMAKE_SKIP_BUILD_RPATH true)

#Verbose
INCLUDE_DIRECTORIES(${CMAKE_CURRENT_SOURCE_DIR} ${CMAKE_SOURCE_DIR}/inc)

INCLUDE(FindPkgConfig)
pkg_check_modules(pkgs REQUIRED glib-2.0)

FOREACH(flag ${pkgs_CFLAGS})
	SET(pkgs_CFLAGS_str "${pkgs_CFLAGS_str} ${flag}")
ENDFOREACH(flag)

pkg_check_modules(libpkgs REQUIRED dbus-glib-1 db-util vconf sqlite3 dlog)

FOREACH(flag ${libpkgs_CFLAGS})
	SET(EXTRA_CFLAGS "${EXTRA_CFLAGS} ${flag}")
ENDFOREACH(flag)

SET(comm_dir "${CMAKE_SOURCE_DIR}")
SET(comm_c_src_dir "${comm_dir}")

## Additional flag
SET(EXTRA_CFLAGS "${EXTRA_CFLAGS} -fvisibility=hidden")
SET(EXTRA_CFLAGS "${EXTRA_CFLAGS} -g -Wall")
SET(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} ${EXTRA_CFLAGS}")

###################################################################################################
## for librpm-util.so (library)

add_library(rpm-util STATIC
                ${CMAKE_CURRENT_SOURCE_DIR}/rpm-installer-util.c
                )
set_target_properties(rpm-util PROPERTIES COMPILE_FLAGS "${pkgs_CFLAGS_str}")
target_link_libraries(rpm-util ${libpkg_LDFLAGS})
###################################################################################################

INSTALL(TARGETS
	rpm-util
	DESTINATION lib/rpm-installer
	COMPONENT RuntimeLibraries)
