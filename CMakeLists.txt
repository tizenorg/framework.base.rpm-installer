#
# Copyright (c) 2008 ~ 2010 Samsung Electronics Co., Ltd.
# All rights reserved
#

CMAKE_MINIMUM_REQUIRED(VERSION 2.6)
SET(CMAKE_ALLOW_LOOSE_LOOP_CONSTRUCTS true)

PROJECT(rpm-installer C)

SET(PREFIX ${CMAKE_INSTALL_PREFIX})
SET(EXEC_PREFIX "\${prefix}")
SET(LIBDIR "\${prefix}/lib")
SET(INCLUDEDIR "\${prefix}/include")
SET(VERSION 1.0)

set(CMAKE_SKIP_BUILD_RPATH true)

configure_file(rpm_installer_deactvation_list.txt.in rpm_installer_deactvation_list.txt @ONLY)
INSTALL(FILES ${CMAKE_CURRENT_BINARY_DIR}/rpm_installer_deactvation_list.txt DESTINATION /opt/share/packages/.pkgmgr/rpm-installer/)

##################
## build comm libraries
add_subdirectory(common)
add_subdirectory(frontend)
add_subdirectory(po)
add_subdirectory(backend-lib)
##################

