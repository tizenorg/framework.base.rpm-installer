/*
 * rpm-installer
 *
 * Copyright (c) 2000 - 2011 Samsung Electronics Co., Ltd. All rights reserved.
 *
 * Contact: Jayoun Lee <airjany@samsung.com>, Sewook Park <sewook7.park@samsung.com>,
 * Jaeho Lee <jaeho81.lee@samsung.com>, Shobhit Srivastava <shobhit.s@samsung.com>
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 */

#ifndef __RPM_INSTALLER_UTIL_H_
#define __RPM_INSTALLER_UTIL_H_

#ifdef __cplusplus
extern "C" {
#endif				/* __cplusplus */

#include <string.h>
#include <stdarg.h>
#include <sys/wait.h>
#include <sys/types.h>
#include <unistd.h>
#include <libgen.h>
#include <wait.h>
#include <stdio.h>

#define RPM_BACKEND_EXEC	"rpm-backend"

#define PKGTYPE "rpm"

/*Error number according to Tizen Native Package Manager Command Specification v1.0*/
#define RPM_INSTALLER_SUCCESS					0
#define RPM_INSTALLER_ERR_WRONG_PARAM				64
#define RPM_INSTALLER_ERR_DBUS_PROBLEM				102
#define RPM_INSTALLER_ERR_PACKAGE_EXIST				121
#define RPM_INSTALLER_ERR_PACKAGE_NOT_INSTALLED			104
#define RPM_INSTALLER_ERR_RESOURCE_BUSY				105
#define RPM_INSTALLER_ERR_NOT_ENOUGH_MEMORY			63
#define RPM_INSTALLER_ERR_NOT_SUPPOTED_VERSION			107
#define RPM_INSTALLER_ERR_NO_RPM_FILE				2
#define RPM_INSTALLER_ERR_DB_ACCESS_FAILED			109
#define RPM_INSTALLER_ERR_RPM_OPERATION_FAILED			110
#define RPM_INSTALLER_ERR_PACKAGE_NOT_UPGRADED			111
#define RPM_INSTALLER_ERR_RPM_SCRIPT_WRONG_ARGS			112
#define RPM_INSTALLER_ERR_NEED_USER_CONFIRMATION		113
#define RPM_INSTALLER_ERR_PACKAGE_INSTALLATION_DISABLED		114
#define RPM_INSTALLER_ERR_PACKAGE_UNINSTALLATION_DISABLED	115
#define RPM_INSTALLER_ERR_CLEAR_DATA_FAILED			116
#define RPM_INSTALLER_ERR_INTERNAL				117
#define RPM_INSTALLER_ERR_PKG_NOT_FOUND				1
#define RPM_INSTALLER_ERR_UNKNOWN				119
#define RPM_INSTALLER_ERR_NO_MANIFEST				11
#define RPM_INSTALLER_ERR_INVALID_MANIFEST			12

#define RPM_INSTALLER_SUCCESS_STR			"Success"
#define RPM_INSTALLER_ERR_WRONG_PARAM_STR		"Wrong Input Param"
#define RPM_INSTALLER_ERR_DBUS_PROBLEM_STR			"DBUS Error"
#define RPM_INSTALLER_ERR_NOT_ENOUGH_MEMORY_STR	"Not Enough Memory"
#define RPM_INSTALLER_ERR_PACKAGE_EXIST_STR	"Package Already Installed"
#define RPM_INSTALLER_ERR_PACKAGE_NOT_INSTALLED_STR	"Package Not Installed"
#define RPM_INSTALLER_ERR_RESOURCE_BUSY_STR			"Resource Busy"
#define RPM_INSTALLER_ERR_UNKNOWN_STR			"Unknown Error"
#define RPM_INSTALLER_ERR_PKG_NOT_FOUND_STR		"Package file not found"
#define RPM_INSTALLER_ERR_NOT_SUPPOTED_VERSION_STR	"Version Not supported"
#define RPM_INSTALLER_ERR_NO_RPM_FILE_STR	"No RPM Package"
#define RPM_INSTALLER_ERR_DB_ACCESS_FAILED_STR	"DB Access Failed"
#define RPM_INSTALLER_ERR_RPM_OPERATION_FAILED_STR	"RPM operation failed"
#define RPM_INSTALLER_ERR_PACKAGE_NOT_UPGRADED_STR	"Package Not Upgraded"
#define RPM_INSTALLER_ERR_RPM_SCRIPT_WRONG_ARGS_STR	"Wrong Args to Script"
#define RPM_INSTALLER_ERR_PACKAGE_INSTALLATION_DISABLED_STR	"Installation Disabled"
#define RPM_INSTALLER_ERR_PACKAGE_UNINSTALLATION_DISABLED_STR	"Uninstallation Disabled"
#define RPM_INSTALLER_ERR_CLEAR_DATA_FAILED_STR		"Clear Data Failed"
#define RPM_INSTALLER_ERR_INTERNAL_STR	"Internal Error"
#define RPM_INSTALLER_ERR_NO_MANIFEST_STR	"Manifest File Not Found"
#define RPM_INSTALLER_ERR_INVALID_MANIFEST_STR	"Manifest Validation Failed"

#define DEBUG_ERR		0x0001
#define DEBUG_INFO		0x0002
#define DEBUG_RESULT	0x0004

#define RPM_LOG	1

	void _print_msg(int type, int exetype, char *format, ...);
#define _d_msg(type, fmtstr, args...) { \
_print_msg(type, RPM_LOG, "%s:%d:%s(): " fmtstr, basename(__FILE__), \
__LINE__, __func__, ##args); \
}

	void _d_msg_init(char *program);
	void _d_msg_deinit();
	void _ri_error_no_to_string(int errnumber, char **errstr);
	int _ri_string_to_error_no(char *errstr);

#ifdef __cplusplus
}
#endif				/* __cplusplus */
#endif				/* __RPM_INSTALLER_UTIL_H_ */
