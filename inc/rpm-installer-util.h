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
#include <dirent.h>
#include <rpm/header.h>
#include <rpm/rpmts.h>
#include <rpm/rpmlib.h>
#include <glib.h>

#include <libxml/parser.h>
#include <libxml/xmlreader.h>
#include <libxml/xmlschemas.h>
#include <pkgmgr-info.h>

#include <dlog.h>

#ifdef	LOG_TAG
#undef	LOG_TAG
#define	LOG_TAG		"rpm-installer"
#endif

#define _LOGE(fmt, arg...) do { \
			fprintf(stderr, "  ## "fmt"\n", ##arg); \
			LOGE(fmt, ##arg); \
		} while (0)

#define _LOGD(fmt, arg...) do { \
			fprintf(stderr, "  ## "fmt"\n", ##arg); \
			LOGD(fmt, ##arg); \
		} while (0)

#define _LOGP(fmt, arg...)	fprintf(stderr, "[coretpk-installer] "fmt"\n", ##arg)

#define RPM_BACKEND_EXEC	"rpm-backend"

#define WGT_CONFIG	"config.xml"
#define SIGNATURE1_XML						"signature1.xml"
#define SIGNATURE2_XML						"signature2.xml"
#define AUTHOR_SIGNATURE_XML				"author-signature.xml"

#define ASCII(s) (const char *)s
#define XMLCHAR(s) (const xmlChar *)s

#define PKG_MAX_LEN		128
#define VERSION_MAX_LEN	11

#define DIRECTORY_PERMISSION_755			0755
#define DIRECTORY_PERMISSION_644			0644
#define FILE_PERMISSION_755					0755
#define FILE_PERMISSION_644					0644

struct pkginfo_t {
	char package_name[PKG_MAX_LEN];
	char version[VERSION_MAX_LEN];
	char client_id[PKG_MAX_LEN];
	char api_version[VERSION_MAX_LEN];
	bool is_custom_clock;
	bool is_widget;
	bool is_preload;
	GList *privileges;
	pkgmgrinfo_install_location install_location;
};
typedef struct pkginfo_t pkginfo;

struct privilegeinfo_t {
	char package_id[PKG_MAX_LEN];
	int visibility;
};
typedef struct privilegeinfo_t privilegeinfo;

#ifndef PATH_MAX
# define PATH_MAX 4096
#endif

#define FREE_AND_STRDUP(from, to) do { \
		if (to) free((void *)to); \
		if (from) to = strdup(from); \
	} while (0)


#define FREE_AND_NULL(ptr) do { \
		if (ptr) { \
			free((void *)ptr); \
			ptr = NULL; \
		} \
	} while (0)


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
#define RPM_INSTALLER_ERR_SIG_NOT_FOUND				21
#define RPM_INSTALLER_ERR_SIG_INVALID					22
#define RPM_INSTALLER_ERR_SIG_VERIFICATION_FAILED				23
#define RPM_INSTALLER_ERR_ROOT_CERT_NOT_FOUND				31
#define RPM_INSTALLER_ERR_CERT_INVALID					32
#define RPM_INSTALLER_ERR_CERTCHAIN_VERIFICATION_FAILED		33
#define RPM_INSTALLER_ERR_NO_CONFIG                                         34
#define RPM_INSTALLER_ERR_INVALID_CONFIG	35
#define RPM_INSTALLER_ERR_CMD_NOT_SUPPORTED	36
#define RPM_INSTALLER_ERR_PRIVILEGE_UNAUTHORIZED	43
#define RPM_INSTALLER_ERR_PRIVILEGE_UNKNOWN	44
#define RPM_INSTALLER_ERR_PRIVILEGE_USING_LEGACY_FAILED	45

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
#define RPM_INSTALLER_ERR_SIG_NOT_FOUND_STR		"Signature Not Found"
#define RPM_INSTALLER_ERR_SIG_INVALID_STR	"Invalid Signature"
#define RPM_INSTALLER_ERR_SIG_VERIFICATION_FAILED_STR	"Signature Verification Failed"
#define RPM_INSTALLER_ERR_ROOT_CERT_NOT_FOUND_STR		"Root Cert Not Found"
#define RPM_INSTALLER_ERR_CERT_INVALID_STR	"Invalid Certificate"
#define RPM_INSTALLER_ERR_CERTCHAIN_VERIFICATION_FAILED_STR	"Certificate Chain Verification Failed"
#define RPM_INSTALLER_ERR_NO_CONFIG_STR		"Config file is not present"
#define RPM_INSTALLER_ERR_INVALID_CONFIG_STR	"Config file is not valid"
#define RPM_INSTALLER_ERR_CMD_NOT_SUPPORTED_STR	"Unsupported Command"
#define RPM_INSTALLER_ERR_PRIVILEGE_UNAUTHORIZED_STR "Unauthorized privilege"
#define RPM_INSTALLER_ERR_PRIVILEGE_UNKNOWN_ERR_STR "Unknown privilege"
#define RPM_INSTALLER_ERR_PRIVILEGE_USING_LEGACY_FAILED_STR "Deprecated privilege"

#define DEBUG_ERR		0x0001
#define DEBUG_INFO		0x0002
#define DEBUG_RESULT	0x0004

#define RPM_LOG	1
#define SIZE_KB	1024
#define BUFF_SZE    1024
#define RPM_INSTALLER_RW_INSTALL_PATH "/opt/usr"
#define DIR_RPM_INSTALLER_APPLICATIONS_TEMP "/tmp/wgt_unzip"
#define RPM_UNZIP "/usr/bin/unzip"
#define DIR_PERMS (S_IRWXU | S_IRGRP | S_IXGRP | S_IROTH | S_IXOTH)
#define DIR_RPM_WGT_SMACK_RULE_OPT "/opt/usr/.wgt/"

	void _ri_error_no_to_string(int errnumber, char **errstr);
	int _ri_recursive_delete_dir(char *dirname);
	int _ri_string_to_error_no(char *errstr);
	int _ri_get_available_free_memory(const char *opt_path, unsigned long *free_mem);
	int  _ri_process_wgt_package(char** pkgid);
	unsigned long  _ri_calculate_file_size(const char *filename);
	int  _ri_wgt_package_extract(char *pkgid);
	int  _ri_stream_config_file(const char* filename, pkginfo *info);
	void _ri_process_config_node(xmlTextReaderPtr reader, pkginfo * info);
	int _verify_wgt_package_signature_files();
	void _ri_remove_wgt_unzip_dir();
	int _ri_xsystem(const char *argv[]);

	int  _get_package_name_from_xml(char* manifest,char** pkgname);
	int  _get_pkgname_from_rpm_name(char* pkgfile,char** pkgname);
	int _child_element(xmlTextReaderPtr reader, int depth);
	char *_ri_basename(char *name);
	int _ri_verify_sig_and_cert(const char *sigfile, int *visibility);
	char* _manifest_to_package(const char* manifest);
	int _rpm_delete_dir(char *dirname);
	unsigned long  _ri_calculate_rpm_size( char* rpm_file);
	int _ri_get_attribute(xmlTextReaderPtr reader,char *attribute, const char **xml_attribute);
#ifdef __cplusplus
}
#endif				/* __cplusplus */
#endif				/* __RPM_INSTALLER_UTIL_H_ */
