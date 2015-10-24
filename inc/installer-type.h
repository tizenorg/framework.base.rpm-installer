/*
*
* Copyright (c) 2000 - 2011 Samsung Electronics Co., Ltd. All rights reserved.
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

#ifndef	_INSTALLER_TYPE_H_
#define	_INSTALLER_TYPE_H_

#ifdef __cplusplus
extern "C" {
#endif

#include <dlog.h>
#include <glib.h>
#include <sys/stat.h>
#include <pkgmgr-info.h>

#ifdef	LOG_TAG
#undef	LOG_TAG
#define	LOG_TAG		"rpm-installer"
#endif

#define	INSTALLER_VERSION					"20150703.1"

#define BUF_SIZE									4096
#define	SIZE_KB										1024
#define APP_OWNER_ID							5000
#define APP_GROUP_ID							5000
#define TERMINATE_RETRY_COUNT			100
#define MAX_CERT_NUM							9
#define	PKG_MAX_LEN								128
#define	VERSION_MAX_LEN						128
#define	DIRECTORY_PERMISSION_755	0755
#define	DIRECTORY_PERMISSION_644	0644
#define	FILE_PERMISSION_644				0644

#define PERM_BASE									(S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH) // 0644
#define PERM_EXECUTE							(S_IXUSR | S_IXGRP | S_IXOTH)
#define PERM_WRITE								(S_IWUSR | S_IWGRP | S_IWOTH)
#define	DIR_PERMS									(S_IRWXU | S_IRGRP | S_IXGRP | S_IROTH | S_IXOTH)

#define TEMP_DIR													"/opt/usr/rpminstaller"
#define USR_APPS													"/usr/apps"
#define	OPT_USR														"/opt/usr"
#define OPT_USR_APPS											"/opt/usr/apps"
#define USR_SHARE_PACKAGES								"/usr/share/packages"
#define OPT_SHARE_PACKAGES								"/opt/share/packages"
#define USR_PACKAGES										"/usr/packages"
#define OPT_STORAGE_SDCARD								"/opt/storage/sdcard"
#define OPT_STORAGE_SDCARD_APP_ROOT				"/opt/storage/sdcard/apps"
#define CSC_FLAG													"/opt/usr/data/pkgmgr/csc"
#define BIN_DIR_STR												"bin"
#define RES_DIR_STR												"res"
#define SHARED_RES_DIR_STR								"shared/res"

#ifdef _APPFW_FEATURE_MOUNT_INSTALL
#define MIC_ENV													"/tmp/alaunch/-2"
#define PKG_NAME_STRING_LEN_MAX								128
#endif

#define PRELOAD_WATCH_FACE_PATH						"/usr/apps/com.samsung.watchface"

#define CORETPK_XML												"tizen-manifest.xml"
#define	RES_XML										"res/res.xml"

#ifdef _APPFW_FEATURE_DELTA_UPDATE
#define DELTATPK_XML							"delta_info.xml"
#define DELTA_EXTENSION					".delta"
#endif
#define SIGNATURE1_XML										"signature1.xml"
#define	SIGNATURE2_XML										"signature2.xml"
#define AUTHOR_SIGNATURE_XML							"author-signature.xml"
#define	CONFIG_XML												"config.xml"

#define INI_VALUE_SIGNATURE								"signature"
#define INI_VALUE_AUTHOR_SIGNATURE				"author-signature"
#define RDS_DELTA_FILE										".rds_delta"
#define RDS_DELTA_ADD											"#add"
#define RDS_DELTA_DELETE									"#delete"
#define RDS_DELTA_MODIFY									"#modify"

// coretpk
static const int VERSION_ERROR = -1;
static const int VERSION_OLD = 0;
static const int VERSION_SAME = 1;
static const int VERSION_NEW = 2;

#define CORETPK_CATEGORY_CONVERTER				"/usr/bin/coretpk_category_converter.sh"
#define CORETPK_CONFIG_PATH								"/usr/etc/coretpk-installer-config.ini"

#define CORETPK_INSTALL										"coretpk-install"
#define CORETPK_UNINSTALL									"coretpk-uninstall"
#define CORETPK_DIRECTORY_INSTALL					"coretpk-directory-install"
#ifdef _APPFW_FEATURE_DELTA_UPDATE
#define CORETPK_DELTA_INSTALL					"coretpk-delta-install"
#endif
#ifdef _APPFW_FEATURE_MOUNT_INSTALL
#define CORETPK_MOUNT_INSTALL					"coretpk-mount-install"
#endif
#define CORETPK_MOVE											"coretpk-move"
#define CORETPK_REINSTALL									"coretpk-reinstall"
#ifdef _APPFW_FEATURE_EXPANSION_PKG_INSTALL
#define CORETPK_TEP_INSTALL									"coretpk-tep-install"
#endif

// rpm
#define PRE_CHECK_FOR_MANIFEST
#define CPIO_SCRIPT												"/usr/bin/cpio_rpm_package.sh"
#define CPIO_SCRIPT_UPDATE_XML						"/usr/bin/cpio_rpm_package_update_xml.sh"
#define RPM_UPDATE_XML										"/usr/bin/rpm_update_xml.sh"
#define INSTALL_SCRIPT										"/usr/bin/install_rpm_package.sh"
#define INSTALL_SCRIPT_WITH_DBPATH_RO			"/usr/bin/install_rpm_package_with_dbpath_ro.sh"
#define INSTALL_SCRIPT_WITH_DBPATH_RW			"/usr/bin/install_rpm_package_with_dbpath_rw.sh"
#define UNINSTALL_SCRIPT									"/usr/bin/uninstall_rpm_package.sh"
#define UPGRADE_SCRIPT										"/usr/bin/upgrade_rpm_package.sh"
#define UPGRADE_SCRIPT_WITH_DBPATH_RO			"/usr/bin/upgrade_rpm_package_with_dbpath_ro.sh"
#define UPGRADE_SCRIPT_WITH_DBPATH_RW			"/usr/bin/upgrade_rpm_package_with_dbpath_rw.sh"
#define OPT_ZIP_FILE											"/usr/system/RestoreDir/opt.zip"
#define LIBAIL_PATH												"/usr/lib/libail.so.0"
#define	PKGMGR_DB													"/opt/dbspace/.pkgmgr_parser.db"
#define RPM_CONFIG_PATH										"/usr/etc/rpm-installer-config.ini"

#define TEMP_DBPATH														"/opt/usr/rpmdb_tmp"
#define SMACK_RULES_ALT_PATH									"/etc/smack/accesses2.d"
#define RPM																		"/usr/etc/package-manager/backend/rpm"
#define	RPM_UNZIP															"/usr/bin/unzip"
#define	DIR_RPM_WGT_SMACK_RULE_OPT						"/opt/usr/.wgt/"

#define	PKGTYPE_RPM											"rpm"
#define	PKGTYPE_TPK											"tpk"
#define TOKEN_PACKAGE_STR						"package="
#define TOKEN_PATH_STR							"path="
#define TOKEN_OPERATION_STR					"op="
#define TOKEN_REMOVE_STR						"removable="
#define SEPERATOR_END								':'
#define SEPERATOR_START							'"'
#define	EXT_APPDATA_PRIVILEGE_NAME	"http://tizen.org/privilege/externalstorage.appdata"

enum rds_state_type {
	RDS_STATE_NONE,
	RDS_STATE_DELETE,
	RDS_STATE_ADD,
	RDS_STATE_MODIFY,
};

enum rpm_sig_type {
	SIG_AUTH,
	SIG_DIST1,
	SIG_DIST2,
};

enum rpm_sig_sub_type {
	SIG_SIGNER,
	SIG_INTERMEDIATE,
	SIG_ROOT,
};

enum rpm_privilege_level {
    PRIVILEGE_UNKNOWN  = 0,
    PRIVILEGE_PUBLIC   = 1,
    PRIVILEGE_PARTNER  = 2,
    PRIVILEGE_PLATFORM = 3
};

typedef struct cert_chain_t {
	int cert_type;
	char *cert_value;
} cert_chain;

typedef struct pkginfo_t {
	char package_name[PKG_MAX_LEN];
	char version[VERSION_MAX_LEN];
	char client_id[PKG_MAX_LEN];
	char api_version[BUF_SIZE];
	char sig_capath[BUF_SIZE];
	char pkg_chksum[BUF_SIZE];
	bool is_widget;
	bool is_preload;
	bool support_disable;
	GList *privileges;
	pkgmgrinfo_install_location install_location;
} pkginfo;

typedef struct privilegeinfo_t {
	char package_id[PKG_MAX_LEN];
	int visibility;
	GList *privileges;
} privilegeinfo;

typedef struct cmdinfo_t {
	bool support_disable;
	char pkg_chksum[BUF_SIZE];
} cmdinfo;

cert_chain list[MAX_CERT_NUM];

#ifdef _APPFW_FEATURE_DELTA_UPDATE
typedef struct delta_info_t{
	pkginfo *pkg_info;
	GList *add_files_list;
	GList *remove_files_list;
	GList *modify_files_list;
}delta_info;
#endif

// Error number according to Tizen Native Package Manager Command Specification v1.0
#define	RPM_INSTALLER_SUCCESS											0

// 1 -100 : Package command errors
#define RPM_INSTALLER_ERR_PKG_NOT_FOUND									1
#define RPM_INSTALLER_ERR_NO_RPM_FILE									2
#define RPM_INSTALLER_ERR_PACKAGE_INVALID								3
#define RPM_INSTALLER_ERR_NOT_SUPPORTED_API_VERSION						5
#define RPM_INSTALLER_ERR_NO_MANIFEST									11
#define RPM_INSTALLER_ERR_INVALID_MANIFEST								12
#define RPM_INSTALLER_ERR_SIG_NOT_FOUND									21
#define RPM_INSTALLER_ERR_SIG_INVALID									22
#define RPM_INSTALLER_ERR_SIG_VERIFICATION_FAILED						23
#define RPM_INSTALLER_ERR_ROOT_CERT_NOT_FOUND							31
#define RPM_INSTALLER_ERR_CERT_INVALID									32
#define RPM_INSTALLER_ERR_CERTCHAIN_VERIFICATION_FAILED					33
#define RPM_INSTALLER_ERR_NO_CONFIG										34
#define RPM_INSTALLER_ERR_INVALID_CONFIG								35
#define RPM_INSTALLER_ERR_CMD_NOT_SUPPORTED								36
#define RPM_INSTALLER_ERR_CERTIFICATE_EXPIRED							37
#define RPM_INSTALLER_ERR_PRIVILEGE_UNAUTHORIZED						43
#define RPM_INSTALLER_ERR_PRIVILEGE_UNKNOWN								44
#define RPM_INSTALLER_ERR_PRIVILEGE_USING_LEGACY_FAILED					45
#define RPM_INSTALLER_ERR_NOT_ENOUGH_MEMORY								63
#define	RPM_INSTALLER_ERR_WRONG_PARAM									64
#define RPM_INSTALLER_ERR_SIGNATURE_INVALID_CERT_CHAIN					71
#define RPM_INSTALLER_ERR_SIGNATURE_INVALID_DISTRIBUTOR_CERT			72
#define RPM_INSTALLER_ERR_SIGNATURE_INVALID_SDK_DEFAULT_AUTHOR_CERT		73
#define RPM_INSTALLER_ERR_SIGNATURE_IN_DISTRIBUTOR_CASE_AUTHOR_CERT		74
#define RPM_INSTALLER_ERR_SIGNATURE_INVALID_DEVICE_UNIQUE_ID			75
#define RPM_INSTALLER_ERR_SIGNATURE_INVALID_CERT_TIME					76
#define RPM_INSTALLER_ERR_SIGNATURE_INVALID_NO_HASH_FILE				77
#define RPM_INSTALLER_ERR_SIGNATURE_NO_DEVICE_PROFILE					78
#define RPM_INSTALLER_ERR_SIGNATURE_INVALID_HASH_SIGNATURE				79

// 101-120 : reserved for Core installer
#define RPM_INSTALLER_ERR_UNZIP_FAILED									101
#define RPM_INSTALLER_ERR_DBUS_PROBLEM									102
#define RPM_INSTALLER_ERR_PACKAGE_NOT_INSTALLED							104
#define RPM_INSTALLER_ERR_RESOURCE_BUSY									105
#define RPM_INSTALLER_ERR_NOT_SUPPOTED_VERSION							107
#define RPM_INSTALLER_ERR_DB_ACCESS_FAILED								109
#define RPM_INSTALLER_ERR_RPM_OPERATION_FAILED							110
#define RPM_INSTALLER_ERR_PACKAGE_NOT_UPGRADED							111
#define RPM_INSTALLER_ERR_RPM_SCRIPT_WRONG_ARGS							112
#define RPM_INSTALLER_ERR_NEED_USER_CONFIRMATION						113
#define RPM_INSTALLER_ERR_PACKAGE_INSTALLATION_DISABLED					114
#define RPM_INSTALLER_ERR_PACKAGE_UNINSTALLATION_DISABLED				115
#define RPM_INSTALLER_ERR_CLEAR_DATA_FAILED								116
#define RPM_INSTALLER_ERR_INTERNAL										117
#define RPM_INSTALLER_ERR_UNKNOWN										119
#define RPM_INSTALLER_ERR_PACKAGE_EXIST									121


#define RPM_INSTALLER_SUCCESS_STR										"Success"
#define RPM_INSTALLER_ERR_WRONG_PARAM_STR								"Wrong Input Param"
#define RPM_INSTALLER_ERR_DBUS_PROBLEM_STR								"DBUS Error"
#define RPM_INSTALLER_ERR_NOT_ENOUGH_MEMORY_STR							"Not Enough Memory"
#define RPM_INSTALLER_ERR_PACKAGE_EXIST_STR								"Package Already Installed"
#define RPM_INSTALLER_ERR_PACKAGE_NOT_INSTALLED_STR						"Package Not Installed"
#define RPM_INSTALLER_ERR_RESOURCE_BUSY_STR								"Resource Busy"
#define RPM_INSTALLER_ERR_UNKNOWN_STR									"Unknown Error"
#define RPM_INSTALLER_ERR_PKG_NOT_FOUND_STR								"Package file not found"
#define RPM_INSTALLER_ERR_NOT_SUPPOTED_VERSION_STR						"Version Not supported"
#define RPM_INSTALLER_ERR_NO_RPM_FILE_STR								"No RPM Package"
#define RPM_INSTALLER_ERR_DB_ACCESS_FAILED_STR							"DB Access Failed"
#define RPM_INSTALLER_ERR_RPM_OPERATION_FAILED_STR						"RPM operation failed"
#define RPM_INSTALLER_ERR_PACKAGE_NOT_UPGRADED_STR						"Package Not Upgraded"
#define RPM_INSTALLER_ERR_RPM_SCRIPT_WRONG_ARGS_STR						"Wrong Args to Script"
#define RPM_INSTALLER_ERR_PACKAGE_INSTALLATION_DISABLED_STR				"Installation Disabled"
#define RPM_INSTALLER_ERR_PACKAGE_UNINSTALLATION_DISABLED_STR			"Uninstallation Disabled"
#define RPM_INSTALLER_ERR_CLEAR_DATA_FAILED_STR							"Clear Data Failed"
#define RPM_INSTALLER_ERR_INTERNAL_STR									"Internal Error"
#define RPM_INSTALLER_ERR_NO_MANIFEST_STR								"Manifest File Not Found"
#define RPM_INSTALLER_ERR_INVALID_MANIFEST_STR							"Manifest Validation Failed"
#define RPM_INSTALLER_ERR_SIG_NOT_FOUND_STR								"Signature Not Found"
#define RPM_INSTALLER_ERR_SIG_INVALID_STR								"Invalid Signature"
#define RPM_INSTALLER_ERR_SIG_VERIFICATION_FAILED_STR					"Signature Verification Failed"
#define RPM_INSTALLER_ERR_ROOT_CERT_NOT_FOUND_STR						"Root Cert Not Found"
#define RPM_INSTALLER_ERR_CERT_INVALID_STR								"Invalid Certificate"
#define RPM_INSTALLER_ERR_CERTCHAIN_VERIFICATION_FAILED_STR				"Certificate Chain Verification Failed"
#define RPM_INSTALLER_ERR_NO_CONFIG_STR									"Config file is not present"
#define RPM_INSTALLER_ERR_INVALID_CONFIG_STR							"Config file is not valid"
#define RPM_INSTALLER_ERR_CMD_NOT_SUPPORTED_STR							"Unsupported Command"
#define RPM_INSTALLER_ERR_PRIVILEGE_UNAUTHORIZED_STR					"Unauthorized privilege"
#define RPM_INSTALLER_ERR_PRIVILEGE_UNKNOWN_ERR_STR						"Unknown privilege"
#define RPM_INSTALLER_ERR_PRIVILEGE_USING_LEGACY_FAILED_STR				"Deprecated privilege"
#define RPM_INSTALLER_ERR_NOT_SUPPORTED_API_VERSION_STR					"API Version Not supported"
#define	RPM_INSTALLER_ERR_CERTIFICATE_EXPIRED_STR						"Cert Expired"
#define RPM_INSTALLER_ERR_UNZIP_FAILED_STR								"Unzip Failed"
#define RPM_INSTALLER_ERR_PACKAGE_INVALID_STR							"Package Invalid"

#define	ASCII(s)		(const char *)s
#define	XMLCHAR(s)	(const xmlChar *)s

#ifndef FREE_AND_STRDUP
#define	FREE_AND_STRDUP(from, to) do {	\
		if (to) free((void *)to);	\
		if (from) to = strdup(from);	\
} while(0)
#endif

#ifndef FREE_AND_NULL
#define	FREE_AND_NULL(ptr) do {	\
		if (ptr) {	\
			free((void *)ptr);	\
			ptr = NULL;	\
		} \
} while(0)
#endif

#define	_LOGE(fmt, arg...) do {	\
	fprintf(stderr, "  ## "fmt"\n", ##arg);	\
	LOGE(fmt, ##arg);	\
} while(0)

#define	_LOGD(fmt, arg...) do {	\
	fprintf(stderr, "  ## "fmt"\n", ##arg);	\
	LOGD(fmt, ##arg);	\
} while(0)

#define	_SLOGE(fmt, arg...) do {        \
	fprintf(stderr, "  ## "fmt"\n", ##arg); \
	SECURE_LOGE(fmt, ##arg);        \
} while(0)

#define	_SLOGD(fmt, arg...) do {        \
	fprintf(stderr, "  ## "fmt"\n", ##arg); \
	SECURE_LOGD(fmt, ##arg);        \
} while(0)

#define	ret_if(expr) do {	\
	if (expr) {	\
		_LOGE("(%s) ", #expr);	\
		return;	\
	}	\
} while(0)

#define	retm_if(expr, fmt, arg...) do {	\
	if (expr) {	\
		_LOGE("(%s) "fmt, #expr, ##arg);	\
		return;	\
	}	\
} while(0)

#define	retv_if(expr, val) do {	\
	if (expr) {	\
		_LOGE("(%s) ", #expr);	\
		return (val);	\
	}	\
} while(0)

#define	retvm_if(expr, val, fmt, arg...) do {	\
	if (expr) {	\
		_LOGE("(%s) "fmt, #expr, ##arg);	\
		return (val);	\
	}	\
} while(0)

#define	tryvm_if(expr, val, fmt, arg...) do {	\
	if (expr) {	\
		_LOGE("(%s) "fmt, #expr, ##arg);	\
		val;	\
		goto catch;	\
	}	\
} while(0)


#ifdef __cplusplus
}
#endif
#endif	/* _INSTALLER_TYPE_H_ */
