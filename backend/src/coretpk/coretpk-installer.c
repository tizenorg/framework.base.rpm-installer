/*
 * coretpk-installer
 *
 * Copyright (c) 2000 - 2011 Samsung Electronics Co., Ltd. All rights reserved.
 *
 * Contact:
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
#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include <string.h>
#include <stdlib.h>
#include <dirent.h>
#include <dlfcn.h>
#include <unistd.h>
#include <glib.h>
#include <openssl/sha.h>
#include <openssl/evp.h>
#include <vconf.h>
#include <unzip.h>
#include <sys/smack.h>
#include <ctype.h>

#include <pkgmgr_parser.h>
#include <privilege-control.h>
#include <privilege_manager.h>
#include <app_manager.h>
#include <app2ext_interface.h>
#include <package-manager.h>
#include "pkgmgr_parser_resource.h"
#include <app_control.h>
#include <security-server.h>

#include "coretpk-installer-internal.h"
#include "installer-type.h"
#include "installer-util.h"
/* use rpm-installer exceptions */
/* because the logic of coretpk and rpm are similar, use rpm functions. */
#include "rpm-installer.h"
#ifdef _APPFW_FEATURE_EXPANSION_PKG_INSTALL
#include <stdbool.h>

static bool is_tpk_and_tep = false;
#endif
extern pkgmgr_installer *pi;
extern char *sig1_capath;

#ifdef _APPFW_FEATURE_DELTA_UPDATE
#define  DELTA_DIR	 ".patch"
#define  NEW_DIR	 ".new"
#define DELTA_TOOL	"/usr/bin/xdelta3"
#define EXT_STORAGE_PRIVILEGE	"http://tizen.org/privilege/externalstorage"
#endif

int _coretpk_installer_get_group_id(const char *pkgid, char **result);
void _coretpk_installer_set_privilege_setup_path(const char *pkgid, const char *dirpath, app_path_type_t type, const char *label);
#ifdef _APPFW_FEATURE_EXPANSION_PKG_INSTALL
int _coretpk_installer_tep_install(const char *tep_path, int tep_move, const char *clientid);
int _coretpk_installer_tep_uninstall(const char *pkgid);
#endif

int __coretpk_patch_trimmed_api_version(const char *api_version, char **trim_api_version)
{
	char *trim_version = NULL;
	char *ptr = NULL;

	trim_version = strdup(api_version);
	if (trim_version == NULL) {
		_LOGE("out of memory");
		return RPM_INSTALLER_ERR_NOT_ENOUGH_MEMORY;
	}
	ptr = strchr(trim_version, '.');
	if (ptr) {
		ptr = strchr(++ptr, '.');
	}
	if (ptr) {
		if (atoi(++ptr) == 0) {
			*(--ptr) = '\0';
			_LOGD("api_version (%s -> %s)", api_version, trim_version);
		}
	}

	*trim_api_version = trim_version;

	return RPM_INSTALLER_SUCCESS;
}

int __coretpk_patch_padded_api_version(const char *api_version, char **pad_api_version)
{
	char *pad_version = NULL;
	char *ptr_fw = NULL;
	char *ptr_bw = NULL;

	pad_version = strdup(api_version);
	if (pad_version == NULL) {
		_LOGE("out of memory");
		return RPM_INSTALLER_ERR_NOT_ENOUGH_MEMORY;
	}

	ptr_fw = strchr(pad_version, '.');
	ptr_bw = strrchr(pad_version, '.');

	if (ptr_fw && ptr_bw) {
		if (ptr_fw == ptr_bw) {
			pad_version = strncat(pad_version, ".0", BUF_SIZE - strlen(pad_version) - 1);
		}
	}

	*pad_api_version = pad_version;

	return RPM_INSTALLER_SUCCESS;
}

static int __coretpk_compare_with_platform_version(const char *api_version)
{
	char *current_version = NULL;
	int ret = 0;
	int result = 0;

	if (!api_version || strlen(api_version) == 0) {
		_LOGE("Invalid parameter");
		return RPM_INSTALLER_ERR_WRONG_PARAM;
	}

	ret = __coretpk_patch_padded_api_version(api_version, &current_version);
	if (ret != RPM_INSTALLER_SUCCESS) {
		return RPM_INSTALLER_ERR_WRONG_PARAM;
	}

	result = strverscmp(TIZEN_FULL_VERSION, current_version);
	if (result < 0) {
		ret = RPM_INSTALLER_ERR_NOT_SUPPORTED_API_VERSION;
	} else {
		ret = RPM_INSTALLER_SUCCESS;
	}

	FREE_AND_NULL(current_version);

	return ret;
}

static void __terminate_running_app(const char *pkgid)
{
	int ret = -1;
	pkgmgrinfo_pkginfo_h pkghandle = NULL;

	ret = pkgmgrinfo_pkginfo_get_pkginfo(pkgid, &pkghandle);
	if (ret < 0) {
		_LOGE("failed to get the pkginfo handle.");
		return;
	}

	/* terminate running app */
	ret = pkgmgrinfo_appinfo_get_list(pkghandle, PMINFO_UI_APP, __ri_check_running_app, NULL);
	if (ret < 0) {
		_LOGE("failed to get the pkginfo handle.");
	}

	pkgmgrinfo_pkginfo_destroy_pkginfo(pkghandle);
}

static int __get_unzip_size(const char *item, unsigned long long *size)
{
	if (!item || !size) {
		_LOGE("Invalid argument.");
		return PMINFO_R_ERROR;
	}
	int ret = 0;
	unzFile uzf = unzOpen64(item);
	if (uzf == NULL) {
		_LOGE("Fail to open item : %s", item);
		*size = 0;
		return PMINFO_R_ERROR;
	} else {
		ret = unzGoToFirstFile(uzf);
		if (ret != UNZ_OK) {
			_LOGE("error get first zip file ");
			unzClose(uzf);
			*size = 0;
			return PMINFO_R_ERROR;
		} else {
			do {
				ret = unzOpenCurrentFile(uzf);
				if (ret != UNZ_OK) {
					_LOGE("error unzOpenCurrentFile ");
					unzClose(uzf);
					*size = 0;
					return PMINFO_R_ERROR;
				}

				unz_file_info fileInfo = { 0 };
				char *filename = (char *)calloc(1, BUF_SIZE);
				ret = unzGetCurrentFileInfo(uzf, &fileInfo, filename, (BUF_SIZE - 1), NULL, 0, NULL, 0);
				*size = (unsigned long long)fileInfo.uncompressed_size + *size;
				if (ret != UNZ_OK) {
					_LOGE("error get current file info");
					unzCloseCurrentFile(uzf);
					*size = 0;
					break;
				}

				FREE_AND_NULL(filename);
			} while (unzGoToNextFile(uzf) == UNZ_OK);
		}
	}
	unzClose(uzf);

	return PMINFO_R_OK;
}

static int __is_default_external_storage()
{
#ifdef _APPFW_FEATURE_SYSMAN_MMC
	int ret = 0;
	int storage = 0;
	int mmc_status = VCONFKEY_SYSMAN_MMC_REMOVED;

	ret = vconf_get_int("db/setting/default_memory/install_applications", &storage);
	retvm_if(ret != 0, PMINFO_R_ERROR, "vconf_get_int(db/setting/default_memory/install_applications) is failed.");

	if (storage == 1) {
		ret = vconf_get_int(VCONFKEY_SYSMAN_MMC_STATUS, &mmc_status);
		retvm_if(ret != 0, PMINFO_R_ERROR, "vconf_get_int(VCONFKEY_SYSMAN_MMC_STATUS) is failed.");

		if ((mmc_status == VCONFKEY_SYSMAN_MMC_REMOVED) || (mmc_status == VCONFKEY_SYSMAN_MMC_INSERTED_NOT_MOUNTED)) {
			_LOGD("mmc_status is MMC_REMOVED or NOT_MOUNTED.");
		} else {
			_LOGD("mmc_status is MMC_MOUNTED.");
			return PMINFO_R_OK;
		}
	}
#endif

	return PMINFO_R_ERROR;
}

static void __apply_smack_for_mmc(const char *pkgid)
{
	char dirpath[BUF_SIZE] = { '\0' };

	snprintf(dirpath, BUF_SIZE, "%s/%s/.mmc", OPT_USR_APPS, pkgid);
	if (access(dirpath, F_OK) != 0) {
		_LOGE("Cannot access to [%s].", dirpath);
		return;
	}
	memset(dirpath, '\0', BUF_SIZE);

	/* [pkgid]/.mmc/bin */
	snprintf(dirpath, BUF_SIZE, "%s/.mmc/bin", pkgid);
	_coretpk_installer_set_privilege_setup_path((char *)pkgid, dirpath, APP_PATH_PRIVATE, (char *)pkgid);
	memset(dirpath, '\0', BUF_SIZE);

	/* [pkgid]/.mmc/lib */
	snprintf(dirpath, BUF_SIZE, "%s/.mmc/lib", pkgid);
	_coretpk_installer_set_privilege_setup_path((char *)pkgid, dirpath, APP_PATH_PRIVATE, (char *)pkgid);
	memset(dirpath, '\0', BUF_SIZE);

	/* [pkgid]/.mmc/lost+found */
	snprintf(dirpath, BUF_SIZE, "%s/.mmc/lost+found", pkgid);
	_coretpk_installer_set_privilege_setup_path((char *)pkgid, dirpath, APP_PATH_PRIVATE, (char *)pkgid);
	memset(dirpath, '\0', BUF_SIZE);

	/* [pkgid]/.mmc/res */
	snprintf(dirpath, BUF_SIZE, "%s/.mmc/res", pkgid);
	_coretpk_installer_set_privilege_setup_path((char *)pkgid, dirpath, APP_PATH_PRIVATE, (char *)pkgid);
	memset(dirpath, '\0', BUF_SIZE);

	return;
}

static int __pre_upgrade_for_mmc(const char *pkgid, const char *pkgfile, GList **dir_list, app2ext_handle **handle, pkgmgrinfo_installed_storage storage)
{
	int ret = 0;
	unsigned long long archive_size_byte = 0;
	int archive_size_mega = 0;

	if (__is_dir(pkgfile)) {
		_LOGD("skip - directory=[%s]", pkgfile);
		return 0;
	}

	if (storage == PMINFO_INTERNAL_STORAGE) {
		_LOGD("Package[%s] is installed on Device storage\n", pkgid);
		return 0;
	}
	_LOGD("__pre_upgrade start.");

	ret = __get_unzip_size(pkgfile, &archive_size_byte);
	if (ret < 0) {
		_LOGD("Failed to get uncompressed size.");
		return PMINFO_R_ERROR;
	}
	archive_size_mega = archive_size_byte / (1024 * 1024) + 1;
	_LOGD("Uncompressed size is converted from [%lld]bytes to [%d]Mb.", archive_size_byte, archive_size_mega);

	*handle = app2ext_init(APP2EXT_SD_CARD);
	if (*handle == NULL) {
		_LOGE("app2ext_init(%s) failed.", pkgid);
		return PMINFO_R_ERROR;
	}

	if ((&((*handle)->interface) != NULL) &&
		((*handle)->interface.pre_upgrade != NULL) &&
		((*handle)->interface.post_upgrade != NULL) &&
		((*handle)->interface.disable != NULL)) {
		ret = (*handle)->interface.disable(pkgid);
		if (ret != APP2EXT_SUCCESS) {
			_LOGE("Unmount ret[%d]", ret);
		}

		*dir_list = __rpm_populate_dir_list();
		if (*dir_list == NULL) {
			_LOGE("__rpm_populate_dir_list(%s) failed.", pkgid);
			return PMINFO_R_ERROR;
		}

		ret = (*handle)->interface.pre_upgrade(pkgid, *dir_list, archive_size_mega);
		if (ret == APP2EXT_ERROR_MMC_STATUS) {
			_LOGE("@app2xt MMC is not here, go internal\n");
		} else if (ret == APP2EXT_SUCCESS) {
			_LOGD("@pre_upgrade done, go internal\n");
		} else {
			_LOGE("@app2xt pre upgrade API failed (%d)\n", ret);
			return PMINFO_R_ERROR;
		}
	} else {
		_LOGE("handle is not proper.");
		return PMINFO_R_ERROR;
	}

	_LOGD("__pre_upgrade end.");
	return PMINFO_R_OK;
}

static int __post_upgrade_for_mmc(app2ext_handle *handle, const char *pkgid, GList *dir_list, pkgmgrinfo_installed_storage storage)
{
	retvm_if(handle == NULL, RPM_INSTALLER_ERR_WRONG_PARAM, "handle is NULL.");

	if (storage == PMINFO_INTERNAL_STORAGE) {
		_LOGD("Package [%s] is installed on Device storage.", pkgid);
		return 0;
	}
	_LOGD("__post_upgrade start.");

	/* set smack again for .mmc folder */
	__apply_smack_for_mmc(pkgid);
	_LOGD("__apply_smack_for_mmc is completed.");

	if ((handle != NULL) && (handle->interface.post_upgrade != NULL)) {
		__rpm_clear_dir_list(dir_list);
		handle->interface.post_upgrade(pkgid, APP2EXT_STATUS_SUCCESS);
		app2ext_deinit(handle);
	} else {
		_LOGE("handle->interface.post_upgrade is NULL.");
		return PMINFO_R_ERROR;
	}

	_LOGD("__post_upgrade end.");
	return PMINFO_R_OK;
}

static int __pre_install_for_mmc(const char *pkgid, const char *pkgfile, GList **dir_list, app2ext_handle **handle, pkgmgrinfo_install_location location)
{
	int ret = 0;
	unsigned long long archive_size_byte = 0;
	int archive_size_mega = 0;

	if (__is_dir(pkgfile)) {
		_LOGD("skip - directory=[%s]", pkgfile);
		return 0;
	}

	ret = __is_default_external_storage();
	if (ret != 0) {
		_LOGD("Installed storage is internal.");
		return 0;
	}

	if (location == PMINFO_INSTALL_LOCATION_INTERNAL_ONLY) {
		_LOGD("Default storage is SD card but package is internal-only.");
		_LOGD("Install package on Device storage");
		return 0;
	}
	_LOGD("__pre_install start.");

	ret = __get_unzip_size(pkgfile, &archive_size_byte);
	if (ret < 0) {
		_LOGD("Failed to get uncompressed size.");
		return PMINFO_R_ERROR;
	}
	archive_size_mega = archive_size_byte / (1024 * 1024) + 1;
	_LOGD("Uncompressed size is converted from [%lld]bytes to [%d]Mb.", archive_size_byte, archive_size_mega);

	*handle = app2ext_init(APP2EXT_SD_CARD);
	if (*handle == NULL) {
		_LOGE("app2ext_init(%s) failed.", pkgid);
		return PMINFO_R_ERROR;
	}
	if ((&((*handle)->interface) != NULL) && ((*handle)->interface.pre_install != NULL) && ((*handle)->interface.post_install != NULL)
		&& ((*handle)->interface.force_clean != NULL)) {
		ret = (*handle)->interface.force_clean(pkgid);
		if (ret != APP2EXT_SUCCESS) {
			_LOGE("Force clean is failed. pkgid[%s] ret[%d]", pkgid, ret);
			return PMINFO_R_ERROR;
		}
		_LOGD("Force clean is OK");

		*dir_list = __rpm_populate_dir_list();
		if (*dir_list == NULL) {
			_LOGE("__rpm_populate_dir_list(%s) failed.", pkgid);
			return PMINFO_R_ERROR;
		}

		ret = (*handle)->interface.pre_install(pkgid, *dir_list, archive_size_mega);
		if (ret == APP2EXT_ERROR_MMC_STATUS) {
			_LOGE("@app2xt MMC is not here, go internal\n");
		} else if (ret == APP2EXT_SUCCESS) {
			_LOGD("@pre_install done, go internal\n");
		} else {
			_LOGE("@app2xt pre install API failed (%d)\n", ret);
			return PMINFO_R_ERROR;
		}
	} else {
		_LOGE("handle is not proper.");
		return PMINFO_R_ERROR;
	}

	_LOGD("__pre_install end.");
	return PMINFO_R_OK;
}

static int __post_install_for_mmc(app2ext_handle *handle, const char *pkgid, GList *dir_list, int install_status, pkgmgrinfo_install_location location)
{
	retvm_if(handle == NULL, RPM_INSTALLER_ERR_WRONG_PARAM, "handle is NULL.");

	int ret = __is_default_external_storage();
	if (ret != 0) {
		_LOGD("Installed storage is internal.");
		return 0;
	}

	if (location == PMINFO_INSTALL_LOCATION_INTERNAL_ONLY) {
		_LOGD("Package is installed internally");
		return 0;
	}
	_LOGD("__post_install start.");

	/* set smack again for .mmc folder */
	__apply_smack_for_mmc(pkgid);
	_LOGD("__apply_smack_for_mmc is completed.");

	if ((handle != NULL) && (handle->interface.post_install != NULL)) {
		__rpm_clear_dir_list(dir_list);
		handle->interface.post_install(pkgid, install_status);
		app2ext_deinit(handle);
	} else {
		_LOGE("handle->interface.post_install is NULL.");
		return PMINFO_R_ERROR;
	}

	_LOGD("__post_install end.");
	return PMINFO_R_OK;
}

static void __str_trim(char *input)
{
	char *trim_str = input;

	if (input == NULL)
		return;

	while (*input != 0) {
		if (!isspace(*input)) {
			*trim_str = *input;
			trim_str++;
		}
		input++;
	}

	*trim_str = 0;
	return;
}

static int __coretpk_privilege_func(const char *name, void *user_data)
{
	int ret = 0;
	const char *perm[] = { NULL, NULL };
	const char *ug_pkgid = "ui-gadget::client";

	perm[0] = name;

	_LOGD("privilege = [%s]", name);
	_ri_privilege_register_package("ui-gadget::client");

	ret = _ri_privilege_enable_permissions(ug_pkgid, PERM_APP_TYPE_EFL, perm, 1);
	_LOGE("add ug privilege(%s, %s, %d) done.", ug_pkgid, name, ret);

	return ret;
}

static int __ui_gadget_func(const pkgmgrinfo_appinfo_h handle, void *user_data)
{
	int ret = 0;
	bool is_ug = 0;
	char *pkgid = NULL;
	char *exec = NULL;
	char usr_appdir[BUF_SIZE] = { '\0' };

	ret = pkgmgrinfo_appinfo_is_ui_gadget(handle, &is_ug);
	retvm_if(ret < 0, RPM_INSTALLER_ERR_PKG_NOT_FOUND, "Failed to get is_ui_gadget.\n");

	if (is_ug == true) {
		/* get pkgid */
		ret = pkgmgrinfo_appinfo_get_pkgid(handle, &pkgid);
		retvm_if(ret < 0, RPM_INSTALLER_ERR_PKG_NOT_FOUND, "Failed to get pkgid\n");

		_LOGD("[%s] has ui-gadget.", pkgid);

		/* get exec */
		ret = pkgmgrinfo_appinfo_get_exec(handle, &exec);
		retvm_if(ret < 0, RPM_INSTALLER_ERR_PKG_NOT_FOUND, "Failed to get exec\n");

		/* check bin directory */
		snprintf(usr_appdir, BUF_SIZE, "%s/%s/bin", USR_APPS, pkgid);
		if (strstr(exec, usr_appdir)) {
			if (access(usr_appdir, F_OK) != 0) {
				/* permission(755) */
				ret = mkdir(usr_appdir, DIRECTORY_PERMISSION_755);
				if (ret < 0) {
					char buf[BUF_SIZE] = { 0, };
					if( strerror_r(errno, buf, sizeof(buf)) == 0) {
						_LOGE("mkdir(%s) failed. [%d][%s]", usr_appdir, errno, buf);
					}
				}
			}
		}

		/* make symlink to exec */
		const char *ln_argv[] = { "/bin/ln", "-sf", "/usr/bin/ug-client", exec, NULL };
		ret = _ri_xsystem(ln_argv);
		retvm_if(ret < 0, RPM_INSTALLER_ERR_INTERNAL, "Failed to exec ln_argv\n");

		_LOGD("symlink: [%s]->[/usr/bin/ug-client]", exec);

		*(bool *) user_data = true;
	}

	return 0;
}

static int __check_updated_system_package(const char *pkgid)
{
	int ret = 0;
	bool is_update = false;
	bool is_system = false;
	pkgmgrinfo_pkginfo_h pkghandle = NULL;

	ret = pkgmgrinfo_pkginfo_get_pkginfo(pkgid, &pkghandle);
	retvm_if(ret < 0, -1, "pkgmgrinfo_pkginfo_get_pkginfo(%s) failed.", pkgid);

	ret = pkgmgrinfo_pkginfo_is_system(pkghandle, &is_system);
	tryvm_if(ret < 0, ret = -1, "pkgmgrinfo_pkginfo_is_system(%s) failed.", pkgid);

	ret = pkgmgrinfo_pkginfo_is_update(pkghandle, &is_update);
	tryvm_if(ret < 0, ret = -1, "pkgmgrinfo_pkginfo_is_update(%s) failed.", pkgid);

	if (is_system && is_update) {
		_LOGD("pkgid=[%s] is updated system package.", pkgid);
		ret = 1;
	} else {
		_LOGD("pkgid=[%s] is not updated system app.", pkgid);
		ret = -1;
	}

catch:
	pkgmgrinfo_pkginfo_destroy_pkginfo(pkghandle);

	return ret;
}

int __get_error_code_for_cert(int ret)
{
	int error_code = ret;

	switch (ret) {
	case CERT_SVC_ERR_INVALID_NO_DEVICE_PROFILE:
		error_code = RPM_INSTALLER_ERR_SIGNATURE_NO_DEVICE_PROFILE;
		_LOGE("error=[CERT_SVC_ERR_INVALID_NO_DEVICE_PROFILE]");
		break;

	case CERT_SVC_ERR_INVALID_DEVICE_UNIQUE_ID:
		error_code = RPM_INSTALLER_ERR_SIGNATURE_INVALID_DEVICE_UNIQUE_ID;
		_LOGE("error=[CERT_SVC_ERR_INVALID_DEVICE_UNIQUE_ID]");
		break;

	case CERT_SVC_ERR_INVALID_SDK_DEFAULT_AUTHOR_CERT:
		error_code = RPM_INSTALLER_ERR_SIGNATURE_INVALID_SDK_DEFAULT_AUTHOR_CERT;
		_LOGE("error=[CERT_SVC_ERR_INVALID_SDK_DEFAULT_AUTHOR_CERT]");
		break;

	case CERT_SVC_ERR_IN_DISTRIBUTOR_CASE_AUTHOR_CERT:
		error_code = RPM_INSTALLER_ERR_SIGNATURE_IN_DISTRIBUTOR_CASE_AUTHOR_CERT;
		_LOGE("error=[CERT_SVC_ERR_IN_DISTRIBUTOR_CASE_AUTHOR_CERT]");
		break;

	case CERT_SVC_ERR_IN_AUTHOR_CASE_DISTRIBUTOR_CERT:
		error_code = RPM_INSTALLER_ERR_SIGNATURE_INVALID_DISTRIBUTOR_CERT;
		_LOGE("error=[CERT_SVC_ERR_IN_AUTHOR_CASE_DISTRIBUTOR_CERT]");
		break;

	default:
		break;
	}

	if (ret != 0) {
		_LOGE("error_code=[%d]", error_code);
	}

	if (error_code < 0) {
		_LOGE("error=[RPM_INSTALLER_ERR_SIG_VERIFICATION_FAILED]");
		error_code = RPM_INSTALLER_ERR_SIG_VERIFICATION_FAILED;
	}

	return error_code;
}

bool __is_csc_package(const char *pkg_id, char *csc_path)
{
	retvm_if(pkg_id == NULL, false, "pkg_id is NULL.");

	int ret = 0;
	bool csc_package = true;
	char *path = NULL;
	pkgmgrinfo_pkginfo_h handle = NULL;

	ret = pkgmgrinfo_pkginfo_get_pkginfo(pkg_id, &handle);
	tryvm_if(ret != PMINFO_R_OK, csc_package = false, "pkgmgrinfo_pkginfo_get_pkginfo(%s) failed.", pkg_id);

	ret = pkgmgrinfo_pkginfo_get_csc_path(handle, &path);
	tryvm_if(ret != PMINFO_R_OK, csc_package = false, "pkgmgrinfo_pkginfo_get_csc_path(%s) failed.", pkg_id);

	if (path && (strlen(path) > 0)) {
		snprintf(csc_path, BUF_SIZE, "%s:", path);
		_LOGD("csc_path = [%s]", csc_path);
	} else {
		_LOGD("csc_path(%s) is not existed.", pkg_id);
		csc_package = false;
	}

catch:
	if (handle) {
		pkgmgrinfo_pkginfo_destroy_pkginfo(handle);
	}

	return csc_package;
}

void __make_csc_flag(const char *pkg_id)
{
	int ret = 0;
	FILE *file = NULL;
	char flag_path[BUF_SIZE] = { 0, };

	if (access(CSC_FLAG, F_OK) != 0) {
		ret = mkdir(CSC_FLAG, DIRECTORY_PERMISSION_755);
		if (ret < 0) {
			_LOGE("mkdir(%s) failed. [%d][%s]", CSC_FLAG, errno, strerror(errno));
		}
	}

	snprintf(flag_path, BUF_SIZE, "%s/%s", CSC_FLAG, pkg_id);
	_LOGD("flag_path=[%s]", flag_path);

	file = fopen(flag_path, "w");
	tryvm_if(file == NULL, ret = -1, "fopen(%s) failed. [%d][%s]", flag_path, errno, strerror(errno));

	_LOGD("csc flag[%s] is created.", pkg_id);

 catch:
	if (file) {
		fclose(file);
	}

	return;
}

int __remove_updates_csc_package(const char *pkgid, const char *csc_path)
{
	retvm_if(pkgid == NULL, RPM_INSTALLER_ERR_WRONG_PARAM, "pkgid is NULL.");
	retvm_if(csc_path == NULL, RPM_INSTALLER_ERR_WRONG_PARAM, "csc_path is NULL.");

	char *path_str = _installer_util_get_str(csc_path, TOKEN_PATH_STR);
	char *remove_str = _installer_util_get_str(csc_path, TOKEN_REMOVE_STR);

	_LOGD("remove update for csc. path_str=[%s], remove_str=[%s]", path_str, remove_str);

	_coretpk_installer_csc_uninstall(pkgid);
	_coretpk_installer_csc_install(path_str, remove_str, csc_path);

	_ri_broadcast_status_notification(pkgid, PKGTYPE_TPK, "start", "update");

	if (path_str)
		free(path_str);
	if (remove_str)
		free(remove_str);

	_ri_broadcast_status_notification(pkgid, PKGTYPE_TPK, "end", "ok");

	return 0;
}

static int __pkg_remove_update(const char *pkgid)
{
	retvm_if(pkgid == NULL, RPM_INSTALLER_ERR_WRONG_PARAM, "pkgid is NULL.");

	int i = 0;
	int ret = 0;
	char buff[BUF_SIZE] = { 0, };
	char rootpath[BUF_SIZE] = { 0, };
	char tizen_manifest[BUF_SIZE] = { 0, };
	char csc_path[BUF_SIZE] = { 0, };
	char res_xml[BUF_SIZE] = { 0, };
	const char *value = NULL;
	pkgmgrinfo_certinfo_h old_handle = NULL;
	pkgmgrinfo_instcertinfo_h new_handle = NULL;

	snprintf(rootpath, BUF_SIZE, "%s/%s/", OPT_USR_APPS, pkgid);
	snprintf(tizen_manifest, BUF_SIZE, "%s%s", rootpath, CORETPK_XML);

	/* csc */
	if (__is_csc_package(pkgid, csc_path) == true) {
		return __remove_updates_csc_package(pkgid, csc_path);
	}

	/* start */
	_ri_broadcast_status_notification(pkgid, PKGTYPE_TPK, "start", "update");

	/* terminate running app */
	__terminate_running_app(pkgid);

	/* remove dir for clean (/opt/usr/apps/[pkgid]) */
	snprintf(rootpath, BUF_SIZE, "%s/%s/", OPT_USR_APPS, pkgid);
	if (__is_dir(rootpath)) {
		_installer_util_delete_dir(rootpath);
	}

	/* Remove origin rule */
	_ri_privilege_unregister_package(pkgid);

	/* unzip pkg path from factory-reset data */
	memset(rootpath, '\0', BUF_SIZE);
	snprintf(rootpath, BUF_SIZE, "opt/usr/apps/%s/*", pkgid);	// relative path
	const char *pkg_argv[] = { "/usr/bin/unzip", "-oXqq", OPT_ZIP_FILE, rootpath, "-d", "/", NULL };
	ret = _ri_xsystem(pkg_argv);
	if (ret != 0) {
		_LOGE("/usr/bin/unzip(%s) failed.", rootpath);
	}

	_ri_broadcast_status_notification(pkgid, PKGTYPE_TPK, "install_percent", "30");

	/* get preload author certificate */
	ret = pkgmgrinfo_pkginfo_create_certinfo(&old_handle);
	if (ret < 0) {
		_LOGE("failed to create_certinfo.");
		goto end;
	}
	ret = pkgmgrinfo_pkginfo_load_certinfo(pkgid, old_handle);
	if (ret < 0) {
		_LOGE("failed to load_certinfo");
		goto end;
	}
	ret = pkgmgrinfo_create_certinfo_set_handle(&new_handle);
	if (ret < 0) {
		_LOGE("failed to certinfo_set_handle");
		goto end;
	}

	/* remove opt xml */
	snprintf(buff, BUF_SIZE, "%s/%s.xml", OPT_SHARE_PACKAGES, pkgid);
	(void)remove(buff);

	/* updated usr xml */
	memset(buff, '\0', BUF_SIZE);
	snprintf(buff, BUF_SIZE, "%s/%s.xml", USR_SHARE_PACKAGES, pkgid);

	_LOGD("manifest = [%s].", buff);

	ret = pkgmgr_parser_parse_manifest_for_upgrade(buff, NULL);
	if (ret < 0) {
		_LOGE("pkgmgr_parser_parse_manifest_for_upgrade(%s) is failed.", pkgid);
		goto end;
	}
	_LOGD("pkgmgr_parser_parse_manifest_for_upgrade() is ok.");

	snprintf(res_xml, BUF_SIZE, "%s/%s/%s", OPT_USR_APPS, pkgid, RES_XML);
	/* check existance of /opt/usr/apps/pkgid/res/res.xml* for backward compatibility */
	if (access(res_xml, R_OK) == 0) {
		/* validate it */
		ret = pkgmgr_resource_parser_check_xml_validation(res_xml);
		if (ret < 0) {
			_LOGE("pkgmgr_resource_parser_check_xml_validation(%s) failed.", res_xml);
			ret = RPM_INSTALLER_ERR_INTERNAL;
			goto end;
		}
	}

	_ri_broadcast_status_notification(pkgid, PKGTYPE_TPK, "install_percent", "60");

	/* save cert info */
	for (i = 0; i < MAX_CERT_NUM; i++) {
		ret = pkgmgrinfo_pkginfo_get_cert_value(old_handle, i, &value);
		if (ret != 0) {
			_LOGE("failed to get_cert_value");
		}
		if (value) {
			ret = pkgmgrinfo_set_cert_value(new_handle, i, (char *)value);
			if (ret != 0) {
				_LOGE("failed to set_cert_value[%d]", i);
			}
		}
	}
	ret = pkgmgrinfo_save_certinfo(pkgid, new_handle);
	if (ret < 0) {
		_LOGE("failed to save_certinfo");
	}

	/* apply smack for pkg root path */
	memset(buff, '\0', BUF_SIZE);
	snprintf(buff, BUF_SIZE, "%s/%s", OPT_USR_APPS, pkgid);
	_ri_privilege_setup_path(pkgid, buff, PERM_APP_PATH_ANY_LABEL, pkgid);

	/* apply smack for defined directory */
	__rpm_apply_smack((char *)pkgid, 0, NULL);

	/* apply privilege */
	ret = _ri_apply_privilege((char *)pkgid, 0, NULL);
	if (ret != 0) {
		_LOGE("_ri_apply_privilege(%s) failed. ret = [%d]", pkgid, ret);
	} else {
		_LOGD("_ri_apply_privilege(%s) success.", pkgid);
	}

	/* reload smack */
	ret = _ri_smack_reload(pkgid, UPGRADE_REQ);
	if (ret != 0) {
		_LOGE("_ri_smack_reload(%s) failed.", pkgid);
	}

end:
	if (old_handle) {
		pkgmgrinfo_pkginfo_destroy_certinfo(old_handle);
	}

	if (new_handle) {
		pkgmgrinfo_destroy_certinfo_set_handle(new_handle);
	}

	/* finish */
	if (ret != 0) {
		_ri_broadcast_status_notification(pkgid, PKGTYPE_TPK, "end", "fail");
	} else {
		_ri_broadcast_status_notification(pkgid, PKGTYPE_TPK, "install_percent", "100");
		_ri_broadcast_status_notification(pkgid, PKGTYPE_TPK, "end", "ok");
	}

	return ret;
}

static int __verify_pkgid(const char *pkgid)
{
	if (pkgid == NULL || strlen(pkgid) == 0)
		return -1;

	/* Not to allow install package if pkgid contains "../"
	It will cause deletion of upper directory.*/
	if (strstr(pkgid, "..") != NULL)
		return -1;

	if (strstr(pkgid, "/") != NULL)
		return -1;

	if (strstr(pkgid, "~") != NULL)
		return -1;

	return 0;
}

static int __compare_author_public_key(const char *pkgid)
{
	int ret = 0;
	int keyLen = 0;
	const char *value = NULL;
	pkgmgrinfo_certinfo_h handle = NULL;
	CERT_CONTEXT *preload_ctx = NULL;
	CERT_CONTEXT *update_ctx = NULL;

	if (_installer_util_get_configuration_value(INI_VALUE_AUTHOR_SIGNATURE) == 0) {
		_LOGD("config is off. [author]");
		return 0;
	}

	/* get preload author certificate */
	ret = pkgmgrinfo_pkginfo_create_certinfo(&handle);
	if (ret < 0) {
		_LOGE("failed to get cert info.");
		goto end;
	}
	ret = pkgmgrinfo_pkginfo_load_certinfo(pkgid, handle);
	if (ret < 0) {
		_LOGE("failed to load cert info. [%s]", pkgid);
		goto end;
	}
	ret = pkgmgrinfo_pkginfo_get_cert_value(handle, PMINFO_AUTHOR_SIGNER_CERT, &value);
	if (ret < 0 || value == NULL) {
		_LOGE("failed to get cert value.");
		ret = -1;
		goto end;
	}
	preload_ctx = cert_svc_cert_context_init();
	if (!preload_ctx) {
		_LOGE("Failed to init context");
		ret = -1;
		goto end;
	}
	ret = cert_svc_load_buf_to_context(preload_ctx, (unsigned char *)value);
	if (ret != CERT_SVC_ERR_NO_ERROR) {
		_LOGE("Failed to load cert from file : %d", ret);
		ret = -1;
		goto end;
	}
	ret = cert_svc_extract_certificate_data(preload_ctx);
	if (ret != CERT_SVC_ERR_NO_ERROR) {
		_LOGE("Failed to extract certificate data %d", ret);
		ret = -1;
		goto end;
	}
	if (preload_ctx->certDesc->info.pubKey) {
		keyLen = preload_ctx->certDesc->info.pubKeyLen;
		_LOGE("preload public key len : %d", keyLen);
	}

	/* get update author certificate */
	update_ctx = cert_svc_cert_context_init();
	if (!update_ctx) {
		_LOGE("Failed to init context");
		ret = -1;
		goto end;
	}
	ret = cert_svc_load_buf_to_context(update_ctx, (unsigned char *)list[PMINFO_SET_AUTHOR_SIGNER_CERT].cert_value);
	if (ret != CERT_SVC_ERR_NO_ERROR) {
		_LOGE("Failed to load cert from file : %d", ret);
		ret = -1;
		goto end;
	}
	ret = cert_svc_extract_certificate_data(update_ctx);
	if (ret != CERT_SVC_ERR_NO_ERROR) {
		_LOGE("Failed to extract certificate data %d", ret);
		ret = -1;
		goto end;
	}
	if (update_ctx->certDesc->info.pubKey) {
		keyLen = update_ctx->certDesc->info.pubKeyLen;
		_LOGE("update pkg public key len : %d", keyLen);
	}

	/* compare author certificate */
	ret = memcmp(preload_ctx->certDesc->info.pubKey, update_ctx->certDesc->info.pubKey, preload_ctx->certDesc->info.pubKeyLen);
	if (ret != 0) {
		_LOGE("pkgid[%s] has different author_public_key !!", pkgid);
		ret = -1;
		goto end;
	}

end:
	/* destroy cert */
	if (handle)
		pkgmgrinfo_pkginfo_destroy_certinfo(handle);
	if (preload_ctx)
		cert_svc_cert_context_final(preload_ctx);
	if (update_ctx)
		cert_svc_cert_context_final(update_ctx);

	return ret;
}

int _coretpk_installer_remove_db_info(const char *pkgid)
{
	int ret = 0;
	pkgmgrinfo_pkginfo_h handle = NULL;

	ret = pkgmgrinfo_pkginfo_get_pkginfo(pkgid, &handle);
	if (ret < 0) {
		return PMINFO_R_OK;
	}
	ret = pkgmgr_parser_parse_manifest_for_uninstallation(pkgid, NULL);
	tryvm_if(ret < 0, ret = PMINFO_R_ERROR, "pkgmgr_parser_parse_manifest_for_uninstallation is failed, pkgid=[%s]", pkgid);

	_LOGD("Remove db info is OK.");

catch:
	pkgmgrinfo_pkginfo_destroy_pkginfo(handle);

	return ret;
}

int _coretpk_installer_set_smack_label_access(const char *path, const char *label)
{
#ifdef _APPFW_FEATURE_SUPPORT_ONLYCAP
	int res = security_server_label_access(path, label);
#else
	int res = smack_lsetlabel(path, label, SMACK_LABEL_ACCESS);
#endif
	if (res != 0) {
		_LOGE("security_server_label_access(%s) failed[%d] (path:[%s]))", label, res, path);
		return -1;
	} else {
		_LOGD("[smack] set_smack_label, path=[%s], label=[%s]", path, label);
	}

	return 0;
}

int _coretpk_installer_get_smack_label_access(const char *path, char **label)
{
	int res = smack_lgetlabel(path, label, SMACK_LABEL_ACCESS);
	if (res != 0) {
		_LOGE("Error in getting smack ACCESS label failed. result[%d] (path:[%s]))", res, path);
		return -1;
	} else {
		_LOGD("[smack] get_smack_label, path=[%s], label=[%s]", path, *label);
	}

	return 0;
}

int _coretpk_installer_set_smack_label_transmute(const char *path, const char *flag)
{
#ifdef _APPFW_FEATURE_SUPPORT_ONLYCAP
	int res = security_server_label_transmute(path, 1);
#else
	int res = smack_lsetlabel(path, flag, SMACK_LABEL_TRANSMUTE);
#endif
	if (res != 0)
	{
		_LOGE("security_server_label_transmute(%s) failed[%d] (path:[%s]))", flag, res, path);
		return -1;
	}
	return 0;
}

int _coretpk_installer_verify_privilege_list(const char *pkg_id, const pkginfo * pkg_file_info, int visibility)
{
	retvm_if(pkg_id == NULL, RPM_INSTALLER_ERR_WRONG_PARAM, "pkg_id is NULL.");
	retvm_if(pkg_file_info == NULL, RPM_INSTALLER_ERR_WRONG_PARAM, "pkg_file_info is NULL.");

	if (pkg_file_info->privileges == NULL)
		return 0;

	_LOGD("------------------------------------------");
	_LOGD("Verify Privilege");
	_LOGD("------------------------------------------");

	int ret = 0;
	char *error_message = NULL;
	char buf[BUF_SIZE] = {'\0'};

	ret = privilege_manager_verify_privilege(pkg_file_info->api_version, PRVMGR_PACKAGE_TYPE_CORE, pkg_file_info->privileges, visibility, &error_message);

	if (ret != PRVMGR_ERR_NONE) {
		if (!error_message)
			return RPM_INSTALLER_ERR_SIG_VERIFICATION_FAILED;

		if (strstr(error_message, "[DEPRECATED_PRIVILEGE]") != NULL)
			ret = RPM_INSTALLER_ERR_PRIVILEGE_USING_LEGACY_FAILED;
		else if (strstr(error_message, "[NO_EXIST_PRIVILEGE]") != NULL)
			ret = RPM_INSTALLER_ERR_PRIVILEGE_UNKNOWN;
		else if (strstr(error_message, "[MISMATCHED_PRIVILEGE_LEVEL]") != NULL)
			ret = RPM_INSTALLER_ERR_PRIVILEGE_UNAUTHORIZED;
		else {
			_LOGE("Unidentified privilege error : [%s]", error_message);
			ret = RPM_INSTALLER_ERR_SIG_VERIFICATION_FAILED;
		}

		snprintf(buf, BUF_SIZE - 1, "%d:%s", ret, error_message);
		_ri_broadcast_privilege_notification(pkg_id, PKGTYPE_TPK, "error", buf);
	}

	if (error_message) {
		_LOGE("error_message=[%s]", error_message);
		free(error_message);
		error_message = NULL;
	}

	return ret;
}

void _coretpk_installer_search_ui_gadget(const char *pkgid)
{
	int ret = 0;
	bool is_ug_pkg = false;
	pkgmgrinfo_pkginfo_h pkghandle = NULL;

	ret = pkgmgrinfo_pkginfo_get_pkginfo(pkgid, &pkghandle);
	retm_if(ret < 0, "pkgmgrinfo_pkginfo_get_pkginfo(%s) failed.", pkgid);

	/* search ug app */
	ret = pkgmgrinfo_appinfo_get_list(pkghandle, PM_UI_APP, __ui_gadget_func, &is_ug_pkg);
	tryvm_if(ret < 0, ret = RPM_INSTALLER_ERR_INTERNAL, "Fail to get applist");

	/* if there is ug app,  apply privilege */
	if (is_ug_pkg == true) {
		ret = pkgmgrinfo_pkginfo_foreach_privilege(pkghandle, __coretpk_privilege_func, NULL);
		tryvm_if(ret < 0, ret = RPM_INSTALLER_ERR_INTERNAL, "Fail to get privilege list");
	}

catch:
	pkgmgrinfo_pkginfo_destroy_pkginfo(pkghandle);
}

int _coretpk_backend_interface(const char *reqcommand, const ri_frontend_cmdline_arg * data)
{
	if (reqcommand == NULL || data == NULL) {
		_LOGE("reqcommand or data is NULL.");
		return -1;
	}
#ifdef _APPFW_FEATURE_EXPANSION_PKG_INSTALL
	/* '.tep' also gets installed after tpk installation,
	   so to manage progress percentage, 'is_tpk_and_tep' is used */
	is_tpk_and_tep = false;
	if (NULL != data->tep_path) {
		is_tpk_and_tep = true;
	}
#endif

	if (strncmp(reqcommand, CORETPK_INSTALL, strlen(CORETPK_INSTALL)) == 0) {
#ifdef _APPFW_FEATURE_SUPPORT_DEBUGMODE_FOR_SDK
		if (data->debug_mode)
			return _coretpk_installer_prepare_package_install_with_debug(data->pkgid, data->clientid, false, NULL);
		else
#endif
			return _coretpk_installer_prepare_package_install(data->pkgid, data->clientid, false, NULL);
	} else if (strncmp(reqcommand, CORETPK_UNINSTALL, strlen(CORETPK_UNINSTALL)) == 0) {
		return _coretpk_installer_prepare_package_uninstall(data->pkgid);
	} else if (strncmp(reqcommand, CORETPK_DIRECTORY_INSTALL, strlen(CORETPK_DIRECTORY_INSTALL)) == 0) {
		return _coretpk_installer_prepare_preload_install(data->pkgid, data->clientid, NULL);
#ifdef _APPFW_FEATURE_DELTA_UPDATE
	} else if (strncmp(reqcommand, CORETPK_DELTA_INSTALL, strlen(CORETPK_DELTA_INSTALL)) == 0) {
		return _coretpk_installer_prepare_delta_install(data->pkgid, data->clientid);
#endif
#ifdef _APPFW_FEATURE_MOUNT_INSTALL
	} else if (strncmp(reqcommand, CORETPK_MOUNT_INSTALL, strlen(CORETPK_MOUNT_INSTALL)) == 0) {
		return _coretpk_installer_prepare_mount_install(data->pkgid, data->clientid, false, NULL);
#endif
	} else if (strncmp(reqcommand, CORETPK_MOVE, strlen(CORETPK_MOVE)) == 0) {
		return _coretpk_installer_package_move(data->pkgid, data->move_type);
	} else if (strncmp(reqcommand, CORETPK_REINSTALL, strlen(CORETPK_REINSTALL)) == 0) {
		return _coretpk_installer_package_reinstall(data->pkgid, data->clientid);
#ifdef _APPFW_FEATURE_EXPANSION_PKG_INSTALL
	} else if (strncmp(reqcommand, CORETPK_TEP_INSTALL, strlen(CORETPK_TEP_INSTALL)) == 0) {
		return _coretpk_installer_tep_install(data->tep_path, data->tep_move, data->clientid);
#endif
	} else {
		return -1;
	}
}

int _coretpk_installer_verify_signatures(const char *root_path, const char *pkg_id, int *visibility, char *ca_path)
{
	retvm_if(root_path == NULL, RPM_INSTALLER_ERR_WRONG_PARAM, "root_path is NULL.");
	retvm_if(pkg_id == NULL, RPM_INSTALLER_ERR_WRONG_PARAM, "pkg_id is NULL.");

	int ret = 0;
	char signature[BUF_SIZE] = { 0, };

	_LOGD("------------------------------------------");
	_LOGD("Verify Signature");
	_LOGD("------------------------------------------");
	_LOGD("root_path=[%s], pkg_id=[%s]", root_path, pkg_id);

	ret = chdir(root_path);
	if (ret != 0) {
		char buf[BUF_SIZE] = { 0, };
		if( strerror_r(errno, buf, sizeof(buf)) == 0) {
			_LOGE("chdir(%s) failed. [%s]", root_path, buf);
		}
	}

	/* author-signature.xml is mandatory */
	snprintf(signature, BUF_SIZE, "%s/author-signature.xml", root_path);
	tryvm_if(access(signature, F_OK) != 0, ret = RPM_INSTALLER_ERR_SIG_NOT_FOUND, "access(%s) failed.", signature);

	ret = _ri_verify_sig_and_cert(signature, visibility, true, NULL);
	tryvm_if(ret != 0, , "_ri_verify_sig_and_cert(%s) failed.", signature);
	_LOGD("_ri_verify_sig_and_cert(%s) succeed.", signature);

	memset(signature, '\0', BUF_SIZE);

	/* signature1.xml is mandatory */
	snprintf(signature, BUF_SIZE, "%s/signature1.xml", root_path);
	tryvm_if(access(signature, F_OK) != 0, ret = RPM_INSTALLER_ERR_SIG_NOT_FOUND, "access(%s) failed.", signature);

	ret = _ri_verify_sig_and_cert(signature, visibility, true, ca_path);
	tryvm_if(ret != 0, , "_ri_verify_sig_and_cert(%s) failed.", signature);
	_LOGD("_ri_verify_sig_and_cert(%s) succeed.", signature);

catch:
	ret = __get_error_code_for_cert(ret);

	if ((ret != 0) && (_installer_util_get_configuration_value(INI_VALUE_SIGNATURE) == 0)) {
		_LOGD("verify_signatures(%s, %s) failed, but it's ok for config.", root_path, pkg_id);
		ret = 0;
	}

	return ret;
}

pkginfo *_coretpk_installer_get_pkgfile_info(const char *pkgfile, int cmd)
{
	retvm_if(pkgfile == NULL, NULL, "pkgfile is NULL.");

	pkginfo *info = NULL;
	int ret = 0;
	int visibility = 0;
	char cwd[BUF_SIZE] = { 0, };
	char signature_file[BUF_SIZE] = { 0, };
	char tizen_manifest[BUF_SIZE] = { 0, };
	char *temp = NULL;
	char *xmls = "*.xml";
	bool directory_install = false;
	char buf[BUF_SIZE] = { 0, };

	if (__is_dir(pkgfile)) {
		_LOGD("Directory=[%s]", pkgfile);
		directory_install = true;
	}

	if (directory_install == false) {
		temp = getcwd(cwd, BUF_SIZE);
		if ((temp == NULL) || (cwd[0] == '\0')) {
			if( strerror_r(errno, buf, sizeof(buf)) == 0) {
				_LOGE("getcwd() failed. [%d][%s]", errno, buf);
			}
			return NULL;
		}

		ret = mkdir(TEMP_DIR, DIRECTORY_PERMISSION_644);
		if (ret < 0) {
			if (access(TEMP_DIR, F_OK) == 0) {
				_installer_util_delete_dir(TEMP_DIR);
				ret = mkdir(TEMP_DIR, DIRECTORY_PERMISSION_644);
				if (ret < 0) {
					if( strerror_r(errno, buf, sizeof(buf)) == 0) {
						_LOGE("mkdir(%s) failed. [%d][%s]", TEMP_DIR, errno, buf);
					}
					return NULL;
				}
			} else {
				if( strerror_r(errno, buf, sizeof(buf)) == 0) {
					_LOGE("access(%s) failed. [%d][%s]", TEMP_DIR, errno, buf);
				}
				return NULL;
			}
		}

		ret = chdir(TEMP_DIR);
		if (ret != 0) {
			if( strerror_r(errno, buf, sizeof(buf)) == 0) {
				_LOGE("chdir(%s) failed. [%d][%s]", TEMP_DIR, errno, buf);
			}
			goto err;
		}
		_LOGD("TEMP_DIR=[%s]", TEMP_DIR);

		/* extract all the xml files */
		const char *unzip_argv[] = { "/usr/bin/unzip", "-oqq", pkgfile, xmls, "-d", TEMP_DIR, NULL };
		ret = _ri_xsystem(unzip_argv);
		if (ret != 0) {
			_LOGE("cannot find xml files in the package.");
			goto err;
		}

		snprintf(tizen_manifest, BUF_SIZE, "%s/%s", TEMP_DIR, CORETPK_XML);
	} else {
		snprintf(tizen_manifest, BUF_SIZE, "%s/%s", pkgfile, CORETPK_XML);
	}

	if (access(tizen_manifest, F_OK) != 0) {
		_LOGE("manifest file [%s] is not present", tizen_manifest);
		ret = RPM_INSTALLER_ERR_NO_MANIFEST;
		goto err;
	}
	_LOGD("manifest=[%s]", tizen_manifest);

	info = _coretpk_parser_get_manifest_info(tizen_manifest);
	if (info == NULL) {
		_LOGE("_coretpk_parser_get_manifest_info(%s) failed.", tizen_manifest);
		ret = RPM_INSTALLER_ERR_INTERNAL;
		goto err;
	}

	if (__verify_pkgid(info->package_name) != 0) {
		_LOGE("pkgid[%s] verification failed", info->package_name);
		ret = RPM_INSTALLER_ERR_INTERNAL;
		goto err;
	}

	info->is_widget = _coretpk_parser_is_widget(tizen_manifest);

	_LOGD("pkgid=[%s], version=[%s], install_location=[%d]", info->package_name, info->version, info->install_location);

	/* In case of coretpk installation/upgrade, check the privileges before processing the request further. */
	if ((cmd == CORETPK_INSTALL_CMD)
		&& (directory_install == false)) {
		/* If signature is enabled, Get the visibility from signature files. */
		if (_installer_util_get_configuration_value(INI_VALUE_SIGNATURE)) {
			/* signature1.xml is mandatory */
			snprintf(signature_file, BUF_SIZE, "%s/%s", TEMP_DIR, SIGNATURE1_XML);
			if (access(signature_file, F_OK) != 0) {
				_LOGE("[%s] is not present", signature_file);
				ret = RPM_INSTALLER_ERR_SIG_NOT_FOUND;
				goto err;
			}
			ret = _ri_get_visibility_from_signature_file(signature_file, &visibility, true);
			if (ret != 0) {
				_LOGE("Couldnt get visiblity [%d], ret: %d", visibility, ret);
				ret = RPM_INSTALLER_ERR_INTERNAL;
				goto err;
			} else {
				if (sig1_capath != NULL) {
					snprintf(info->sig_capath, BUF_SIZE, "%s", sig1_capath);
					FREE_AND_NULL(sig1_capath);
				}
				_LOGD("visibility : %d\n", visibility);
			}
		}
	}

err:
	_installer_util_delete_dir(TEMP_DIR);

	if (ret != 0) {
		if (info) {
			_installer_util_free_pkg_info(info);
			info = NULL;
		}
	}

	if (cwd[0] != '\0') {
		ret = chdir(cwd);
		if (ret != 0) {
			if( strerror_r(errno, buf, sizeof(buf)) == 0) {
				_LOGE("chdir(%s) failed. [%d][%s]", cwd, errno, buf);
			}
		}
	}

	return info;
}

int _coretpk_installer_apply_file_policy(char *filepath)
{
	int ret = 0;

	if (access(filepath, F_OK) == 0) {
		/* permission(644) */
		ret = chmod(filepath, FILE_PERMISSION_644);
		if (ret != 0) {
			char buf[BUF_SIZE] = { 0, };
			if( strerror_r(errno, buf, sizeof(buf)) == 0) {
				_LOGE("chmod(%s) failed. [%d][%s]", filepath, errno, buf);
			}
		}
	} else {
		_LOGE("skip! empty filepath=[%s]", filepath);
	}

	return 0;
}

int _coretpk_installer_apply_directory_policy(char *dirpath, int mode, bool appowner)
{
	int ret = 0;
	DIR *dir;
	struct dirent entry;
	struct dirent *result;
	char fullpath[BUF_SIZE] = { '\0' };
	char buf[BUF_SIZE] = { 0, };

	if (access(dirpath, F_OK) != 0) {
		_LOGE("skip! empty dirpath=[%s]", dirpath);
		return 0;
	}

	dir = opendir(dirpath);
	if (!dir) {
		if( strerror_r(errno, buf, sizeof(buf)) == 0) {
			_LOGE("opendir(%s) failed. [%d][%s]", dirpath, errno, buf);
		}
		return -1;
	}

	/* permission(755) */
	ret = _coretpk_installer_change_mode(dirpath, DIRECTORY_PERMISSION_755);
	if (ret != 0) {
		_LOGE("_coretpk_installer_change_mode is failed, dirpath=[%s]", dirpath);
	}

	for (ret = readdir_r(dir, &entry, &result); ret == 0 && result != NULL; ret = readdir_r(dir, &entry, &result)) {
		if (strcmp(entry.d_name, ".") == 0) {
			snprintf(fullpath, BUF_SIZE, "%s/", dirpath);
			if (appowner == true) {
				_coretpk_installer_change_directory_owner(fullpath, APP_OWNER_ID, APP_GROUP_ID);
			}
			ret = _coretpk_installer_change_mode(fullpath, DIRECTORY_PERMISSION_755);
			if (ret != 0) {
				_LOGE("_coretpk_installer_change_mode is failed, fullpath=[%s]", fullpath);
			}
			continue;
		} else if (strcmp(entry.d_name, "..") == 0) {
			continue;
		}

		/* sub dir */
		if (entry.d_type == DT_DIR) {
			snprintf(fullpath, BUF_SIZE, "%s/%s", dirpath, entry.d_name);

			/*  owner:group */
			if (appowner == true) {
				ret = _coretpk_installer_change_directory_owner(fullpath, APP_OWNER_ID, APP_GROUP_ID);
				if (ret != 0) {
					_LOGE("_coretpk_installer_change_directory_owner failed, fullpath=[%s]", fullpath);
				}
			}
		/* sub symlink */
		} else if (entry.d_type == DT_LNK) {
			_LOGD("skip! symlink=[%s/%s]", dirpath, entry.d_name);
			continue;
		/* sub file */
		} else {
			snprintf(fullpath, BUF_SIZE, "%s/%s", dirpath, entry.d_name);

			/* permission(input mode) */
			ret = _coretpk_installer_change_mode(fullpath, mode);
			if (ret != 0) {
				_LOGE("_coretpk_installer_change_mode failed, fullpath=[%s]", fullpath);
			}

			/* owner:group */
			if (appowner == true) {
				ret = _coretpk_installer_change_file_owner(fullpath, APP_OWNER_ID, APP_GROUP_ID);
				if (ret != 0) {
					_LOGE("_coretpk_installer_change_file_owner failed, fullpath=[%s]", fullpath);
				}
			}
		}

		/* find next dir */
		if (entry.d_type == DT_DIR) {
			ret = _coretpk_installer_apply_directory_policy(fullpath, mode, appowner);
			if (ret != 0) {
				_LOGE("_coretpk_installer_apply_directory_policy failed, fullpath=[%s]", fullpath);
			}
		}
		memset(fullpath, '\0', BUF_SIZE);
	}

	closedir(dir);

	return ret;
}

int _coretpk_installer_make_directory_for_ext(const char *pkgid)
{
	char ext_pkg_base_path[BUF_SIZE] = { 0, };
	char temp_path[BUF_SIZE] = { 0, };
	char pkg_shared_data_path[BUF_SIZE] = { 0, };
	char *shared_data_label = NULL;
	int mmc_status = 0;
	int res = 0;
	char buf[BUF_SIZE] = { 0, };

	if (access(OPT_STORAGE_SDCARD, F_OK) != 0) {
		if( strerror_r(errno, buf, sizeof(buf)) == 0) {
			_LOGE("access(%s) failed. [%d][%s]", OPT_STORAGE_SDCARD, errno, buf);
		}
		return -1;
	}

	res = vconf_get_int(VCONFKEY_SYSMAN_MMC_STATUS, &mmc_status);
	retvm_if(res != 0, 0, "vconf_get_int(VCONFKEY_SYSMAN_MMC_STATUS) is failed.");

	if ((mmc_status == VCONFKEY_SYSMAN_MMC_REMOVED) || (mmc_status == VCONFKEY_SYSMAN_MMC_INSERTED_NOT_MOUNTED)) {
		_LOGD("mmc_status is MMC_REMOVED or NOT_MOUNTED.");
		return 0;
	} else {
		_LOGD("mmc_status is MMC_MOUNTED.");
	}

	/* pkg root path */
	if (access(OPT_STORAGE_SDCARD_APP_ROOT, F_OK) != 0) {
		/* permission(755) */
		res = mkdir(OPT_STORAGE_SDCARD_APP_ROOT, DIRECTORY_PERMISSION_755);
		if (res < 0) {
			if( strerror_r(errno, buf, sizeof(buf)) == 0) {
				_LOGE("mkdir(%s) failed. [%d][%s]", OPT_STORAGE_SDCARD_APP_ROOT, errno, buf);
			}
			return -1;
		}
	}

	/* app root path */
	snprintf(ext_pkg_base_path, BUF_SIZE, "%s/%s", OPT_STORAGE_SDCARD_APP_ROOT, pkgid);
	res = mkdir(ext_pkg_base_path, 0500);
	if (res == -1 && errno != EEXIST) {
		if( strerror_r(errno, buf, sizeof(buf)) == 0) {
			_LOGE("mkdir() is failed. error = [%d] strerror = [%s]", errno, buf);
		}
		return -1;
	}

	res = _coretpk_installer_set_smack_label_access(ext_pkg_base_path, "_");
	if (res != 0) {
		_LOGE("_coretpk_installer_set_smack_label_access() is failed.");
		return -1;
	}

	/* data */
	memset(temp_path, 0, BUF_SIZE);
	snprintf(temp_path, BUF_SIZE - 1, "%s/data", ext_pkg_base_path);
	res = mkdir(temp_path, 0700);
	if (res == -1 && errno != EEXIST) {
		if( strerror_r(errno, buf, sizeof(buf)) == 0) {
			_LOGE("mkdir() is failed. error = [%d] strerror = [%s]", errno, buf);
		}
		return -1;
	}
	res = _coretpk_installer_set_smack_label_access(temp_path, pkgid);
	if (res != 0) {
		_LOGE("_coretpk_installer_set_smack_label_access() is failed.");
		return -1;
	}

	/* cache */
	memset(temp_path, 0, BUF_SIZE);
	snprintf(temp_path, BUF_SIZE - 1, "%s/cache", ext_pkg_base_path);
	res = mkdir(temp_path, 0700);
	if (res == -1 && errno != EEXIST) {
		if( strerror_r(errno, buf, sizeof(buf)) == 0) {
			_LOGE("mkdir() is failed. error = [%d] strerror = [%s]", errno, buf);
		}
		return -1;
	}
	res = _coretpk_installer_set_smack_label_access(temp_path, pkgid);
	if (res != 0) {
		_LOGE("_coretpk_installer_set_smack_label_access() is failed.");
		return -1;
	}

	/* shared */
	memset(temp_path, 0, BUF_SIZE);
	snprintf(temp_path, BUF_SIZE - 1, "%s/shared", ext_pkg_base_path);
	res = mkdir(temp_path, 0500);
	if (res == -1 && errno != EEXIST) {
		if( strerror_r(errno, buf, sizeof(buf)) == 0) {
			_LOGE("mkdir() is failed. error = [%d] strerror = [%s]", errno, buf);
		}
		return -1;
	}
	res = _coretpk_installer_set_smack_label_access(temp_path, "_");
	if (res != 0) {
		_LOGE("_coretpk_installer_set_smack_label_access() is failed.");
		return -1;
	}

	snprintf(pkg_shared_data_path, BUF_SIZE, "%s/%s/%s", OPT_USR_APPS, pkgid, "shared/data");

	res = access(pkg_shared_data_path, F_OK);
	if (res == 0) {
		_LOGD("Exist shared/data folder (path:[%s])", pkg_shared_data_path);
		res = _coretpk_installer_get_smack_label_access(pkg_shared_data_path, &shared_data_label);
		if (res != 0) {
			_LOGE("_coretpk_installer_get_smack_label_access() is failed.");
			return -1;
		}

		/* shared/data */
		memset(temp_path, 0, BUF_SIZE);
		snprintf(temp_path, BUF_SIZE - 1, "%s/shared/data", ext_pkg_base_path);
		res = mkdir(temp_path, 0705);
		if (res == -1 && errno != EEXIST) {
			if( strerror_r(errno, buf, sizeof(buf)) == 0) {
				_LOGE("mkdir() is failed. error = [%d] strerror = [%s]", errno, buf);
			}
			return -1;
		}

		res = _coretpk_installer_set_smack_label_access(temp_path, shared_data_label);
		if (res != 0) {
			_LOGE("_coretpk_installer_set_smack_label_access() is failed.");
			return -1;
		}

		res = _coretpk_installer_set_smack_label_transmute(temp_path, "1");
		if (res != 0) {
			_LOGE("_coretpk_installer_set_smack_label_transmute() is failed.");
			/* return -1; */
		}

		/* shared/cache */
		memset(temp_path, 0, BUF_SIZE);
		snprintf(temp_path, BUF_SIZE - 1, "%s/shared/cache", ext_pkg_base_path);
		res = mkdir(temp_path, 0700);
		if (res == -1 && errno != EEXIST) {
			if( strerror_r(errno, buf, sizeof(buf)) == 0) {
				_LOGE("mkdir() is failed. error = [%d] strerror = [%s]", errno, buf);
			}
			return -1;
		}
		res = _coretpk_installer_set_smack_label_access(temp_path, shared_data_label);
		if (res != 0) {
			_LOGE("_coretpk_installer_set_smack_label_access() is failed.");
			return -1;
		}
		res = _coretpk_installer_set_smack_label_transmute(temp_path, "1");
		if (res != 0) {
			_LOGE("_coretpk_installer_set_smack_label_transmute() is failed.");
			/* return -1; */
		}

	} else if (res == -1 && errno == ENOENT) {
		if( strerror_r(errno, buf, sizeof(buf)) == 0) {
			_LOGD("Directory dose not exist. path: %s, errno: %d (%s)", pkg_shared_data_path, errno, buf);
		}
		return 0;
	} else {
		if( strerror_r(errno, buf, sizeof(buf)) == 0) {
			_LOGE("access() failed. path: %s, errno: %d (%s)", pkg_shared_data_path, errno, buf);
		}
		return -1;
	}

	return 0;
}

int _coretpk_installer_make_directory(const char *pkgid, bool preload)
{
	retvm_if(pkgid == NULL, RPM_INSTALLER_ERR_WRONG_PARAM, "pkgid is NULL.");

	int ret = 0;
	char appdir[BUF_SIZE] = { '\0' };
	char rootfile[BUF_SIZE] = { '\0' };
	char *groupid = NULL;
	char buf[BUF_SIZE] = { 0, };

	/*  root */
	memset(appdir, '\0', BUF_SIZE);
	snprintf(appdir, BUF_SIZE, "%s/%s", OPT_USR_APPS, pkgid);
	if (access(appdir, F_OK) != 0) {
		/*  permission(755) */
		ret = mkdir(appdir, DIRECTORY_PERMISSION_755);
		if (ret < 0) {
			if( strerror_r(errno, buf, sizeof(buf)) == 0) {
				_LOGE("mkdir(%s) failed. [%d][%s]", appdir, errno, buf);
			}
		}
	}
	ret = _coretpk_installer_apply_directory_policy(appdir, PERM_BASE, false);
	if (ret != 0) {
		_LOGE("_coretpk_installer_apply_directory_policy() failed, appdir=[%s], ret=[%d]", appdir, ret);
		return -1;
	}

	/*  bin */
	memset(appdir, '\0', BUF_SIZE);
	snprintf(appdir, BUF_SIZE, "%s/%s/bin", OPT_USR_APPS, pkgid);
	if (access(appdir, F_OK) != 0) {
		memset(appdir, '\0', BUF_SIZE);
		snprintf(appdir, BUF_SIZE, "%s/%s/bin", USR_APPS, pkgid);
		if (access(appdir, F_OK) != 0) {
			_LOGE("[%s] is not existed.", appdir);
		}
	}
	ret = _coretpk_installer_apply_directory_policy(appdir, PERM_BASE | PERM_EXECUTE, false);
	if (ret != 0) {
		_LOGE("_coretpk_installer_apply_directory_policy() failed, appdir=[%s], ret=[%d]", appdir, ret);
		return -1;
	}

	/*  data */
	memset(appdir, '\0', BUF_SIZE);
	snprintf(appdir, BUF_SIZE, "%s/%s/data", OPT_USR_APPS, pkgid);
	if (access(appdir, F_OK) != 0) {
		/*  permission(755) */
		ret = mkdir(appdir, DIRECTORY_PERMISSION_755);
		if (ret < 0) {
			if( strerror_r(errno, buf, sizeof(buf)) == 0) {
				_LOGE("mkdir failed, appdir=[%s], errno=[%d][%s]", appdir, errno, buf);
			}
		}
	}
	ret = _coretpk_installer_apply_directory_policy(appdir, PERM_BASE, true);
	if (ret != 0) {
		_LOGE("_coretpk_installer_apply_directory_policy() failed, appdir=[%s], ret=[%d]", appdir, ret);
		return -1;
	}

	/* lib */
	memset(appdir, '\0', BUF_SIZE);
	snprintf(appdir, BUF_SIZE, "%s/%s/lib", OPT_USR_APPS, pkgid);
	if ((access(appdir, F_OK) != 0) && (preload == true)) {
		memset(appdir, '\0', BUF_SIZE);
		snprintf(appdir, BUF_SIZE, "%s/%s/lib", USR_APPS, pkgid);
	}
	ret = _coretpk_installer_apply_directory_policy(appdir, PERM_BASE | PERM_EXECUTE, false);
	if (ret != 0) {
		_LOGE("_coretpk_installer_apply_directory_policy() failed, appdir=[%s], ret=[%d]", appdir, ret);
		return -1;
	}

	/*  res */
	memset(appdir, '\0', BUF_SIZE);
	snprintf(appdir, BUF_SIZE, "%s/%s/res", OPT_USR_APPS, pkgid);
	if ((access(appdir, F_OK) != 0) && (preload == true)) {
		memset(appdir, '\0', BUF_SIZE);
		snprintf(appdir, BUF_SIZE, "%s/%s/res", USR_APPS, pkgid);
	}
	ret = _coretpk_installer_apply_directory_policy(appdir, PERM_BASE, false);
	if (ret != 0) {
		_LOGE("_coretpk_installer_apply_directory_policy() failed, appdir=[%s], ret=[%d]", appdir, ret);
		return -1;
	}

	/*  cache */
	memset(appdir, '\0', BUF_SIZE);
	snprintf(appdir, BUF_SIZE, "%s/%s/cache", OPT_USR_APPS, pkgid);
	if (access(appdir, F_OK) != 0) {
		/*  permission(755) */
		ret = mkdir(appdir, DIRECTORY_PERMISSION_755);
		if (ret < 0) {
			if( strerror_r(errno, buf, sizeof(buf)) == 0) {
				_LOGE("mkdir failed, appdir=[%s], errno=[%d][%s]", appdir, errno, buf);
			}
		}
	}
	ret = _coretpk_installer_apply_directory_policy(appdir, PERM_BASE, true);
	if (ret != 0) {
		_LOGE("_coretpk_installer_apply_directory_policy() failed, appdir=[%s], ret=[%d]", appdir, ret);
		return -1;
	}

	/*  shared */
	memset(appdir, '\0', BUF_SIZE);
	snprintf(appdir, BUF_SIZE, "%s/%s/shared", OPT_USR_APPS, pkgid);
	if (access(appdir, F_OK) != 0) {
		ret = mkdir(appdir, DIRECTORY_PERMISSION_755);
		if (ret < 0) {
			if( strerror_r(errno, buf, sizeof(buf)) == 0) {
				_LOGE("mkdir(%s) failed. [%d][%s]", appdir, errno, buf);
			}
		}
	}
	ret = _coretpk_installer_apply_directory_policy(appdir, PERM_BASE, false);
	if (ret != 0) {
		_LOGE("_coretpk_installer_apply_directory_policy() failed, appdir=[%s], ret=[%d]", appdir, ret);
		return -1;
	}

	if (preload == true) {
		memset(appdir, '\0', BUF_SIZE);
		snprintf(appdir, BUF_SIZE, "%s/%s/shared", USR_APPS, pkgid);
		if (access(appdir, F_OK) != 0) {
			ret = mkdir(appdir, DIRECTORY_PERMISSION_755);
			if (ret < 0) {
				if( strerror_r(errno, buf, sizeof(buf)) == 0) {
					_LOGE("mkdir failed. appdir=[%s], errno=[%d][%s]", appdir, errno, buf);
				}
			}
		}
		ret = _coretpk_installer_apply_directory_policy(appdir, PERM_BASE, false);
		if (ret != 0) {
			_LOGE("_coretpk_installer_apply_directory_policy() failed, appdir=[%s], ret=[%d]", appdir, ret);
			return -1;
		}
	}

	/*  shared/data */
	memset(appdir, '\0', BUF_SIZE);
	snprintf(appdir, BUF_SIZE, "%s/%s/shared/data", OPT_USR_APPS, pkgid);
	if (access(appdir, F_OK) != 0) {
		ret = mkdir(appdir, DIRECTORY_PERMISSION_755);
		if (ret < 0) {
			if( strerror_r(errno, buf, sizeof(buf)) == 0) {
				_LOGE("mkdir failed. appdir=[%s], errno=[%d][%s]", appdir, errno, buf);
			}
		}
	}
	ret = _coretpk_installer_apply_directory_policy(appdir, PERM_BASE, true);
	if (ret != 0) {
		_LOGE("_coretpk_installer_apply_directory_policy() failed, appdir=[%s], ret=[%d]", appdir, ret);
		return -1;
	}

	/*  shared/cache */
	memset(appdir, '\0', BUF_SIZE);
	snprintf(appdir, BUF_SIZE, "%s/%s/shared/cache", OPT_USR_APPS, pkgid);
	if (access(appdir, F_OK) != 0) {
		ret = mkdir(appdir, DIRECTORY_PERMISSION_755);
		if (ret < 0) {
			if( strerror_r(errno, buf, sizeof(buf)) == 0) {
				_LOGE("mkdir failed. appdir=[%s], errno=[%d][%s]", appdir, errno, buf);
			}
		}
	}
	ret = _coretpk_installer_apply_directory_policy(appdir, PERM_BASE, true);
	if (ret != 0) {
		_LOGE("_coretpk_installer_apply_directory_policy() failed, appdir=[%s], ret=[%d]", appdir, ret);
		return -1;
	}

	/*  shared/res */
	memset(appdir, '\0', BUF_SIZE);
	snprintf(appdir, BUF_SIZE, "%s/%s/shared/res", OPT_USR_APPS, pkgid);
	ret = _coretpk_installer_apply_directory_policy(appdir, PERM_BASE, false);
	if (ret != 0) {
		_LOGE("_coretpk_installer_apply_directory_policy() failed, appdir=[%s], ret=[%d]", appdir, ret);
		return -1;
	}

	if (preload == true) {
		memset(appdir, '\0', BUF_SIZE);
		snprintf(appdir, BUF_SIZE, "%s/%s/shared/res", USR_APPS, pkgid);
		ret = _coretpk_installer_apply_directory_policy(appdir, PERM_BASE, false);
		if (ret != 0) {
			_LOGE("_coretpk_installer_apply_directory_policy() failed, appdir=[%s], ret=[%d]", appdir, ret);
			return -1;
		}
	}

	/*  shared/trusted */
	memset(appdir, '\0', BUF_SIZE);
	snprintf(appdir, BUF_SIZE, "%s/%s/shared/trusted", OPT_USR_APPS, pkgid);
	if (access(appdir, F_OK) != 0) {
		ret = _coretpk_installer_get_group_id(pkgid, &groupid);
		if (ret == 0) {
			ret = mkdir(appdir, DIRECTORY_PERMISSION_755);
			if (ret < 0) {
				if( strerror_r(errno, buf, sizeof(buf)) == 0) {
					_LOGE("mkdir failed, appdir=[%s], errno=[%d][%s]", appdir, errno, buf);
				}
			}
			free(groupid);
		}
	}
	ret = _coretpk_installer_apply_directory_policy(appdir, PERM_BASE, true);
	if (ret != 0) {
		_LOGE("_coretpk_installer_apply_directory_policy() failed, appdir=[%s], ret=[%d]", appdir, ret);
		return -1;
	}

	/*  [pkgid]/tizen-manifest.xml */
	snprintf(rootfile, BUF_SIZE, "%s/%s/%s", OPT_USR_APPS, pkgid, CORETPK_XML);
	ret = _coretpk_installer_apply_file_policy(rootfile);
	if (ret != 0) {
		_LOGE("_coretpk_installer_apply_file_policy() failed, rootfile=[%s]", rootfile);
		return -1;
	}

	if (preload == true) {
		memset(rootfile, '\0', BUF_SIZE);
		snprintf(rootfile, BUF_SIZE, "%s/%s/%s", USR_APPS, pkgid, CORETPK_XML);
		ret = _coretpk_installer_apply_file_policy(rootfile);
		if (ret != 0) {
			_LOGE("_coretpk_installer_apply_file_policy() failed, rootfile=[%s]", rootfile);
			return -1;
		}
	}

	/*  [pkgid]/author-signature.xml */
	memset(rootfile, '\0', BUF_SIZE);
	snprintf(rootfile, BUF_SIZE, "%s/%s/%s", OPT_USR_APPS, pkgid, AUTHOR_SIGNATURE_XML);
	ret = _coretpk_installer_apply_file_policy(rootfile);
	if (ret != 0) {
		_LOGE("_coretpk_installer_apply_file_policy() failed, rootfile=[%s]", rootfile);
		return -1;
	}

	if (preload == true) {
		memset(rootfile, '\0', BUF_SIZE);
		snprintf(rootfile, BUF_SIZE, "%s/%s/%s", USR_APPS, pkgid, AUTHOR_SIGNATURE_XML);
		ret = _coretpk_installer_apply_file_policy(rootfile);
		if (ret != 0) {
			_LOGE("_coretpk_installer_apply_file_policy() failed, rootfile=[%s]", rootfile);
			return -1;
		}
	}

	/*  [pkgid]/signature1.xml */
	memset(rootfile, '\0', BUF_SIZE);
	snprintf(rootfile, BUF_SIZE, "%s/%s/%s", OPT_USR_APPS, pkgid, SIGNATURE1_XML);
	ret = _coretpk_installer_apply_file_policy(rootfile);
	if (ret != 0) {
		_LOGE("_coretpk_installer_apply_file_policy() failed, rootfile=[%s]", rootfile);
		return -1;
	}

	if (preload == true) {
		memset(rootfile, '\0', BUF_SIZE);
		snprintf(rootfile, BUF_SIZE, "%s/%s/%s", USR_APPS, pkgid, SIGNATURE1_XML);
		ret = _coretpk_installer_apply_file_policy(rootfile);
		if (ret != 0) {
			_LOGE("_coretpk_installer_apply_file_policy() failed, rootfile=[%s]", rootfile);
			return -1;
		}
	}

	/*  /opt/share/packages/[pkgid].xml */
	memset(rootfile, '\0', BUF_SIZE);
	snprintf(rootfile, BUF_SIZE, "%s/%s.xml", OPT_SHARE_PACKAGES, pkgid);
	ret = _coretpk_installer_apply_file_policy(rootfile);
	if (ret != 0) {
		_LOGE("_coretpk_installer_apply_file_policy() failed, rootfile=[%s]", rootfile);
		return -1;
	}

	if (preload == true) {
		memset(rootfile, '\0', BUF_SIZE);
		snprintf(rootfile, BUF_SIZE, "%s/%s.xml", USR_SHARE_PACKAGES, pkgid);
		ret = _coretpk_installer_apply_file_policy(rootfile);
		if (ret != 0) {
			_LOGE("_coretpk_installer_apply_file_policy() failed, rootfile=[%s]", rootfile);
			return -1;
		}
	}

	return ret;
}

#ifdef _APPFW_FEATURE_MOUNT_INSTALL
int _coretpk_installer_mount_install_make_directory(const char *pkgid, bool preload)
{
	retvm_if(pkgid == NULL, RPM_INSTALLER_ERR_WRONG_PARAM, "pkgid is NULL.");

	int ret = 0;
	char appdir[BUF_SIZE] = { '\0' };
	char rootfile[BUF_SIZE] = { '\0' };
	char *groupid = NULL;
	char buf[BUF_SIZE] = { 0, };

	/*  root */
	memset(appdir, '\0', BUF_SIZE);
	snprintf(appdir, BUF_SIZE, "%s/%s", OPT_USR_APPS, pkgid);
	if (access(appdir, F_OK) != 0) {
		/*  permission(755) */
		ret = mkdir(appdir, DIRECTORY_PERMISSION_755);
		if (ret < 0) {
			_LOGE("mkdir(%s) failed. [%d][%s]", appdir, errno, buf);
		}
	}
	ret = _coretpk_installer_apply_directory_policy(appdir, PERM_BASE, false);
	if (ret != 0) {
		if( strerror_r(errno, buf, sizeof(buf)) == 0) {
			_LOGE("_coretpk_installer_apply_directory_policy() failed, appdir=[%s], ret=[%d]", appdir, ret);
		}
		return -1;
	}

	/*  bin */
	memset(appdir, '\0', BUF_SIZE);
	snprintf(appdir, BUF_SIZE, "%s/%s/bin", OPT_USR_APPS, pkgid);
	if (access(appdir, F_OK) != 0) {
		memset(appdir, '\0', BUF_SIZE);
		snprintf(appdir, BUF_SIZE, "%s/%s/bin", USR_APPS, pkgid);
		if (access(appdir, F_OK) != 0) {
			_LOGE("[%s] is not existed.", appdir);
		}
	}
#if 1
	ret = _coretpk_installer_apply_directory_policy(appdir, PERM_BASE | PERM_EXECUTE, false);
	if (ret != 0) {
		_LOGE("_coretpk_installer_apply_directory_policy() failed, appdir=[%s], ret=[%d]", appdir, ret);
		return -1;
	}
#endif

	/*  data */
	memset(appdir, '\0', BUF_SIZE);
	snprintf(appdir, BUF_SIZE, "%s/%s/data", OPT_USR_APPS, pkgid);
	if (access(appdir, F_OK) != 0) {
		/*  permission(755) */
		ret = mkdir(appdir, DIRECTORY_PERMISSION_755);
		if (ret < 0) {
			if( strerror_r(errno, buf, sizeof(buf)) == 0) {
				_LOGE("mkdir failed, appdir=[%s], errno=[%d][%s]", appdir, errno, buf);
			}
		}
		ret = _coretpk_installer_apply_directory_policy(appdir, PERM_BASE, true);
		if (ret != 0) {
			_LOGE("_coretpk_installer_apply_directory_policy() failed, appdir=[%s], ret=[%d]", appdir, ret);
			return -1;
		}
	}


	/* lib */
	memset(appdir, '\0', BUF_SIZE);
	snprintf(appdir, BUF_SIZE, "%s/%s/lib", OPT_USR_APPS, pkgid);
	if ((access(appdir, F_OK) != 0) && (preload == true)) {
		memset(appdir, '\0', BUF_SIZE);
		snprintf(appdir, BUF_SIZE, "%s/%s/lib", USR_APPS, pkgid);
	}


#if 0
	ret = _coretpk_installer_apply_directory_policy(appdir, PERM_BASE | PERM_EXECUTE, false);
	if (ret != 0) {
		_LOGE("_coretpk_installer_apply_directory_policy() failed, appdir=[%s], ret=[%d]", appdir, ret);
		return -1;
	}
#endif

	/*  res */
	memset(appdir, '\0', BUF_SIZE);
	snprintf(appdir, BUF_SIZE, "%s/%s/res", OPT_USR_APPS, pkgid);
	if ((access(appdir, F_OK) != 0) && (preload == true)) {
		memset(appdir, '\0', BUF_SIZE);
		snprintf(appdir, BUF_SIZE, "%s/%s/res", USR_APPS, pkgid);
	}

#if 0
	ret = _coretpk_installer_apply_directory_policy(appdir, PERM_BASE, false);
	if (ret != 0) {
		_LOGE("_coretpk_installer_apply_directory_policy() failed, appdir=[%s], ret=[%d]", appdir, ret);
		return -1;
	}
#endif

	/*  cache */
	memset(appdir, '\0', BUF_SIZE);
	snprintf(appdir, BUF_SIZE, "%s/%s/cache", OPT_USR_APPS, pkgid);
	if (access(appdir, F_OK) != 0) {
		/*  permission(755) */
		ret = mkdir(appdir, DIRECTORY_PERMISSION_755);
		if (ret < 0) {
			if( strerror_r(errno, buf, sizeof(buf)) == 0) {
				_LOGE("mkdir failed, appdir=[%s], errno=[%d][%s]", appdir, errno, buf);
			}
		}
		ret = _coretpk_installer_apply_directory_policy(appdir, PERM_BASE, true);
		if (ret != 0) {
			_LOGE("_coretpk_installer_apply_directory_policy() failed, appdir=[%s], ret=[%d]", appdir, ret);
			return -1;
		}
	}


	/*  shared */
	memset(appdir, '\0', BUF_SIZE);
	snprintf(appdir, BUF_SIZE, "%s/%s/shared", OPT_USR_APPS, pkgid);
	if (access(appdir, F_OK) != 0) {
		ret = mkdir(appdir, DIRECTORY_PERMISSION_755);
		if (ret < 0) {
			if( strerror_r(errno, buf, sizeof(buf)) == 0) {
				_LOGE("mkdir(%s) failed. [%d][%s]", appdir, errno, buf);
			}
		}
		ret = _coretpk_installer_apply_directory_policy(appdir, PERM_BASE, false);
		if (ret != 0) {
			_LOGE("_coretpk_installer_apply_directory_policy() failed, appdir=[%s], ret=[%d]", appdir, ret);
			return -1;
		}

		/*  shared/data */
		memset(appdir, '\0', BUF_SIZE);
		snprintf(appdir, BUF_SIZE, "%s/%s/shared/data", OPT_USR_APPS, pkgid);
		if (access(appdir, F_OK) != 0) {
			ret = mkdir(appdir, DIRECTORY_PERMISSION_755);
			if (ret < 0) {
				if( strerror_r(errno, buf, sizeof(buf)) == 0) {
					_LOGE("mkdir failed. appdir=[%s], errno=[%d][%s]", appdir, errno, buf);
				}
			}
			ret = _coretpk_installer_apply_directory_policy(appdir, PERM_BASE, true);
			if (ret != 0) {
				_LOGE("_coretpk_installer_apply_directory_policy() failed, appdir=[%s], ret=[%d]", appdir, ret);
				return -1;
			}
		}

		/*  shared/cache */
		memset(appdir, '\0', BUF_SIZE);
		snprintf(appdir, BUF_SIZE, "%s/%s/shared/cache", OPT_USR_APPS, pkgid);
		if (access(appdir, F_OK) != 0) {
			ret = mkdir(appdir, DIRECTORY_PERMISSION_755);
			if (ret < 0) {
				if( strerror_r(errno, buf, sizeof(buf)) == 0) {
					_LOGE("mkdir failed. appdir=[%s], errno=[%d][%s]", appdir, errno, buf);
				}
			}
			ret = _coretpk_installer_apply_directory_policy(appdir, PERM_BASE, true);
			if (ret != 0) {
				_LOGE("_coretpk_installer_apply_directory_policy() failed, appdir=[%s], ret=[%d]", appdir, ret);
				return -1;
			}
		}

		/*  shared/res */
		memset(appdir, '\0', BUF_SIZE);
		snprintf(appdir, BUF_SIZE, "%s/%s/shared/res", OPT_USR_APPS, pkgid);
		ret = _coretpk_installer_apply_directory_policy(appdir, PERM_BASE, false);
		if (ret != 0) {
			_LOGE("_coretpk_installer_apply_directory_policy() failed, appdir=[%s], ret=[%d]", appdir, ret);
			return -1;
		}

		/*  shared/trusted */
		memset(appdir, '\0', BUF_SIZE);
		snprintf(appdir, BUF_SIZE, "%s/%s/shared/trusted", OPT_USR_APPS, pkgid);
		if (access(appdir, F_OK) != 0) {
			ret = _coretpk_installer_get_group_id(pkgid, &groupid);
			if (ret == 0) {
				ret = mkdir(appdir, DIRECTORY_PERMISSION_755);
				if (ret < 0) {
					if( strerror_r(errno, buf, sizeof(buf)) == 0) {
						_LOGE("mkdir failed, appdir=[%s], errno=[%d][%s]", appdir, errno, buf);
					}
				}
				free(groupid);
			}
			ret = _coretpk_installer_apply_directory_policy(appdir, PERM_BASE, true);
			if (ret != 0) {
				_LOGE("_coretpk_installer_apply_directory_policy() failed, appdir=[%s], ret=[%d]", appdir, ret);
				return -1;
			}
		}
	}

	if (preload == true) {
		memset(appdir, '\0', BUF_SIZE);
		snprintf(appdir, BUF_SIZE, "%s/%s/shared", USR_APPS, pkgid);
		if (access(appdir, F_OK) != 0) {
			ret = mkdir(appdir, DIRECTORY_PERMISSION_755);
			if (ret < 0) {
				if( strerror_r(errno, buf, sizeof(buf)) == 0) {
					_LOGE("mkdir failed. appdir=[%s], errno=[%d][%s]", appdir, errno, buf);
				}
			}
		}
		ret = _coretpk_installer_apply_directory_policy(appdir, PERM_BASE, false);
		if (ret != 0) {
			_LOGE("_coretpk_installer_apply_directory_policy() failed, appdir=[%s], ret=[%d]", appdir, ret);
			return -1;
		}

		memset(appdir, '\0', BUF_SIZE);
		snprintf(appdir, BUF_SIZE, "%s/%s/shared/res", USR_APPS, pkgid);
		ret = _coretpk_installer_apply_directory_policy(appdir, PERM_BASE, false);
		if (ret != 0) {
			_LOGE("_coretpk_installer_apply_directory_policy() failed, appdir=[%s], ret=[%d]", appdir, ret);
			return -1;
		}
	}

#if 0
	/*  [pkgid]/tizen-manifest.xml */
	snprintf(rootfile, BUF_SIZE, "%s/%s/%s", OPT_USR_APPS, pkgid, CORETPK_XML);
	ret = _coretpk_installer_apply_file_policy(rootfile);
	if (ret != 0) {
		_LOGE("_coretpk_installer_apply_file_policy() failed, rootfile=[%s]", rootfile);
		return -1;
	}

	if (preload == true) {
		memset(rootfile, '\0', BUF_SIZE);
		snprintf(rootfile, BUF_SIZE, "%s/%s/%s", USR_APPS, pkgid, CORETPK_XML);
		ret = _coretpk_installer_apply_file_policy(rootfile);
		if (ret != 0) {
			_LOGE("_coretpk_installer_apply_file_policy() failed, rootfile=[%s]", rootfile);
			return -1;
		}
	}

	/*  [pkgid]/author-signature.xml */
	memset(rootfile, '\0', BUF_SIZE);
	snprintf(rootfile, BUF_SIZE, "%s/%s/%s", OPT_USR_APPS, pkgid, AUTHOR_SIGNATURE_XML);
	ret = _coretpk_installer_apply_file_policy(rootfile);
	if (ret != 0) {
		_LOGE("_coretpk_installer_apply_file_policy() failed, rootfile=[%s]", rootfile);
		return -1;
	}

	if (preload == true) {
		memset(rootfile, '\0', BUF_SIZE);
		snprintf(rootfile, BUF_SIZE, "%s/%s/%s", USR_APPS, pkgid, AUTHOR_SIGNATURE_XML);
		ret = _coretpk_installer_apply_file_policy(rootfile);
		if (ret != 0) {
			_LOGE("_coretpk_installer_apply_file_policy() failed, rootfile=[%s]", rootfile);
			return -1;
		}
	}

	/*  [pkgid]/signature1.xml */
	memset(rootfile, '\0', BUF_SIZE);
	snprintf(rootfile, BUF_SIZE, "%s/%s/%s", OPT_USR_APPS, pkgid, SIGNATURE1_XML);
	ret = _coretpk_installer_apply_file_policy(rootfile);
	if (ret != 0) {
		_LOGE("_coretpk_installer_apply_file_policy() failed, rootfile=[%s]", rootfile);
		return -1;
	}

	if (preload == true) {
		memset(rootfile, '\0', BUF_SIZE);
		snprintf(rootfile, BUF_SIZE, "%s/%s/%s", USR_APPS, pkgid, SIGNATURE1_XML);
		ret = _coretpk_installer_apply_file_policy(rootfile);
		if (ret != 0) {
			_LOGE("_coretpk_installer_apply_file_policy() failed, rootfile=[%s]", rootfile);
			return -1;
		}
	}
#endif

	/*  /opt/share/packages/[pkgid].xml */
	memset(rootfile, '\0', BUF_SIZE);
	snprintf(rootfile, BUF_SIZE, "%s/%s.xml", OPT_SHARE_PACKAGES, pkgid);
	ret = _coretpk_installer_apply_file_policy(rootfile);
	if (ret != 0) {
		_LOGE("_coretpk_installer_apply_file_policy() failed, rootfile=[%s]", rootfile);
		return -1;
	}

	if (preload == true) {
		memset(rootfile, '\0', BUF_SIZE);
		snprintf(rootfile, BUF_SIZE, "%s/%s.xml", USR_SHARE_PACKAGES, pkgid);
		ret = _coretpk_installer_apply_file_policy(rootfile);
		if (ret != 0) {
			_LOGE("_coretpk_installer_apply_file_policy() failed, rootfile=[%s]", rootfile);
			return -1;
		}
	}

	return ret;
}


#endif

int _coretpk_installer_change_mode(const char *path, int mode)
{
	int ret = 0;

	ret = chmod(path, mode);
	if (ret != 0) {
		char buf[BUF_SIZE] = { 0, };
		if( strerror_r(errno, buf, sizeof(buf)) == 0) {
			_LOGE("chmod(%s) failed. [%d][%s]", path, errno, buf);
		}
		return -1;
	}

	return ret;
}

int _coretpk_installer_change_file_owner(const char *path, int ownerid, int groupid)
{
	int ret = 0;

	if (access(path, F_OK) == 0) {
		ret = chown(path, ownerid, groupid);
		if (ret != 0) {
			char buf[BUF_SIZE] = { 0, };
			if( strerror_r(errno, buf, sizeof(buf)) == 0) {
				_LOGE("chown(%s) failed. [%d][%s]", path, errno, buf);
			}
			return -1;
		}
	}

	return ret;
}

int _coretpk_installer_change_directory_owner(const char *dirpath, int ownerid, int groupid)
{
	int ret = 0;

	if (__is_dir(dirpath)) {
		ret = chown(dirpath, ownerid, groupid);
		if (ret != 0) {
			char buf[BUF_SIZE] = { 0, };
			if( strerror_r(errno, buf, sizeof(buf)) == 0) {
				_LOGE("chown(%s) failed. [%d][%s]", dirpath, errno, buf);
			}
			return -1;
		}
	}

	return ret;
}

void _coretpk_installer_set_privilege_setup_path_for_ext(const char *pkgid, const char *dirpath, app_path_type_t type, const char *label)
{
	char path[BUF_SIZE] = { '\0' };

	snprintf(path, BUF_SIZE, "%s/%s", OPT_STORAGE_SDCARD_APP_ROOT, dirpath);
	if (access(path, F_OK) == 0) {
		_ri_privilege_setup_path(pkgid, path, type, label);
	}
}

void _coretpk_installer_set_privilege_setup_path(const char *pkgid, const char *dirpath, app_path_type_t type, const char *label)
{
	char path[BUF_SIZE] = { '\0' };

	snprintf(path, BUF_SIZE, "%s/%s", USR_APPS, dirpath);
	if (access(path, F_OK) == 0) {
		_ri_privilege_setup_path(pkgid, path, type, label);
	}
	memset(path, '\0', BUF_SIZE);

	snprintf(path, BUF_SIZE, "%s/%s", OPT_USR_APPS, dirpath);
	if (access(path, F_OK) == 0) {
		_ri_privilege_setup_path(pkgid, path, type, label);
	}
}

int _coretpk_installer_get_group_id(const char *pkgid, char **result)
{
	int ret = 0;
	const char *value = NULL;
	char author_signature[BUF_SIZE] = { '\0' };
	char *e_rootcert = NULL;
	char *d_rootcert = NULL;
	gsize d_size = 0;
	unsigned char hashout[BUF_SIZE] = { '\0' };
	unsigned int h_size = 0;
	int e_size = 0;
	int length = 0;
	pkgmgrinfo_certinfo_h handle = NULL;

	snprintf(author_signature, BUF_SIZE, "%s/%s/%s", OPT_USR_APPS, pkgid, AUTHOR_SIGNATURE_XML);
	if (access(author_signature, F_OK) != 0) {
		_LOGE("[%s] is not found.", author_signature);

		memset(author_signature, '\0', BUF_SIZE);
		snprintf(author_signature, BUF_SIZE, "%s/%s/%s", USR_APPS, pkgid, AUTHOR_SIGNATURE_XML);
		if (access(author_signature, F_OK) != 0) {
			_LOGE("[%s] is not found.", author_signature);
			return -1;
		} else {
			_LOGE("author_signature=[%s]", author_signature);
		}
	}

	ret = pkgmgrinfo_pkginfo_create_certinfo(&handle);
	if (ret < 0) {
		_LOGE("failed to get cert info.");
		goto err;
	}

	ret = pkgmgrinfo_pkginfo_load_certinfo(pkgid, handle);
	if (ret < 0) {
		_LOGE("failed to load cert info.");
		goto err;
	}

	/* get root certificate */
	ret = pkgmgrinfo_pkginfo_get_cert_value(handle, PMINFO_AUTHOR_SIGNER_CERT, &value);
	if (ret < 0 || value == NULL) {
		_LOGE("failed to get cert value.");
		goto err;
	}

	/* decode cert */
	d_rootcert = (char *)g_base64_decode(value, &d_size);
	if (d_rootcert == NULL) {
		_LOGE("failed to execute decode.");
		goto err;
	}

	/* hash */
	EVP_Digest(d_rootcert, d_size, hashout, &h_size, EVP_sha1(), NULL);
	if (h_size <= 0) {
		_LOGE("h_size is invalid.");
		goto err;
	}

	/* encode cert */
	e_rootcert = g_base64_encode((const guchar *)hashout, h_size);
	if (e_rootcert == NULL) {
		_LOGE("failed to execute encode.");
		goto err;
	}
	e_size = strlen(e_rootcert);
	_LOGD("encoding done, len=[%d]", e_size);

	/* replace / to # */
	for (length = e_size; length >= 0; --length) {
		if (e_rootcert[length] == '/') {
			e_rootcert[length] = '#';
		}
	}

	*result = e_rootcert;

err:
	if (d_rootcert) {
		free(d_rootcert);
	}

	/* destroy cert */
	if (handle) {
		pkgmgrinfo_pkginfo_destroy_certinfo(handle);
	}

	return ret;
}

int _coretpk_installer_apply_smack_for_ext(const char *pkgname)
{
	int ret = 0;
	char dirpath[BUF_SIZE] = { '\0' };

	/* [pkgid]/data */
	snprintf(dirpath, BUF_SIZE, "%s/data", pkgname);
	_coretpk_installer_set_privilege_setup_path_for_ext(pkgname, dirpath, APP_PATH_PRIVATE, pkgname);
	memset(dirpath, '\0', BUF_SIZE);

	/* [pkgid]/cache */
	snprintf(dirpath, BUF_SIZE, "%s/cache", pkgname);
	_coretpk_installer_set_privilege_setup_path_for_ext(pkgname, dirpath, APP_PATH_PRIVATE, pkgname);
	memset(dirpath, '\0', BUF_SIZE);

	/* [pkgid]/shared */
	snprintf(dirpath, BUF_SIZE, "%s/shared", pkgname);
	_coretpk_installer_set_privilege_setup_path_for_ext(pkgname, dirpath, APP_PATH_ANY_LABEL, "_");
	memset(dirpath, '\0', BUF_SIZE);

	/* [pkgid]/shared/data */
	snprintf(dirpath, BUF_SIZE, "%s/shared/data", pkgname);
	_coretpk_installer_set_privilege_setup_path_for_ext(pkgname, dirpath, APP_PATH_PUBLIC_RO, NULL);

	return ret;
}

int _coretpk_installer_apply_smack(const char *pkgname, int flag)
{
	int ret = 0;
	char dirpath[BUF_SIZE] = { '\0' };
	char manifest[BUF_SIZE] = { '\0' };
	char *groupid = NULL;
	char *shared_data_label = NULL;

	_ri_privilege_register_package(pkgname);

	/*  app root */
	snprintf(dirpath, BUF_SIZE, "%s", pkgname);
	_coretpk_installer_set_privilege_setup_path(pkgname, dirpath, APP_PATH_ANY_LABEL, "_");
	memset(dirpath, '\0', BUF_SIZE);

	/*  shared */
	snprintf(dirpath, BUF_SIZE, "%s/shared", pkgname);
	_coretpk_installer_set_privilege_setup_path(pkgname, dirpath, APP_PATH_ANY_LABEL, "_");
	memset(dirpath, '\0', BUF_SIZE);

	/*  shared/res */
	snprintf(dirpath, BUF_SIZE, "%s/shared/res", pkgname);
	_coretpk_installer_set_privilege_setup_path(pkgname, dirpath, APP_PATH_ANY_LABEL, "_");
	memset(dirpath, '\0', BUF_SIZE);

	/*  shared/data */
	snprintf(dirpath, BUF_SIZE, "%s/shared/data", pkgname);
	_coretpk_installer_set_privilege_setup_path(pkgname, dirpath, APP_PATH_PUBLIC_RO, NULL);
	memset(dirpath, '\0', BUF_SIZE);

	/*  shared/cache */
	snprintf(dirpath, BUF_SIZE, "%s/%s/shared/data", OPT_USR_APPS, pkgname);
	ret = _coretpk_installer_get_smack_label_access(dirpath, &shared_data_label);
	if (ret == 0) {
		memset(dirpath, '\0', BUF_SIZE);
		snprintf(dirpath, BUF_SIZE, "%s/%s/shared/cache", OPT_USR_APPS, pkgname);
		ret = _coretpk_installer_set_smack_label_access(dirpath, shared_data_label);
		if (ret != 0) {
			_LOGE("_coretpk_installer_apply_directory_policy() failed, appdir=[%s], ret=[%d]", dirpath, ret);
		}
		ret = _coretpk_installer_set_smack_label_transmute(dirpath, "1");
		if (ret != 0) {
			_LOGE("_coretpk_installer_apply_directory_policy() failed, appdir=[%s], ret=[%d]", dirpath, ret);
		}
	}

	/*  shared/trusted */
	memset(dirpath, '\0', BUF_SIZE);
	snprintf(dirpath, BUF_SIZE, "%s/shared/trusted", pkgname);
	if (_installer_util_get_configuration_value(INI_VALUE_SIGNATURE)) {
		ret = _coretpk_installer_get_group_id(pkgname, &groupid);
		if (ret == 0) {
			LOGD("groupid = [%s] for shared/trusted.", groupid);
			_coretpk_installer_set_privilege_setup_path(pkgname, dirpath, APP_PATH_GROUP_RW, groupid);
			if (groupid)
				free(groupid);
		} else {
			if (flag == 1) {
				LOGE("_coretpk_installer_get_group_id(%s) failed.", pkgname);
				return -1;
			}
		}
	}
	memset(dirpath, '\0', BUF_SIZE);

	/* bin */
	snprintf(dirpath, BUF_SIZE, "%s/bin", pkgname);
	_coretpk_installer_set_privilege_setup_path(pkgname, dirpath, APP_PATH_PRIVATE, pkgname);
	memset(dirpath, '\0', BUF_SIZE);

	/* data */
	snprintf(dirpath, BUF_SIZE, "%s/data", pkgname);
	_coretpk_installer_set_privilege_setup_path(pkgname, dirpath, APP_PATH_PRIVATE, pkgname);
	memset(dirpath, '\0', BUF_SIZE);

	/* lib */
	snprintf(dirpath, BUF_SIZE, "%s/lib", pkgname);
	_coretpk_installer_set_privilege_setup_path(pkgname, dirpath, APP_PATH_PRIVATE, pkgname);
	memset(dirpath, '\0', BUF_SIZE);

	/* res */
	snprintf(dirpath, BUF_SIZE, "%s/res", pkgname);
	_coretpk_installer_set_privilege_setup_path(pkgname, dirpath, APP_PATH_PRIVATE, pkgname);
	memset(dirpath, '\0', BUF_SIZE);

	/* cache */
	snprintf(dirpath, BUF_SIZE, "%s/cache", pkgname);
	_coretpk_installer_set_privilege_setup_path(pkgname, dirpath, APP_PATH_PRIVATE, pkgname);
	memset(dirpath, '\0', BUF_SIZE);

	/* tizen-manifest.xml */
	snprintf(dirpath, BUF_SIZE, "%s/%s", pkgname, CORETPK_XML);
	_coretpk_installer_set_privilege_setup_path(pkgname, dirpath, APP_PATH_PRIVATE, pkgname);
	memset(dirpath, '\0', BUF_SIZE);

	/* author-signature.xml */
	snprintf(dirpath, BUF_SIZE, "%s/%s", pkgname, AUTHOR_SIGNATURE_XML);
	_coretpk_installer_set_privilege_setup_path(pkgname, dirpath, APP_PATH_PRIVATE, pkgname);
	memset(dirpath, '\0', BUF_SIZE);

	/* signature1.xml */
	snprintf(dirpath, BUF_SIZE, "%s/%s", pkgname, SIGNATURE1_XML);
	_coretpk_installer_set_privilege_setup_path(pkgname, dirpath, APP_PATH_PRIVATE, pkgname);
	memset(dirpath, '\0', BUF_SIZE);

	/* [pkgid].xml */
	snprintf(manifest, BUF_SIZE, "%s/%s.xml", OPT_SHARE_PACKAGES, pkgname);
	if (access(manifest, F_OK) == 0) {
		_ri_privilege_setup_path(pkgname, manifest, APP_PATH_PRIVATE, pkgname);
	}

	/* external storage */
	if (access(OPT_STORAGE_SDCARD, F_OK) == 0) {
		ret = _coretpk_installer_apply_smack_for_ext(pkgname);
		if (ret != 0) {
			_LOGE("_coretpk_installer_apply_smack_for_ext(%s) failed.", pkgname);
			return -1;
		}
	}

	return ret;
}

static char *__getprivilege(const char *pBuf)
{
	const char *pKey = "<privilege>";
	const char *p = NULL;
	const char *pStart = NULL;
	const char *pEnd = NULL;

	p = strstr(pBuf, pKey);
	if (p == NULL)
		return NULL;

	pStart = p + strlen(pKey);
	pEnd = strchr(pStart, '<');
	if (pEnd == NULL)
		return NULL;

	size_t len = pEnd - pStart;
	if (len <= 0)
		return NULL;

	char *pRes = (char *)malloc(len + 1);
	if (pRes == NULL) {
		_LOGE("malloc failed!!");
		return NULL;
	}
	strncpy(pRes, pStart, len);
	pRes[len] = 0;

	return pRes;
}

int _coretpk_installer_apply_privilege(const char *pkgid, const char *pkgPath, int apiVisibility)
{
	int ret = 0;
	FILE *fp = NULL;
	char *find_str = NULL;
	char buf[BUF_SIZE] = { 0 };
	char manifest[BUF_SIZE] = { '\0' };
	const char *perm[] = { NULL, NULL };
	int apptype = PERM_APP_TYPE_EFL;
	pkginfo *pkg_info = NULL;

	if (apiVisibility & CERT_SVC_VISIBILITY_PLATFORM) {
		_LOGD("VISIBILITY_PLATFORM!");
		apptype = PERM_APP_TYPE_EFL_PLATFORM;
	} else if ((apiVisibility & CERT_SVC_VISIBILITY_PARTNER) ||
		(apiVisibility & CERT_SVC_VISIBILITY_PARTNER_OPERATOR) ||
		(apiVisibility & CERT_SVC_VISIBILITY_PARTNER_MANUFACTURER)) {
		_LOGD("VISIBILITY_PARTNER!");
		apptype = PERM_APP_TYPE_EFL_PARTNER;
	}

	snprintf(manifest, BUF_SIZE, "%s/%s", pkgPath, CORETPK_XML);
	_LOGD("pkgid = [%s], manifest = [%s]", pkgid, manifest);

	fp = fopen(manifest, "r");
	if (fp == NULL) {
		_LOGE("Fail get : %s\n", manifest);
		return -1;
	}

	pkg_info = _coretpk_parser_get_manifest_info(manifest);
	if (pkg_info == NULL || strlen(pkg_info->api_version) == 0) {
		_LOGE("failed to set pkg version for privilege, ret[%d]", ret);
		fclose(fp);
		if (pkg_info)
			free(pkg_info);
		return -1;
	}
	ret = _ri_privilege_set_package_version(pkgid, pkg_info->api_version);
	if (ret != 0) {
		_LOGE("failed to set pkg version for privilege, ret[%d]", ret);
		free(pkg_info);
		fclose(fp);
		return -1;
	} else
		_LOGD("api-version for privilege has done successfully.");
	free(pkg_info);

	while (fgets(buf, BUF_SIZE, fp) != NULL) {
		__str_trim(buf);

		if (strstr(buf, "<privilege>")) {
			find_str = __getprivilege(buf);
			if (find_str != NULL) {
				_LOGD("privilege = [%s]", find_str);
				perm[0] = find_str;

				ret = _ri_privilege_enable_permissions(pkgid, apptype, perm, 1);
				if (ret < 0) {
					_LOGE("_ri_privilege_enable_permissions(%s, %d) failed.", pkgid, apptype);
				} else {
					_LOGD("_ri_privilege_enable_permissions(%s, %d) succeed.", pkgid, apptype);
				}

				free(find_str);
				find_str = NULL;
			} else {
				_LOGD("find_str is null.");
			}
		}

		memset(buf, 0x00, BUF_SIZE);
	}

	/* reload privilege */
	const char *perm_reload[] = { NULL, NULL };
	ret = _ri_privilege_enable_permissions(pkgid, apptype, perm_reload, 1);
	if (ret < 0) {
		_LOGE("_ri_privilege_enable_permissions for smack reload is failed.");
	}

	if (fp != NULL)
		fclose(fp);

	return 0;
}

int _coretpk_installer_install_package(const char *pkgfile, const pkginfo * pkg_file_info)
{
	retvm_if(pkgfile == NULL, RPM_INSTALLER_ERR_WRONG_PARAM, "pkgfile is NULL.");
	retvm_if(pkg_file_info == NULL, RPM_INSTALLER_ERR_WRONG_PARAM, "pkg_file_info is NULL.");

	int ret = 0;
	int visibility = 0;
	int install_status = APP2EXT_STATUS_SUCCESS;
	char root_path[BUF_SIZE] = { 0, };
	char tizen_manifest[BUF_SIZE] = { 0, };
	char system_manifest[BUF_SIZE] = { 0, };
	char cwd[BUF_SIZE] = { 0, };
	char rwmanifest[BUF_SIZE] = { 0, };
	char res_xml[BUF_SIZE] = { 0, };
	char signature1[BUF_SIZE] = { 0, };
	char *temp = NULL;
	const char *pkgid = pkg_file_info->package_name;
	bool update = false;
	bool directory_install = false;
	char buf[BUF_SIZE] = { 0, };
	pkgmgrinfo_pkginfo_h pkginfo_handle = NULL;
	pkgmgrinfo_installed_storage storage = PMINFO_INTERNAL_STORAGE;
	app2ext_handle *handle = NULL;
	GList *dir_list = NULL;
	bundle *optional_data = NULL;

	optional_data = bundle_create();
	if (optional_data) {
		if (pkg_file_info->support_disable == true) {
			bundle_add_str(optional_data, "support-disable", "true");
		}
	}

	if (__is_dir(pkgfile)) {
		_LOGD("Directory install(preload)");
		directory_install = true;
	}

	if (pkg_file_info->is_preload == true) {
		snprintf(root_path, BUF_SIZE, "%s/%s/", USR_APPS, pkgid);
		snprintf(tizen_manifest, BUF_SIZE, "%s/%s/%s", USR_APPS, pkgid, CORETPK_XML);
	} else {
		snprintf(root_path, BUF_SIZE, "%s/%s/", OPT_USR_APPS, pkgid);
		snprintf(tizen_manifest, BUF_SIZE, "%s/%s/%s", OPT_USR_APPS, pkgid, CORETPK_XML);
	}

	ret = pkgmgrinfo_pkginfo_get_pkginfo(pkgid, &pkginfo_handle);
	if (ret < 0) {
		_LOGD("------------------------------------------");
		_LOGD("Install - [%s][%s]", pkgid, pkgfile);
		_LOGD("------------------------------------------");

		_ri_broadcast_status_notification(pkgid, PKGTYPE_TPK, "start", "install");

		/* If the directory which will be installed exists, remove it. */
		if ((__is_dir(root_path)) && (directory_install == false)) {
			_installer_util_delete_dir(root_path);
		}

		/*pkgid should not be same with SMACK label used by system*/
		if (security_server_check_domain_name(pkgid) == SECURITY_SERVER_API_SUCCESS) {
			_LOGE("Cannot install this pkg[%s] : It has invalid pkg name", pkgid);
			ret = RPM_INSTALLER_ERR_INTERNAL;
			goto err;
		}

		/* pre_install */
		ret = __pre_install_for_mmc(pkgid, pkgfile, &dir_list, &handle, pkg_file_info->install_location);
		if (ret < 0) {
			_LOGE("__pre_install_for_mmc(%s) failed.", pkgid);
			goto err;
		}
	} else {
		_LOGD("------------------------------------------");
		_LOGD("Update - [%s][%s]", pkgid, pkgfile);
		_LOGD("------------------------------------------");

		update = true;
		_ri_broadcast_status_notification(pkgid, PKGTYPE_TPK, "start", "update");

		/* terminate running app */
		__terminate_running_app(pkgid);

		ret = pkgmgrinfo_pkginfo_get_installed_storage(pkginfo_handle, &storage);
		if (ret != 0) {
			_LOGE("pkgmgrinfo_pkginfo_get_installed_storage(%s) failed.", pkgid);
			ret = RPM_INSTALLER_ERR_INTERNAL;
			goto err;
		}

		/* remove dir for clean */
		if (directory_install == false) {
			__ri_remove_updated_dir(pkgid);
		}

		/* pre_upgrade */
		ret = __pre_upgrade_for_mmc(pkgid, pkgfile, &dir_list, &handle, storage);
		if (ret < 0) {
			_LOGE("__pre_upgrade_for_mmc(%s) failed.", pkgid);
			goto err;
		}
	}
#ifdef _APPFW_FEATURE_EXPANSION_PKG_INSTALL
	if (is_tpk_and_tep == true)
		_ri_broadcast_status_notification(pkgid, PKGTYPE_TPK, "install_percent", "20");
	else
#endif
		_ri_broadcast_status_notification(pkgid, PKGTYPE_TPK, "install_percent", "30");

	/*compare package's api version with platform version*/
	ret = __coretpk_compare_with_platform_version(pkg_file_info->api_version);
	if (ret != RPM_INSTALLER_SUCCESS) {
		if (ret == RPM_INSTALLER_ERR_NOT_SUPPORTED_API_VERSION) {
			_LOGE("Unable to install. Platform version[%s] < Package version[%s]",
				TIZEN_FULL_VERSION, pkg_file_info->api_version);
		}
		ret = RPM_INSTALLER_ERR_INTERNAL;
		goto err;
	}

	/* install package */
	if (directory_install == false) {
		_LOGD("[start] unzip(%s)", pkgfile);
		const char *unzip_argv[] = { "/usr/bin/unzip", "-oqq", pkgfile, "-d", root_path, NULL };
		ret = _ri_xsystem(unzip_argv);
		if (ret != 0) {
			_LOGE("failed to unzip for path=[%s], ret=[%d]", root_path, ret);
			ret = RPM_INSTALLER_ERR_UNZIP_FAILED;
			goto err;
		}
		_LOGD("[end] unzip(%s)", root_path);
	}

	/* getcwd */
	temp = getcwd(cwd, BUF_SIZE);
	if ((temp == NULL) || (cwd[0] == '\0')) {
		if( strerror_r(errno, buf, sizeof(buf)) == 0) {
			_LOGE("getcwd() failed. [%d][%s]", errno, buf);
		}
		ret = RPM_INSTALLER_ERR_INTERNAL;
		goto err;

	}
	_LOGD("current working directory, path=[%s]", cwd);

	/* change dir */
	ret = chdir(root_path);
	if (ret != 0) {
		if( strerror_r(errno, buf, sizeof(buf)) == 0) {
			_LOGE("chdir(%s) failed. [%d][%s]", root_path, errno, buf);
		}
		ret = RPM_INSTALLER_ERR_INTERNAL;
		goto err;

	}

	/* check for signature and certificate */
	ret = _coretpk_installer_verify_signatures(root_path, pkgid, &visibility, pkg_file_info->sig_capath);
	if (ret != 0) {
		_LOGE("_coretpk_installer_verify_signatures(%s, %s) failed. ret=[%d]", root_path, pkgid, ret);
		goto err;
	} else {
		_LOGD("signature and certificate are verified successfully.");

		if (update == true) {
			ret = __compare_author_public_key(pkgid);
			if (ret < 0) {
				_LOGE("__compare_author_public_key(%s) failed.", pkgid);
				ret = RPM_INSTALLER_ERR_SIG_VERIFICATION_FAILED;
				goto err;
			}
			_LOGD("#author public key verifying success");
		}
	}

	/* Check privilege and visibility */
	ret = _coretpk_installer_verify_privilege_list(pkgid, pkg_file_info, visibility);
	if (ret != 0) {
		goto err;
	}

	/* chdir */
	ret = chdir(cwd);
	if (ret != 0) {
		if( strerror_r(errno, buf, sizeof(buf)) == 0) {
			_LOGE("chdir(%s) failed. [%d][%s]", cwd, errno, buf);
		}
		ret = RPM_INSTALLER_ERR_INTERNAL;
		goto err;

	}

	/* convert manifest and copy the file */
	ret = _coretpk_parser_convert_manifest(tizen_manifest, pkgid, pkg_file_info->client_id, false, visibility, optional_data);
	if (ret != 0) {
		_LOGE("failed to convert the manifest.");
		ret = RPM_INSTALLER_ERR_INVALID_MANIFEST;
		goto err;
	}
	_LOGD("manifest is converted successfully.");

	if (strstr(pkgfile, ".wgt") != NULL) {
		_LOGD("wgt file=[%s]", pkgfile);

		if (strstr(tizen_manifest, OPT_USR_APPS)) {
			snprintf(rwmanifest, BUF_SIZE, "%s/%s.xml", OPT_SHARE_PACKAGES, pkgid);
			const char *rw_xml_category[] = { CORETPK_CATEGORY_CONVERTER, rwmanifest, NULL };
			ret = _ri_xsystem(rw_xml_category);
			if (ret != 0) {
				_LOGE("coretpk_category_converter failed for [%s], return [%d].", rwmanifest, ret);
				ret = RPM_INSTALLER_ERR_INVALID_MANIFEST;
				goto err;
			}
		}
	}

	/* check the manifest file. */
	if (pkg_file_info->is_preload == true) {
		snprintf(system_manifest, BUF_SIZE, "%s/%s.xml", USR_SHARE_PACKAGES, pkgid);
	} else {
		snprintf(system_manifest, BUF_SIZE, "%s/%s.xml", OPT_SHARE_PACKAGES, pkgid);
	}

	/* compare manifest.xml with schema file(/usr/etc/package-manager/preload/manifest.xsd) */
	_LOGD("[start] check_manifest_validation(%s)", system_manifest);
	ret = pkgmgr_parser_check_manifest_validation(system_manifest);
	if (ret < 0) {
		_LOGE("invalid manifest file(schema)");
		ret = RPM_INSTALLER_ERR_INVALID_MANIFEST;
		goto err;
	}
	_LOGD("[end] check_manifest_validation(%s)", system_manifest);

	snprintf(res_xml, BUF_SIZE, "%s/%s/%s", OPT_USR_APPS, pkgid, RES_XML);
	/* check existance of /opt/usr/apps/pkgid/res/res.xml* for backward compatibility */
	if (access(res_xml, R_OK) == 0) {
		/* validate it */
		ret = pkgmgr_resource_parser_check_xml_validation(res_xml);
		if (ret < 0) {
			_LOGE("failed to validate resource xml");
			ret = RPM_INSTALLER_ERR_INTERNAL;
			goto err;
		}
	}

	/* Parse the manifest to get install location and size. If installation fails, remove manifest info from DB */
	if (update == false) {
		_LOGD("[start] parse_manifest_for_installation(%s)", system_manifest);
		ret = pkgmgr_parser_parse_manifest_for_installation(system_manifest, NULL);
		if (ret < 0) {
			_LOGE("failed to parse the manifest.");
			ret = RPM_INSTALLER_ERR_INTERNAL;
			goto err;
		}
		_LOGD("[end] parse_manifest_for_installation(%s)", system_manifest);
	} else {
		_LOGD("[start] parse_manifest_for_upgrade(%s)", system_manifest);
		ret = pkgmgr_parser_parse_manifest_for_upgrade(system_manifest, NULL);
		if (ret < 0) {
			_LOGE("pkgmgr_parser_parse_manifest_for_upgrade(%s) failed.", system_manifest);
			ret = RPM_INSTALLER_ERR_INTERNAL;
			goto err;
		}
		_LOGD("[end] parse_manifest_for_upgrade(%s)", system_manifest);

		/* clean */
		_ri_unregister_cert(pkgid);
		_ri_privilege_unregister_package(pkgid);
	}
	_LOGD("manifest parsing done successfully.");

	/* search_ug_app */
	_coretpk_installer_search_ui_gadget(pkgid);

	/* register cert info */
	_ri_register_cert(pkgid);

#ifdef _APPFW_FEATURE_EXPANSION_PKG_INSTALL
	if (is_tpk_and_tep == true)
		_ri_broadcast_status_notification(pkgid, PKGTYPE_TPK, "install_percent", "40");
	else
#endif
		_ri_broadcast_status_notification(pkgid, PKGTYPE_TPK, "install_percent", "60");

	/* make directory */
	ret = _coretpk_installer_make_directory(pkgid, pkg_file_info->is_preload);
	if (ret != 0) {
		_LOGE("failed to make the directory.");
		goto err;
	}

	/* apply smack to app dir */
	ret = _coretpk_installer_apply_smack(pkgid, 1);
	if (ret != 0) {
		_LOGE("failed to apply the smack.");
		goto err;
	}

	/* apply privilege for widget */
	if (pkg_file_info->is_widget == true) {
		const char *perm[] = { "http://developer.samsung.com/tizen/privilege/dynamicbox.provider", NULL };
		ret = _ri_privilege_enable_permissions(pkgid, PERM_APP_TYPE_EFL, perm, 1);
		if (ret != 0) {
			_LOGE("_ri_privilege_enable_permissions(privilege/dynamicbox.provider) failed.");
		} else {
			_LOGD("_ri_privilege_enable_permissions(privilege/dynamicbox.provider) succeeded for widget.");
		}
	}

	/* apply smack by privilege */
	ret = _ri_apply_privilege(pkgid, visibility, NULL);
	if (ret != 0) {
		_LOGE("failed to apply permission, ret=[%d]", ret);
	}
	_LOGD("permission applying done successfully.");

#ifdef _APPFW_FEATURE_EXPANSION_PKG_INSTALL
	if (is_tpk_and_tep == true)
		_ri_broadcast_status_notification(pkgid, PKGTYPE_TPK, "install_percent", "50");
	else
#endif
	_ri_broadcast_status_notification(pkgid, PKGTYPE_TPK, "install_percent", "100");
	ret = RPM_INSTALLER_SUCCESS;

err:
	if (update == false) {
		/* post_install */
		if (ret != 0) {
			install_status = APP2EXT_STATUS_FAILED;
		}
		_LOGD("install status is [%d].", install_status);

		if (__post_install_for_mmc(handle, pkgid, dir_list, install_status, pkg_file_info->install_location) < 0) {
			_LOGE("__post_install_for_mmc is failed.");
			ret = -1;
		}
	} else {
		/* post_upgrade */
		if (__post_upgrade_for_mmc(handle, pkgid, dir_list, storage) < 0) {
			_LOGE("__post_upgrade_for_mmc is failed.");
			ret = -1;
		}
	}

	if (optional_data) {
		bundle_free(optional_data);
	}

	if (pkginfo_handle) {
		pkgmgrinfo_pkginfo_destroy_pkginfo(pkginfo_handle);
	}

	if (ret == 0) {
		_LOGD("_coretpk_installer_install_package is done.");

		// signature1.xml
		snprintf(signature1, BUF_SIZE, "%s/%s/%s", OPT_USR_APPS, pkgid, SIGNATURE1_XML);
		if (access(signature1, F_OK) == 0) {
			_LOGD("signature1 file is deleted. [%s]", signature1);
			(void)remove(signature1);
		}
#ifdef _APPFW_FEATURE_EXPANSION_PKG_INSTALL
		if (is_tpk_and_tep == false)
#endif
		_ri_broadcast_status_notification(pkgid, PKGTYPE_TPK, "end", "ok");
	} else {
		if ((update == false) && (directory_install == false)) {
			/* remove db info */
			_coretpk_installer_remove_db_info(pkgid);

			/* remove xml */
			if (access(system_manifest, F_OK) == 0) {
				(void)remove(system_manifest);
			}

			/* remove app dir(root_path) */
			if (__is_dir(root_path)) {
				_installer_util_delete_dir(root_path);
			}

			/* remove ext app dir(/opt/storage/sdcard/apps/pkgid) */
			char extpath[BUF_SIZE] = { '\0' };
			snprintf(extpath, BUF_SIZE, "%s/%s", OPT_STORAGE_SDCARD_APP_ROOT, pkgid);
			if (__is_dir(extpath)) {
				_installer_util_delete_dir(extpath);
			}
		}

		char *errorstr = NULL;
		if (ret < RPM_INSTALLER_ERR_PRIVILEGE_UNAUTHORIZED || ret > RPM_INSTALLER_ERR_PRIVILEGE_USING_LEGACY_FAILED) {
			_ri_error_no_to_string(ret, &errorstr);
			_ri_broadcast_status_notification(pkgid, PKGTYPE_TPK, "error", errorstr);
		}
		sleep(2);

		_LOGE("_coretpk_installer_install_package(%s) failed.", pkgid);
		_ri_broadcast_status_notification(pkgid, PKGTYPE_TPK, "end", "fail");
	}

	return ret;
}

int _coretpk_installer_uninstall_package(const char *pkgid)
{
	retvm_if(pkgid == NULL, RPM_INSTALLER_ERR_WRONG_PARAM, "pkgid is NULL.");

	int ret = 0;
	int update_system = 0;

	update_system = __check_updated_system_package(pkgid);
	if (update_system == 1) {
		_LOGD("start remove_update, pkgid=[%s]", pkgid);
		ret = __pkg_remove_update(pkgid);
	} else {
		_LOGD("start uninstall, pkgid=[%s]", pkgid);
		ret = _rpm_uninstall_pkg_with_dbpath(pkgid, 0);
	}

	if (ret < 0) {
		_LOGE("uninstallation is failed, pkgid=[%s], update_system=[%d]", pkgid, update_system);
	} else {
		_LOGD("uninstallation is done successfully, pkgid=[%s]", pkgid);
	}

	return ret;
}

int _coretpk_installer_prepare_package_install(const char *pkg_file, const char *client_id, bool preload, const cmdinfo * cmd_info)
{
	retvm_if(pkg_file == NULL, RPM_INSTALLER_ERR_WRONG_PARAM, "pkg_file is NULL.");

	int ret = 0;
	pkginfo *pkg_file_info = NULL;

	pkg_file_info = _coretpk_installer_get_pkgfile_info(pkg_file, CORETPK_INSTALL_CMD);
	tryvm_if(pkg_file_info == NULL, ret = RPM_INSTALLER_ERR_PACKAGE_INVALID, "_coretpk_installer_get_pkgfile_info(%s) failed.", pkg_file);
	tryvm_if(strlen(pkg_file_info->package_name) == 0, ret = RPM_INSTALLER_ERR_PACKAGE_INVALID, "package_name is invalid. (len=0)");

	if (client_id) {
		strncpy(pkg_file_info->client_id, client_id, sizeof(pkg_file_info->client_id) - 1);
	}

	pkg_file_info->is_preload = preload;
	if (cmd_info) {
		pkg_file_info->support_disable = cmd_info->support_disable;
	}

	ret = _coretpk_installer_install_package(pkg_file, pkg_file_info);
	if (ret != 0) {
		_LOGE("_coretpk_installer_prepare_package_install(%s) failed. ret=[%d]", pkg_file, ret);
	} else {
		_LOGD("[%s] is installed successfully.", pkg_file);
	}

catch:
	if (ret == RPM_INSTALLER_ERR_PACKAGE_INVALID) {
		_ri_broadcast_status_notification("Invalid package", "invalid", "start", "install");
		_ri_broadcast_status_notification("Invalid package", "invalid", "end", "fail");
	}

	if (pkg_file_info) {
		_installer_util_free_pkg_info(pkg_file_info);
		pkg_file_info = NULL;
	}

	return ret;
}

int _coretpk_installer_prepare_package_install_with_debug(const char *pkg_file, const char *client_id, bool preload, const cmdinfo * cmd_info)
{
	retvm_if(pkg_file == NULL, RPM_INSTALLER_ERR_WRONG_PARAM, "pkg_file is NULL.");

	int ret = 0;
	pkginfo *pkg_file_info = NULL;

	pkg_file_info = _coretpk_installer_get_pkgfile_info(pkg_file, CORETPK_INSTALL_CMD);
	tryvm_if(pkg_file_info == NULL, ret = -2, "_coretpk_installer_get_pkgfile_info(%s) failed.", pkg_file);
	tryvm_if(strlen(pkg_file_info->package_name) == 0, ret = -2, "package_name is invalid. (len=0)");

	if (client_id) {
		strncpy(pkg_file_info->client_id, client_id, sizeof(pkg_file_info->client_id) - 1);
	}

	pkg_file_info->is_preload = preload;
	if (cmd_info) {
		pkg_file_info->support_disable = cmd_info->support_disable;
	}

	ret = _coretpk_installer_install_package(pkg_file, pkg_file_info);
	if (ret != 0) {
		_LOGE("_coretpk_installer_prepare_package_install(%s) failed. ret=[%d]", pkg_file, ret);
	} else {
		_LOGD("[%s] is installed successfully.", pkg_file);

		/* apply privilege for debug_mode */
		const char *perm[] = { "http://tizen.org/privilege/appdebugging", NULL };
		ret = _ri_privilege_enable_permissions(pkg_file_info->package_name, PERM_APP_TYPE_EFL, perm, 1);
		if (ret != 0) {
			_LOGE("_ri_privilege_enable_permissions(privilege/appdebuging) failed.");
		} else {
			_LOGD("_ri_privilege_enable_permissions(privilege/appdebuging succeeded for debug_mode.");
		}
	}

catch:
	if (ret == -2) {
		_ri_broadcast_status_notification("Invalid package", "invalid", "start", "install");
		_ri_broadcast_status_notification("Invalid package", "invalid", "end", "fail");
	}

	if (pkg_file_info) {
		_installer_util_free_pkg_info(pkg_file_info);
		pkg_file_info = NULL;
	}

	return ret;
}

int _coretpk_installer_prepare_package_uninstall(const char *pkgid)
{
	retvm_if(pkgid == NULL, RPM_INSTALLER_ERR_WRONG_PARAM, "pkgid is NULL.");

	int ret = 0;
	pkginfo *dbinfo = NULL;

	dbinfo = _rpm_installer_get_pkgname_info(pkgid);
	if (dbinfo == NULL) {
		_LOGE("[%s] is not installed.", pkgid);
		return RPM_INSTALLER_ERR_PACKAGE_NOT_INSTALLED;
	}

	ret = _coretpk_installer_uninstall_package(pkgid);
	if (ret != 0) {
		_LOGE("_coretpk_installer_uninstall_package() failed, pkgid=[%s], ret=[%d]", pkgid, ret);
	} else {
		_LOGD("_coretpk_installer_uninstall_package() is done successfully, pkgid=[%s]", pkgid);
	}

	if (dbinfo) {
		free(dbinfo);
		dbinfo = NULL;
	}

	return ret;
}

int _coretpk_installer_prepare_preload_install(const char *dirpath, const char *clientid, const cmdinfo * cmd_info)
{
	retvm_if(dirpath == NULL, RPM_INSTALLER_ERR_WRONG_PARAM, "dirpath is NULL.");

	int ret = 0;
	_LOGD("path=[%s], clientid=[%s]", dirpath, clientid);

	ret = _coretpk_installer_prepare_package_install(dirpath, clientid, true, cmd_info);
	return ret;
}

#ifdef _APPFW_FEATURE_MOUNT_INSTALL
int _coretpk_installer_mount_install_create_symbolic_links(const char *pkgfile, const char *pkgid)
{
	int ret = PMINFO_R_OK;
	size_t filename_len;
	char tmp[BUF_SIZE] = {'\0'};
	char *slink_from = NULL;
	char *slink_to = NULL;
	char *filename = NULL;

	unzFile uzf = unzOpen64(pkgfile);
	if (uzf == NULL) {
		_LOGE("Fail to open item : %s", pkgfile);
		return PMINFO_R_ERROR;
	} else {
		ret = unzGoToFirstFile(uzf);
		if (ret != UNZ_OK) {
			_LOGE("error get first zip file ");
			unzClose(uzf);
			return PMINFO_R_ERROR;
		} else {
			do {
				ret = unzOpenCurrentFile(uzf);
				if (ret != UNZ_OK) {
					_LOGE("error unzOpenCurrentFile ");
					unzClose(uzf);
					return PMINFO_R_ERROR;
				}

				unz_file_info fileInfo = { 0 };
				filename = (char *)calloc(1, BUF_SIZE);
				ret = unzGetCurrentFileInfo(uzf, &fileInfo, filename, (BUF_SIZE - 1), NULL, 0, NULL, 0);
				if(ret != UNZ_OK) {
					_LOGE("error unzGetCurrentFileInfo ");
					unzClose(uzf);
					return PMINFO_R_ERROR;
				}

				filename_len = strlen(filename);
				_LOGE("\n\nFilename: [%s], len:[%d]", filename, filename_len);

				/* If it is 1st level directory (like opt/not internal like opt/usr/) or just a file then create symbolic links */
				if( (((strchr(filename, '/') -filename) == filename_len -1) || (strchr(filename, '/') == NULL)) && strstr(filename, "bin/") == NULL) {

					_LOGE("Creating symlink Filename: [%s]\n\n", filename);

					if(((strchr(filename, '/') -filename) == filename_len -1)){
						filename[filename_len -1] = '\0';
					}
					memset(tmp, '\0', BUF_SIZE);
					snprintf(tmp, BUF_SIZE, "%s/%s/%s", OPT_USR_APPS, pkgid, filename);
					slink_from = strdup(tmp);

					memset(tmp, '\0', BUF_SIZE);
					snprintf(tmp, BUF_SIZE, "%s/%s/.pkg/%s", OPT_USR_APPS, pkgid, filename);
					slink_to = strdup(tmp);

					if ((ret = symlink(slink_to, slink_from)) < 0) {
						if (errno == EEXIST) {
							_LOGE("File with Symlink name present %s\n", slink_from);
						} else {
							char buf[BUF_SIZE] = { 0, };
							if( strerror_r(errno, buf, sizeof(buf)) == 0) {
								_LOGE("Symbolic link creation failed, error is [%s]\n", buf);
							}
							goto catch;
						}
					}

					FREE_AND_NULL(slink_from);
					FREE_AND_NULL(slink_to);

				}


				FREE_AND_NULL(filename);
			} while (unzGoToNextFile(uzf) == UNZ_OK);
		}
	}
catch:
	FREE_AND_NULL(slink_from);
	FREE_AND_NULL(slink_to);
	FREE_AND_NULL(filename);

	unzClose(uzf);
	return ret;

}

int _coretpk_installer_mount_install_package(const char *pkgfile, const pkginfo * pkg_file_info)
{
	retvm_if(pkgfile == NULL, RPM_INSTALLER_ERR_WRONG_PARAM, "pkgfile is NULL.");
	retvm_if(pkg_file_info == NULL, RPM_INSTALLER_ERR_WRONG_PARAM, "pkg_file_info is NULL.");

	int ret = 0;
	int visibility = 0;
	int install_status = APP2EXT_STATUS_SUCCESS;
	char root_path[BUF_SIZE] = { 0, };
	char tizen_manifest[BUF_SIZE] = { 0, };
	char system_manifest[BUF_SIZE] = { 0, };
	char cwd[BUF_SIZE] = { 0, };
	char rwmanifest[BUF_SIZE] = { 0, };
	char res_xml[BUF_SIZE] = { 0, };
	char signature1[BUF_SIZE] = { 0, };
	char *temp = NULL;
	const char *pkgid = pkg_file_info->package_name;
	bool update = false;
	bool directory_install = false;
	pkgmgrinfo_pkginfo_h pkginfo_handle = NULL;
	pkgmgrinfo_installed_storage storage = PMINFO_INTERNAL_STORAGE;
	app2ext_handle *handle = NULL;
	bundle *optional_data = NULL;

	char *mnt_path[2] = {NULL, };
	char tpk_path[BUF_SIZE] = {0, };
	char buf[BUF_SIZE] = { 0, };


	optional_data = bundle_create();
	if (optional_data) {
		if (pkg_file_info->support_disable == true) {
			bundle_add_str(optional_data, "support-disable", "true");
		}
	}

	if (__is_dir(pkgfile)) {
		_LOGD("Directory install(preload)");
		directory_install = true;
	}

	snprintf(root_path, BUF_SIZE, "%s/%s/", OPT_USR_APPS, pkgid);
	snprintf(tizen_manifest, BUF_SIZE, "%s/%s/%s", OPT_USR_APPS, pkgid, CORETPK_XML);

	ret = pkgmgrinfo_pkginfo_get_pkginfo(pkgid, &pkginfo_handle);
	if (ret < 0) {
		_LOGD("------------------------------------------");
		_LOGD("Install - [%s][%s]", pkgid, pkgfile);
		_LOGD("------------------------------------------");

		_ri_broadcast_status_notification(pkgid, PKGTYPE_TPK, "start", "install");

	} else {
		_LOGD("------------------------------------------");
		_LOGD("Update - [%s][%s]", pkgid, pkgfile);
		_LOGD("------------------------------------------");

		update = true;
		_ri_broadcast_status_notification(pkgid, PKGTYPE_TPK, "start", "update");

		/* terminate running app */
		__terminate_running_app(pkgid);

		ret = pkgmgrinfo_pkginfo_get_installed_storage(pkginfo_handle, &storage);
		if (ret != 0) {
			_LOGE("pkgmgrinfo_pkginfo_get_installed_storage(%s) failed.", pkgid);
			ret = RPM_INSTALLER_ERR_INTERNAL;
			goto err;
		}

		/* remove dir for clean */
		if (directory_install == false) {
			_installer_util_delete_dir(root_path);
		}
	}

#ifdef _APPFW_FEATURE_EXPANSION_PKG_INSTALL
	if (is_tpk_and_tep == true)
		_ri_broadcast_status_notification(pkgid, PKGTYPE_TPK, "install_percent", "20");
	else
#endif
		_ri_broadcast_status_notification(pkgid, PKGTYPE_TPK, "install_percent", "30");

#if 0
	/* install package */
	if (directory_install == false) {
		_LOGD("[start] unzip(%s)", pkgfile);
		const char *unzip_argv[] = { "/usr/bin/unzip", "-o", pkgfile, "-d", root_path, NULL };
		ret = _ri_xsystem(unzip_argv);
		if (ret != 0) {
			_LOGE("failed to unzip for path=[%s], ret=[%d]", root_path, ret);
			ret = RPM_INSTALLER_ERR_UNZIP_FAILED;
			goto err;
		}
		_LOGD("[end] unzip(%s)", root_path);
	}
#else
	if(access(root_path, F_OK) == 0){
		_installer_util_delete_dir(root_path);
	}

	ret = _installer_util_mkpath(root_path, DIRECTORY_PERMISSION_755);
	if(ret){
		if( strerror_r(errno, buf, sizeof(buf)) == 0) {
			_LOGE("unable to create dir, [%s], error: [%s]", root_path, buf);
		}
	}

	_LOGD("[start] unzip(%s/bin)", pkgfile);
	const char *unzip_argv[] = { "/usr/bin/unzip", "-oqq", pkgfile, "bin/*", "-d", root_path, NULL };
	ret = _ri_xsystem(unzip_argv);
	if (ret != 0) {
		_LOGE("failed to unzip for path=[%s], ret=[%d]", root_path, ret);
		ret = RPM_INSTALLER_ERR_UNZIP_FAILED;
		goto err;
	}
	_LOGD("[end] unzip(%s/bin)", root_path);

	_LOGD("[start] unzip(%s/shared/res/*.png)", pkgfile);
	memset(tpk_path, 0, BUF_SIZE);
	snprintf(tpk_path, BUF_SIZE, "%s/%s/icon/", OPT_USR_APPS, pkgid);
	const char *unzip_argv1[] = { "/usr/bin/unzip", "-ojqq", pkgfile, "shared/res/*.png", "-d", tpk_path, NULL };
	ret = _ri_xsystem(unzip_argv1);
	if (ret != 0) {
		_LOGE("failed to unzip for path=[%s], ret=[%d]", root_path, ret);
		ret = RPM_INSTALLER_ERR_UNZIP_FAILED;
		goto err;
	}
	_LOGD("[end] unzip(%s/bin)", tpk_path);

	snprintf(tpk_path, BUF_SIZE, "%s/%s/.pkg", OPT_USR_APPS, pkgid);
	_LOGE("tpk mount path: [%s]",tpk_path);
	mnt_path[0] = strdup(tpk_path);
	memset(tpk_path, 0, BUF_SIZE);

	char *filename = strrchr(pkgfile, '/');
	filename++;
	snprintf(tpk_path, BUF_SIZE, "%s/%s", USR_PACKAGES, filename);
	_LOGE("tpk filename: [%s]",tpk_path);
	mnt_path[1] = strdup(tpk_path);

	ret = _coretpk_dbus_is_mount_done(mnt_path[0]);
	if(ret != 1) {
		ret = _coretpk_dbus_mount_file(mnt_path, pkgid);
		if(ret){
			if( strerror_r(errno, buf, sizeof(buf)) == 0) {
				_LOGE("DBUS Error: err: [%s]", buf);
			}
			goto err;
		}
		ret = _coretpk_dbus_wait_for_tep_mount(mnt_path[0]);
		if(ret != 0){
			ret = RPM_INSTALLER_ERR_INTERNAL;
			_LOGE("Unable to mount the tpk file");
			goto err;
		}
	}

	_coretpk_installer_mount_install_create_symbolic_links(pkgfile, pkgid);

#endif

	/* getcwd */
	temp = getcwd(cwd, BUF_SIZE);
	if ((temp == NULL) || (cwd[0] == '\0')) {
		if( strerror_r(errno, buf, sizeof(buf)) == 0) {
			_LOGE("getcwd() failed. [%d][%s]", errno, buf);
		}
		ret = RPM_INSTALLER_ERR_INTERNAL;
		goto err;
	}
	_LOGD("current working directory, path=[%s]", cwd);

	/* change dir */
	ret = chdir(root_path);
	if (ret != 0) {
		if( strerror_r(errno, buf, sizeof(buf)) == 0) {
			_LOGE("chdir(%s) failed. [%d][%s]", root_path, errno, buf);
		}
		ret = RPM_INSTALLER_ERR_INTERNAL;
		goto err;
	}

	/* check for signature and certificate */
	ret = _coretpk_installer_verify_signatures(root_path, pkgid, &visibility, pkg_file_info->sig_capath);
	if (ret != 0) {
		_LOGE("_coretpk_installer_verify_signatures(%s, %s) failed. ret=[%d]", root_path, pkgid, ret);
		goto err;
	} else {
		_LOGD("signature and certificate are verified successfully.");

		if (update == true) {
			ret = __compare_author_public_key(pkgid);
			if (ret < 0) {
				_LOGE("__compare_author_public_key(%s) failed.", pkgid);
				ret = RPM_INSTALLER_ERR_SIG_VERIFICATION_FAILED;
				goto err;
			}
			_LOGD("#author public key verifying success");
		}
	}

	/* Check privilege and visibility */
	ret = _coretpk_installer_verify_privilege_list(pkgid, pkg_file_info, visibility);
	if (ret != 0) {
		goto err;
	}

	/* chdir */
	ret = chdir(cwd);
	if (ret != 0) {
		if( strerror_r(errno, buf, sizeof(buf)) == 0) {
			_LOGE("chdir(%s) failed. [%d][%s]", cwd, errno, buf);
		}
		ret = RPM_INSTALLER_ERR_INTERNAL;
		goto err;
	}

	/* convert manifest and copy the file */
	ret = _coretpk_mount_install_parser_convert_manifest(tizen_manifest, pkgid, pkg_file_info->client_id, false, visibility, optional_data);
	if (ret != 0) {
		_LOGE("failed to convert the manifest.");
		ret = RPM_INSTALLER_ERR_INVALID_MANIFEST;
		goto err;
	}
	_LOGD("manifest is converted successfully.");

	if (strstr(pkgfile, ".wgt") != NULL) {
		_LOGD("wgt file=[%s]", pkgfile);

		if (strstr(tizen_manifest, OPT_USR_APPS)) {
			snprintf(rwmanifest, BUF_SIZE, "%s/%s.xml", OPT_SHARE_PACKAGES, pkgid);
			const char *rw_xml_category[] = { CORETPK_CATEGORY_CONVERTER, rwmanifest, NULL };
			ret = _ri_xsystem(rw_xml_category);
			if (ret != 0) {
				_LOGE("coretpk_category_converter failed for [%s], return [%d].", rwmanifest, ret);
				ret = RPM_INSTALLER_ERR_INVALID_MANIFEST;
				goto err;
			}
		}
	}

	snprintf(system_manifest, BUF_SIZE, "%s/%s.xml", OPT_SHARE_PACKAGES, pkgid);

	/* compare manifest.xml with schema file(/usr/etc/package-manager/preload/manifest.xsd) */
	_LOGD("[start] check_manifest_validation(%s)", system_manifest);
	ret = pkgmgr_parser_check_manifest_validation(system_manifest);
	if (ret < 0) {
		_LOGE("invalid manifest file(schema)");
		ret = RPM_INSTALLER_ERR_INVALID_MANIFEST;
		goto err;
	}
	_LOGD("[end] check_manifest_validation(%s)", system_manifest);

	/* Parse the manifest to get install location and size. If installation fails, remove manifest info from DB */
	if (update == false) {
		_LOGD("[start] parse_manifest_for_installation(%s)", system_manifest);
		ret = pkgmgr_parser_parse_manifest_for_installation(system_manifest, NULL);
		if (ret < 0) {
			_LOGE("failed to parse the manifest.");
			ret = RPM_INSTALLER_ERR_INTERNAL;
			goto err;
		}
		_LOGD("[end] parse_manifest_for_installation(%s)", system_manifest);
	} else {
		_LOGD("[start] parse_manifest_for_upgrade(%s)", system_manifest);
		ret = pkgmgr_parser_parse_manifest_for_upgrade(system_manifest, NULL);
		if (ret < 0) {
			_LOGE("pkgmgr_parser_parse_manifest_for_upgrade(%s) failed.", system_manifest);
			ret = RPM_INSTALLER_ERR_INTERNAL;
			goto err;
		}
		_LOGD("[end] parse_manifest_for_upgrade(%s)", system_manifest);

		/* clean */
		_ri_unregister_cert(pkgid);
		_ri_privilege_unregister_package(pkgid);
	}
	_LOGD("manifest parsing done successfully.");

	filename = strrchr(pkgfile, '/');
	filename++;
	ret = pkgmgr_parser_insert_mount_install_info(pkgid, true, filename);
	if (ret < 0) {
		_LOGE("pkgmgr_parser_insert_mount_install_info(%s) failed.", pkgfile);
		ret = RPM_INSTALLER_ERR_INTERNAL;
		goto err;
	}


	/* search_ug_app */
	_coretpk_installer_search_ui_gadget(pkgid);

	/* register cert info */
	_ri_register_cert(pkgid);

#ifdef _APPFW_FEATURE_EXPANSION_PKG_INSTALL
	if (is_tpk_and_tep == true)
		_ri_broadcast_status_notification(pkgid, PKGTYPE_TPK, "install_percent", "40");
	else
#endif
		_ri_broadcast_status_notification(pkgid, PKGTYPE_TPK, "install_percent", "60");

#if 0
	/* make directory */
	ret = _coretpk_installer_make_directory(pkgid, pkg_file_info->is_preload);
	if (ret != 0) {
		_LOGE("failed to make the directory.");
		goto err;
	}

	/* apply smack to app dir */
	ret = _coretpk_installer_apply_smack(pkgid, 1);
	if (ret != 0) {
		_LOGE("failed to apply the smack.");
		goto err;
	}
#else

	/* make directory */
	ret = _coretpk_installer_mount_install_make_directory(pkgid, pkg_file_info->is_preload);
	if (ret != 0) {
		_LOGE("failed to make the directory.");
		goto err;
	}

	/* apply smack to app dir */
	ret = _coretpk_installer_apply_smack(pkgid, 1);
	if (ret != 0) {
		_LOGE("failed to apply the smack.");
		goto err;
	}

#endif

	/* apply privilege for widget */
	if (pkg_file_info->is_widget == true) {
		const char *perm[] = { "http://developer.samsung.com/tizen/privilege/dynamicbox.provider", NULL };
		ret = _ri_privilege_enable_permissions(pkgid, PERM_APP_TYPE_EFL, perm, 1);
		if (ret != 0) {
			_LOGE("_ri_privilege_enable_permissions(privilege/dynamicbox.provider) failed.");
		} else {
			_LOGD("_ri_privilege_enable_permissions(privilege/dynamicbox.provider) succeeded for widget.");
		}
	}

	/* apply smack by privilege */
	ret = _ri_apply_privilege(pkgid, visibility, NULL);
	if (ret != 0) {
		_LOGE("failed to apply permission, ret=[%d]", ret);
	}

	_LOGD("permission applying done successfully.");

#ifdef _APPFW_FEATURE_EXPANSION_PKG_INSTALL
	if (is_tpk_and_tep == true)
		_ri_broadcast_status_notification(pkgid, PKGTYPE_TPK, "install_percent", "50");
	else
#endif
	_ri_broadcast_status_notification(pkgid, PKGTYPE_TPK, "install_percent", "100");
	ret = RPM_INSTALLER_SUCCESS;

err: ;

	int res = _coretpk_dbus_unmount_file(mnt_path[0]);
	if(res){
		_LOGE("TPK Unmount Error");
	}
	sleep(2);
	FREE_AND_NULL(mnt_path[0]);
	FREE_AND_NULL(mnt_path[1]);

	if (optional_data) {
		bundle_free(optional_data);
	}

	if (pkginfo_handle) {
		pkgmgrinfo_pkginfo_destroy_pkginfo(pkginfo_handle);
	}

	if (ret == 0) {
		_LOGD("_coretpk_installer_install_package is done.");

		// signature1.xml
		snprintf(signature1, BUF_SIZE, "%s/%s/%s", OPT_USR_APPS, pkgid, SIGNATURE1_XML);
		if (access(signature1, F_OK) == 0) {
			_LOGD("signature1 file is deleted. [%s]", signature1);
			(void)remove(signature1);
		}
#ifdef _APPFW_FEATURE_EXPANSION_PKG_INSTALL
		if (is_tpk_and_tep == false)
#endif
		_ri_broadcast_status_notification(pkgid, PKGTYPE_TPK, "end", "ok");
	} else {
		if ((update == false) && (directory_install == false)) {
			/* remove db info */
			_coretpk_installer_remove_db_info(pkgid);

			/* remove xml */
			if (access(system_manifest, F_OK) == 0) {
				(void)remove(system_manifest);
			}

			/* remove app dir(root_path) */
			if (__is_dir(root_path)) {
				_installer_util_delete_dir(root_path);
			}

		}

		char *errorstr = NULL;
		if (ret < RPM_INSTALLER_ERR_PRIVILEGE_UNAUTHORIZED || ret > RPM_INSTALLER_ERR_PRIVILEGE_USING_LEGACY_FAILED) {
			_ri_error_no_to_string(ret, &errorstr);
			_ri_broadcast_status_notification(pkgid, PKGTYPE_TPK, "error", errorstr);
		}

		_LOGE("_coretpk_installer_install_package(%s) failed.", pkgid);
		_ri_broadcast_status_notification(pkgid, PKGTYPE_TPK, "end", "fail");
	}

	return ret;
}

int _coretpk_installer_prepare_mount_install(const char *pkg_file, const char *client_id, bool preload, const cmdinfo * cmd_info)
{
	retvm_if(pkg_file == NULL, RPM_INSTALLER_ERR_WRONG_PARAM, "pkg_file is NULL.");

	int ret = 0;
	pkginfo *pkg_file_info = NULL;

	char dest_tpk_path[BUF_SIZE] = {'\0'};

	/* Copy ".tpk" file to /opt/usr/share/packages/xxx.tpk */
	char *filename = strrchr(pkg_file, '/');
	filename++;
	snprintf(dest_tpk_path, PKG_MAX_LEN, "%s/%s", USR_PACKAGES,filename);
	if(strcmp(pkg_file, dest_tpk_path) != 0){
		ret = _installer_util_copy_file(pkg_file, dest_tpk_path);
	}

	pkg_file_info = _coretpk_installer_get_pkgfile_info(pkg_file, CORETPK_INSTALL_CMD);
	tryvm_if(pkg_file_info == NULL, ret = RPM_INSTALLER_ERR_PACKAGE_INVALID, "_coretpk_installer_get_pkgfile_info(%s) failed.", pkg_file);
	tryvm_if(strlen(pkg_file_info->package_name) == 0, ret = RPM_INSTALLER_ERR_PACKAGE_INVALID, "package_name is invalid. (len=0)");

	if (client_id) {
		strncpy(pkg_file_info->client_id, client_id, sizeof(pkg_file_info->client_id) - 1);
	}

	pkg_file_info->is_preload = preload;
	if (cmd_info) {
		pkg_file_info->support_disable = cmd_info->support_disable;
	}

	ret = _coretpk_installer_mount_install_package(pkg_file, pkg_file_info);
	if (ret != 0) {
		_LOGE("_coretpk_installer_prepare_package_install(%s) failed. ret=[%d]", pkg_file, ret);
	} else {
		_LOGD("[%s] is installed successfully.", pkg_file);
	}

catch:
	if (ret == RPM_INSTALLER_ERR_PACKAGE_INVALID) {
		_ri_broadcast_status_notification("Invalid package", "invalid", "start", "install");
		_ri_broadcast_status_notification("Invalid package", "invalid", "end", "fail");
	}

	if (pkg_file_info) {
		_installer_util_free_pkg_info(pkg_file_info);
		pkg_file_info = NULL;
	}

	return ret;
}
#endif


#ifdef _APPFW_FEATURE_DELTA_UPDATE
/* This function reads the metadata file of the delta package and get the various info*/
static void __apply_privilege_for_ext_storage(const char *pkgid)
{
	int ret = 0;
	const char *perm[] = {EXT_STORAGE_PRIVILEGE, NULL};
	ret = _ri_privilege_enable_permissions(pkgid, PERM_APP_TYPE_EFL, perm, 1);
	_LOGD("add privilege_for_ext_storage(%s, %d) done.", pkgid, ret);
}

delta_info *_coretpk_installer_get_delta_info(const char *pkgfile)
{
	int ret = 0;
	delta_info *info = NULL;
	char *temp = NULL;
	char cwd[BUF_SIZE] = { 0 };
	char deltainfo_xml[BUF_SIZE] = { 0, };
	char coretpk_xml[BUF_SIZE] = { 0, };
	char *xmls = "*.xml";
	char buf[BUF_SIZE] = { 0, };

	/* Get the current working directory */
	temp = getcwd(cwd, BUF_SIZE);
	if ((temp == NULL) || (cwd[0] == '\0')) {
		if( strerror_r(errno, buf, sizeof(buf)) == 0) {
			_LOGE("getcwd() failed. [%d][%s]", errno, buf);
		}
		return NULL;
	}

	/* Creates the intermediate directory */
	ret = _installer_util_create_dir(TEMP_DIR, DIRECTORY_PERMISSION_644);
	if (ret < 0) {
		return NULL;
	}

	/* change the working diretory */
	ret = chdir(TEMP_DIR);
	if (ret != 0) {
		if( strerror_r(errno, buf, sizeof(buf)) == 0) {
			_LOGE("chdir(%s) failed. [%d][%s]", TEMP_DIR, errno, buf);
		}
		goto err;
	}
	_LOGD("TEMP_DIR=[%s]", TEMP_DIR);

	/* extract delta_info.xml from delta package */
	const char *unzip_argv[] = { "/usr/bin/unzip", "-oqq", pkgfile, xmls, "-d", TEMP_DIR, NULL };
	ret = _ri_xsystem(unzip_argv);
	if (ret != 0) {
		_LOGE("cannot info delta_info file in the package.");
		goto err;
	}

	snprintf(deltainfo_xml, BUF_SIZE, "%s/%s", TEMP_DIR, DELTATPK_XML);
	snprintf(coretpk_xml, BUF_SIZE, "%s/%s", TEMP_DIR, CORETPK_XML);

	if (access(deltainfo_xml, F_OK) != 0) {
		_LOGE("delta_info file [%s] is not present", deltainfo_xml);
		ret = RPM_INSTALLER_ERR_NO_MANIFEST;
		goto err;
	}
	_LOGD("delta info file=[%s]", deltainfo_xml);

	if (access(coretpk_xml, F_OK) != 0) {
		_LOGE("manifest file [%s] is not present", coretpk_xml);
		ret = RPM_INSTALLER_ERR_NO_MANIFEST;
		goto err;
	}
	_LOGD("manifest file=[%s]", coretpk_xml);

	/* Validate delta info file */
	ret = pkgmgr_parser_check_manifest_validation(deltainfo_xml);
	if (ret < 0) {
		_LOGE("invalid manifest file(schema) %s", deltainfo_xml);
		ret = RPM_INSTALLER_ERR_INVALID_MANIFEST;
		goto err;
	}

	/* Get the info from delta_info.xml */
	info = _coretpk_parser_get_delta_info(deltainfo_xml, coretpk_xml);
	if (info == NULL) {
		_LOGE("_coretpk_parser_get_manifest_info(%s) failed.", deltainfo_xml);
		ret = RPM_INSTALLER_ERR_INTERNAL;
		goto err;
	}

err:
	/* Delete the intermediate directory */
	_installer_util_delete_dir(TEMP_DIR);

	/* Handle failure */
	if (ret != 0) {
		if (info) {
			_installer_util_free_delta_info(info);
			info = NULL;
		}
	}

	/* Changed to old working directory */
	if (cwd[0] != '\0') {
		ret = chdir(cwd);
		if (ret != 0) {
			if( strerror_r(errno, buf, sizeof(buf)) == 0) {
				_LOGE("chdir(%s) failed. [%d][%s]", cwd, errno, buf);
			}
		}
	}

	return info;
}

int __coretpk_installer_delta_apply_file(char *pkgid, char *file)
{

	int ret = 0;
	char delta_file[BUF_SIZE] = { 0 };
	char from_file[BUF_SIZE] = { 0 };
	char to_file[BUF_SIZE] = { 0 };
	char buf[BUF_SIZE] = { 0, };
	int i = 0;

	snprintf(delta_file, BUF_SIZE, "%s/%s%s/%s", OPT_USR_APPS, pkgid, DELTA_DIR, file);
	snprintf(to_file, BUF_SIZE, "%s/%s%s/%s", OPT_USR_APPS, pkgid, NEW_DIR, file);
	snprintf(from_file, BUF_SIZE, "%s/%s%s/%s", OPT_USR_APPS, pkgid, NEW_DIR, file);

	/* Check whether old file is present or not */
	if (access(from_file, F_OK) != 0) {
		_LOGE("from file [%s]is not present", from_file);
		ret = RPM_INSTALLER_ERR_INTERNAL;
		goto catch;
	}
	/* Check whether delta of file is present or not */
	if (access(delta_file, F_OK) != 0) {
		_LOGE("delta file [%s]is not present", delta_file);
		ret = RPM_INSTALLER_ERR_INTERNAL;
		goto catch;
	}

	/* Check whether delta of file is present or not */
	if (access(DELTA_TOOL, F_OK | X_OK) != 0) {
		if( strerror_r(errno, buf, sizeof(buf)) == 0) {
			_LOGE("unable to access delta tool [%s] [Error = %s]", DELTA_TOOL, buf);
		}
		ret = RPM_INSTALLER_ERR_INTERNAL;
		goto catch;

	}

	const char *delta_argv[] = { DELTA_TOOL, "-f", "-d", "-s", from_file, delta_file, to_file, NULL };
	while (delta_argv[i] != NULL) {
		_LOGD("delta_argv[%d]: [%s]", i, delta_argv[i]);
		i++;
	}
	ret = _ri_xsystem(delta_argv);
	if (ret != 0) {
		_LOGE("failed to apply delta for file =[%s], ret=[%d]", file, ret);
		goto catch;
	}

catch:
	return ret;
}

int __coretpk_installer_delta_add_file(char *pkgid, char *file)
{
	int ret = 0;
	char src_file[BUF_SIZE] = { 0 };
	char dest_file[BUF_SIZE] = { 0 };
	struct stat stFileInfo = { 0 };

	_LOGD("file is [%s]", file);
	snprintf(src_file, BUF_SIZE, "%s/%s%s/%s", OPT_USR_APPS, pkgid, DELTA_DIR, file);
	snprintf(dest_file, BUF_SIZE, "%s/%s%s/%s", OPT_USR_APPS, pkgid, NEW_DIR, file);

	if (access(src_file, F_OK) != 0) {
		_LOGE("{%s} is not present", src_file);
		ret = RPM_INSTALLER_ERR_INTERNAL;
		goto catch;
	}

	if (lstat(src_file, &stFileInfo) < 0) {
		_LOGE("lstat(%s) failed.", src_file);
		perror(src_file);
	}

	if (S_ISDIR(stFileInfo.st_mode)) {
		ret = _installer_util_copy_dir(src_file, dest_file);
		if (ret != 0) {
			_LOGE("failed to add dir =[%s], ret=[%d]", file, ret);
			goto catch;
		}
	} else {
		ret = _installer_util_copy_file(src_file, dest_file);
		if (ret != 0) {
			_LOGE("failed to add  file =[%s], ret=[%d]", file, ret);
			goto catch;
		}
	}

catch:
	return ret;
}

int __coretpk_installer_delta_remove_file(char *pkgid, char *file)
{

	int ret = 0;
	char dest_file[BUF_SIZE] = { 0 };
	struct stat stFileInfo = { 0 };

	snprintf(dest_file, BUF_SIZE, "%s/%s%s/%s", OPT_USR_APPS, pkgid, NEW_DIR, file);

	if (access(dest_file, F_OK) == 0) {
		if (lstat(dest_file, &stFileInfo) < 0) {
			_LOGE("lstat(%s) failed.", dest_file);
			perror(dest_file);
		}

		if (S_ISDIR(stFileInfo.st_mode)) {
			ret = _installer_util_delete_dir(dest_file);
			if (ret != 0) {
				_LOGE("failed to delete dir =[%s], ret=[%d]", dest_file, ret);
				return ret;
			}
		} else {
			(void)remove(dest_file);
		}
	}
	return ret;
}

static int __coretpk_installer_movepkg_for_delta_upgrade(char* pkgid, int move_type)
{
	app2ext_handle *hdl = NULL;
	int ret = 0;
	int movetype = -1;
	GList *dir_list = NULL;

	_LOGD("[#]start : _coretpk_installer_package_move[%s][%d]", pkgid, move_type);

	if (move_type == PM_MOVE_TO_INTERNAL) {
		movetype = APP2EXT_MOVE_TO_PHONE;
	} else if (move_type == PM_MOVE_TO_SDCARD) {
		movetype = APP2EXT_MOVE_TO_EXT;
	} else {
		ret = RPM_INSTALLER_ERR_WRONG_PARAM;
		goto err;
	}

	/*terminate running app*/
	__terminate_running_app(pkgid);

	hdl = app2ext_init(APP2EXT_SD_CARD);
	if ((hdl != NULL) && (hdl->interface.move != NULL)) {
		dir_list = __rpm_populate_dir_list();
		if (dir_list == NULL) {
			_LOGE("@Failed to get the populate directory.");
			ret = RPM_INSTALLER_ERR_RPM_SCRIPT_WRONG_ARGS;
			goto err;
		}

		ret = hdl->interface.move(pkgid, dir_list, movetype);
		__rpm_clear_dir_list(dir_list);
		if (ret != 0) {
			_LOGE("@Failed to move app.");
			ret = RPM_INSTALLER_ERR_INTERNAL;
			goto err;
		} else {
			if(move_type == PM_MOVE_TO_INTERNAL) {
				_LOGD("#updating the installed storage from external to internal");
				ret = pkgmgrinfo_pkginfo_set_installed_storage(pkgid, INSTALL_INTERNAL);
			} else {
				_LOGD("#updating the installed storage from internal to external");
				ret = pkgmgrinfo_pkginfo_set_installed_storage(pkgid, INSTALL_EXTERNAL);
			}

			if (ret != PMINFO_R_OK) {
				_LOGE("@Failed to udpate the installed storage.");
				ret = RPM_INSTALLER_ERR_INTERNAL;
				goto err;
			}
		}

	} else {
		_LOGE("@Failed to get app2ext handle.");
		ret = RPM_INSTALLER_ERR_INTERNAL;
	}

err:
	if (hdl != NULL) {
		app2ext_deinit(hdl);
	}

	if (ret == 0) {
		_LOGD("[#]end : __coretpk_installer_movepkg_for_delta_upgrade");
		if (move_type == PM_MOVE_TO_SDCARD)
			__apply_privilege_for_ext_storage(pkgid);
	} else {
		_LOGE("[@]end : __coretpk_installer_movepkg_for_delta_upgrade");
	}

	return ret;
}

/* install the delta package on installed package*/
int __coretpk_installer_install_delta(const char *pkg_file, delta_info * deltainfo)
{
	int ret = 0;
	char delta_pkg_path[BUF_SIZE] = { 0 };
	char new_appdir[BUF_SIZE] = { 0 };
	char appdir[BUF_SIZE] = { 0 };
	char tizen_manifest[BUF_SIZE] = { 0 };
	char system_manifest[BUF_SIZE] = { 0 };
	char *version = NULL;
	pkgmgrinfo_pkginfo_h pkginfo_handle = NULL;
	GList *file_list = NULL;
	char *pkgid = NULL;
	int visibility = 0;
	pkgmgrinfo_installed_storage storage;

	pkgid = deltainfo->pkg_info->package_name;
	if (!pkgid) {
		_LOGE("Unable to get package id from the package file!");
		return RPM_INSTALLER_ERR_PKG_NOT_FOUND;
	}

	_ri_broadcast_status_notification(pkgid, PKGTYPE_TPK, "start", "update");

	/* Get the package info from DB */
	ret = pkgmgrinfo_pkginfo_get_pkginfo(pkgid, &pkginfo_handle);
	if (ret != 0) {
		_LOGE("Package is not installed. Installation of delta package is invalid");
		ret = RPM_INSTALLER_ERR_PKG_NOT_FOUND;
		goto catch;
	}
	/* Get the version of package from DB */
	ret = pkgmgrinfo_pkginfo_get_version(pkginfo_handle, &version);
	if (ret != 0) {
		_LOGE("Failed to get the version");
		ret = RPM_INSTALLER_ERR_INTERNAL;
		goto catch;
	}

	ret = pkgmgrinfo_pkginfo_get_installed_storage(pkginfo_handle, &storage);
	if (ret != 0) {
		_LOGE("Failed to get the updated version");
		ret = RPM_INSTALLER_ERR_INTERNAL;
		goto catch;
	}
	if ( storage == PMINFO_EXTERNAL_STORAGE ) {
		/*move app to internal storage temporarily for applying delta patch*/
		ret = __coretpk_installer_movepkg_for_delta_upgrade(pkgid, PM_MOVE_TO_INTERNAL);
		if (ret !=0) {
			_LOGE("__coretpk_installer_movepkg_for_delta_upgrade PM_MOVE_TO_INTERNAL failed!, ret = %d", ret);
			ret = RPM_INSTALLER_ERR_INTERNAL;
			goto catch;
		}
	}
	_ri_broadcast_status_notification(pkgid, PKGTYPE_TPK, "install_percent", "20");

	_LOGD("------------------------------------------");
	_LOGD("Delta package- Update - [%s][%s]", pkgid, pkg_file);
	_LOGD("------------------------------------------");

	/* terminate running app */
	__terminate_running_app(pkgid);

	/* creates directory for delta package */
	snprintf(delta_pkg_path, BUF_SIZE, "%s/%s%s", OPT_USR_APPS, pkgid, DELTA_DIR);
	ret = _installer_util_create_dir(delta_pkg_path, DIRECTORY_PERMISSION_644);
	if (ret < 0) {
		ret = RPM_INSTALLER_ERR_INTERNAL;
		goto catch;
	}

	/*compare package's api version with platform version*/
	ret = __coretpk_compare_with_platform_version(deltainfo->pkg_info->api_version);
	if (ret != RPM_INSTALLER_SUCCESS) {
		if (ret == RPM_INSTALLER_ERR_NOT_SUPPORTED_API_VERSION) {
			_LOGE("Unable to install. Platform version[%s] < Package version[%s]",
				TIZEN_FULL_VERSION, deltainfo->pkg_info->api_version);
		}
		ret = RPM_INSTALLER_ERR_INTERNAL;
		goto catch;
	}

	/* Extract the delta package */
	const char *unzip_argv[] = { "/usr/bin/unzip", "-oqq", pkg_file, "-d", delta_pkg_path, NULL };
	ret = _ri_xsystem(unzip_argv);
	if (ret != 0) {
		_LOGE("failed to unzip for path=[%s], ret=[%d]", delta_pkg_path, ret);
		goto catch;
	}
	_LOGD("unzip is done successfully, path=[%s]", delta_pkg_path);

	_ri_broadcast_status_notification(pkgid, PKGTYPE_TPK, "install_percent", "30");

	/* Copy the content of package to an intermediate directory */
	snprintf(appdir, BUF_SIZE, "%s/%s", OPT_USR_APPS, pkgid);
	snprintf(new_appdir, BUF_SIZE, "%s/%s%s", OPT_USR_APPS, pkgid, NEW_DIR);

	ret = _installer_util_create_dir(new_appdir, DIRECTORY_PERMISSION_755);
	if (ret < 0) {
		ret = RPM_INSTALLER_ERR_INTERNAL;
		goto catch;
	}

	ret = _installer_util_copy_dir(appdir, new_appdir);

	/* Apply the patches of modified files */
	file_list = deltainfo->modify_files_list;
	char *file_path = NULL;
	while (file_list) {
		file_path = (char *)file_list->data;
		ret = __coretpk_installer_delta_apply_file(pkgid, file_path);
		if (ret != 0) {
			_LOGE("patch failed for [%s]", file_path);
			ret = RPM_INSTALLER_ERR_INTERNAL;
			goto catch;
		}
		file_list = file_list->next;
	}

	/* Add new files and removed unwanted files */

	file_list = deltainfo->remove_files_list;
	while (file_list) {
		file_path = (char *)file_list->data;
		ret = __coretpk_installer_delta_remove_file(pkgid, file_path);
		if (ret != 0) {
			_LOGE("Removing file failed[%s]", file_path);
			ret = RPM_INSTALLER_ERR_INTERNAL;
			goto catch;
		}
		file_list = file_list->next;
	}

	file_list = deltainfo->add_files_list;
	while (file_list) {
		file_path = (char *)file_list->data;
		ret = __coretpk_installer_delta_add_file(pkgid, file_path);
		if (ret != 0) {
			_LOGE("Adding file failed [%s]", file_path);
			ret = RPM_INSTALLER_ERR_INTERNAL;
			goto catch;
		}
		file_list = file_list->next;
	}

	ret = _coretpk_installer_verify_signatures(new_appdir, pkgid, &visibility, NULL);
	if (ret < 0) {
		_LOGE("failed to verify signature and certificate, pkgid=[%s].", pkgid);
		ret = RPM_INSTALLER_ERR_SIG_VERIFICATION_FAILED;
		goto catch;
	} else {
		_LOGD("signature and certificate are verified successfully.");
		ret = __compare_author_public_key(pkgid);
		if (ret < 0) {
			_LOGE("@Failed to verify public key verifying[%s].", pkgid);
			ret = RPM_INSTALLER_ERR_SIG_VERIFICATION_FAILED;
			goto catch;
		}
		_LOGD("#author public key verifying success");
	}
	_ri_broadcast_status_notification(pkgid, PKGTYPE_TPK, "install_percent", "60");
	/* Convert tizen-manifest. validate and install it */
	snprintf(tizen_manifest, BUF_SIZE, "%s/%s", new_appdir, CORETPK_XML);
	snprintf(system_manifest, BUF_SIZE, "%s/%s.xml", OPT_SHARE_PACKAGES, pkgid);

	/* Check privilege and visibility */
	ret = _coretpk_installer_verify_privilege_list(pkgid, deltainfo->pkg_info, visibility);
	if (ret != 0) {
		goto catch;
	}

	if (access(system_manifest, F_OK) == 0)
		unlink(system_manifest);
	ret = _coretpk_parser_convert_manifest(tizen_manifest, pkgid, deltainfo->pkg_info->client_id, false, visibility, NULL);
	if (ret != 0) {
		_LOGE("_coretpk_parser_convert_manifest(%s) failed.", pkgid);
		ret = RPM_INSTALLER_ERR_NO_MANIFEST;
		goto catch;
	}

	ret = pkgmgr_parser_check_manifest_validation(system_manifest);
	if (ret < 0) {
		_LOGE("invalid manifest file(schema)");
		ret = RPM_INSTALLER_ERR_INVALID_MANIFEST;
		goto catch;
	}

	ret = pkgmgr_parser_parse_manifest_for_upgrade(system_manifest, NULL);
	if (ret < 0) {
		_LOGE("failed to parse the manifest.");
		ret = RPM_INSTALLER_ERR_INTERNAL;
		goto catch;
	}
	_ri_unregister_cert(pkgid);
	_ri_privilege_unregister_package(pkgid);

	/* search_ug_app */
	_coretpk_installer_search_ui_gadget(pkgid);

	/* register cert info */
	_ri_register_cert(pkgid);

	/* delete app's old */
	if (access(appdir, F_OK) == 0)
		_installer_util_delete_dir(appdir);

	ret = rename(new_appdir, appdir);
	if (ret != 0) {
		_LOGE("renaming failed src[%s], dest[%s]", new_appdir, appdir);
		goto catch;
	}
	_ri_broadcast_status_notification(pkgid, PKGTYPE_TPK, "install_percent", "80");

	/* make directory */
	ret = _coretpk_installer_make_directory(pkgid, false);
	if (ret != 0) {
		_LOGE("failed to make the directory.");
		goto catch;
	}

	/* apply smack to app dir */
	ret = _coretpk_installer_apply_smack(pkgid, 1);
	if (ret != 0) {
		_LOGE("failed to apply the smack.");
		goto catch;
	}

	/* apply smack by privilege */
	ret = _ri_apply_privilege(pkgid, visibility, NULL);
	if (ret != 0) {
		_LOGE("failed to apply permission, ret=[%d]", ret);
	}
	_LOGD("permission applying done successfully.");

	if ( storage == PMINFO_EXTERNAL_STORAGE ) {
		/* restore location back to sdcard*/
		ret = __coretpk_installer_movepkg_for_delta_upgrade(pkgid, PM_MOVE_TO_SDCARD);
		if (ret !=0) {
			_LOGE("__coretpk_installer_movepkg_for_delta_upgrade  PM_MOVE_TO_SDCARD failed!, ret = %d", ret);
			ret = RPM_INSTALLER_ERR_INTERNAL;
			goto catch;
		}
	}

	/*send event for install_percent*/
	_ri_broadcast_status_notification(pkgid, PKGTYPE_TPK, "install_percent", "100");
	ret = RPM_INSTALLER_SUCCESS;

catch:
	if (ret == RPM_INSTALLER_SUCCESS) {
		_LOGD("[#]end : _coretpk_installer_install_delta");
		_ri_broadcast_status_notification(pkgid, PKGTYPE_TPK, "end", "ok");
	} else {
		char *errorstr = NULL;
		_ri_error_no_to_string(ret, &errorstr);
		_ri_broadcast_status_notification(pkgid, PKGTYPE_TPK, "error", errorstr);
		sleep(2);

		_LOGE("[@]end : __coretpk_installer_install_delta");
		_ri_broadcast_status_notification(pkgid, PKGTYPE_TPK, "end", "fail");
	}

	if (access(delta_pkg_path, F_OK) == 0) {
		_installer_util_delete_dir(delta_pkg_path);
	}

	if(access(new_appdir,F_OK) == 0)
		_installer_util_delete_dir(new_appdir);

	if(pkginfo_handle)
		pkgmgrinfo_pkginfo_destroy_pkginfo(pkginfo_handle);

	return ret;
}

int _coretpk_installer_prepare_delta_install(const char *pkg_file, const char *clientid)
{
	retvm_if(pkg_file == NULL, RPM_INSTALLER_ERR_WRONG_PARAM, "pkg_file is NULL.");

	int ret = 0;
	delta_info *deltainfo = NULL;	/* holds the deltatpk's metadata information */

	/* Get the delta-package info from delta package file */
	deltainfo = _coretpk_installer_get_delta_info(pkg_file);
	tryvm_if(deltainfo == NULL, ret = -2, "_coretpk_installer_get_delta_info(%s) failed.", pkg_file);
	tryvm_if(strlen(deltainfo->pkg_info->package_name) == 0, ret = -2, "package_name is invalid. (len=0)");

	if (clientid) {
		strncpy(deltainfo->pkg_info->client_id, clientid, sizeof(deltainfo->pkg_info->client_id) - 1);
	}

	ret = __coretpk_installer_install_delta(pkg_file, deltainfo);
	if (ret != 0) {
		_LOGE("_coretpk_installer_prepare_delta_install(%s) failed. ret=[%d]", pkg_file, ret);
	} else {
		_LOGD("[%s] is installed successfully.", pkg_file);
	}

catch:

	if (ret == -2) {
		_ri_broadcast_status_notification("Invalid package", "invalid", "start", "update");
		_ri_broadcast_status_notification("Invalid package", "invalid", "end", "fail");
	}

	if (deltainfo) {
		_installer_util_free_delta_info(deltainfo);
		deltainfo = NULL;
	}

	return ret;

}
#endif

int _coretpk_installer_prepare_preload_uninstall(const char *pkgid)
{
	retvm_if(pkgid == NULL, RPM_INSTALLER_ERR_WRONG_PARAM, "pkgid is NULL.");

	int ret = 0;
	char buff[BUF_SIZE] = { '\0' };
	char *smack_label = NULL;
	pkgmgrinfo_pkginfo_h pkghandle = NULL;

	_LOGD("preload_uninstall - pkgid=[%s]", pkgid);

	/* terminate running app */
	ret = pkgmgrinfo_pkginfo_get_pkginfo(pkgid, &pkghandle);
	if (ret < 0) {
		_LOGE("pkgmgrinfo_pkginfo_get_pkginfo(%s) failed.", pkgid);
		return RPM_INSTALLER_ERR_PKG_NOT_FOUND;
	}
	pkgmgrinfo_appinfo_get_list(pkghandle, PM_ALL_APP, __ri_check_running_app, NULL);
	pkgmgrinfo_pkginfo_destroy_pkginfo(pkghandle);

	ret = __get_smack_label_from_db(pkgid, &smack_label);
	_LOGD("smack_label[%s], ret[%d]\n", smack_label, ret);

	/* del root path dir */
	snprintf(buff, BUF_SIZE, "%s/%s", OPT_USR_APPS, pkgid);
	if (__is_dir(buff)) {
		_installer_util_delete_dir(buff);
	}
	memset(buff, '\0', BUF_SIZE);
	snprintf(buff, BUF_SIZE, "%s/%s", USR_APPS, pkgid);
	if (__is_dir(buff)) {
		_installer_util_delete_dir(buff);
	}

	/* del root path dir for ext */
	char extpath[BUF_SIZE] = { '\0' };
	snprintf(extpath, BUF_SIZE, "%s/%s", OPT_STORAGE_SDCARD_APP_ROOT, pkgid);
	if (__is_dir(extpath)) {
		_installer_util_delete_dir(extpath);
	}

	/* del manifest */
	memset(buff, '\0', BUF_SIZE);
	snprintf(buff, BUF_SIZE, "%s/%s.xml", OPT_SHARE_PACKAGES, pkgid);
	(void)remove(buff);
	memset(buff, '\0', BUF_SIZE);
	snprintf(buff, BUF_SIZE, "%s/%s.xml", USR_SHARE_PACKAGES, pkgid);
	(void)remove(buff);

	/* del db info */
	ret = pkgmgr_parser_parse_manifest_for_uninstallation(pkgid, NULL);
	if (ret < 0) {
		_LOGE("pkgmgr_parser_parse_manifest_for_uninstallation() failed, pkgid=[%s]", pkgid);
	}

	/* execute privilege APIs */
	_ri_privilege_revoke_permissions(smack_label);
	_ri_privilege_unregister_package(smack_label);

	/* Unregister cert info */
	_ri_unregister_cert(pkgid);

	_LOGD("_coretpk_installer_prepare_preload_uninstall() is done successfully, pkgid=[%s], ret=[%d]", pkgid, ret);

	FREE_AND_NULL(smack_label);

	return ret;
}

int _coretpk_installer_package_move(const char *pkgid, int move_type)
{
	retvm_if(pkgid == NULL, RPM_INSTALLER_ERR_WRONG_PARAM, "pkgid is NULL.");

	app2ext_handle *hdl = NULL;
	int ret = 0;
	int movetype = -1;
	GList *dir_list = NULL;

	_ri_broadcast_status_notification(pkgid, PKGTYPE_TPK, "start", "move");
	_LOGD("[#]start : _coretpk_installer_package_move[%s][%d]", pkgid, move_type);

	if (move_type == PM_MOVE_TO_INTERNAL) {
		movetype = APP2EXT_MOVE_TO_PHONE;
	} else if (move_type == PM_MOVE_TO_SDCARD) {
		movetype = APP2EXT_MOVE_TO_EXT;
	} else {
		ret = RPM_INSTALLER_ERR_WRONG_PARAM;
		goto err;
	}

	/* terminate running app */
	__terminate_running_app(pkgid);

	hdl = app2ext_init(APP2EXT_SD_CARD);
	if ((hdl != NULL) && (hdl->interface.move != NULL)) {
		dir_list = __rpm_populate_dir_list();
		if (dir_list == NULL) {
			_LOGE("__rpm_populate_dir_list(%s) failed.", pkgid);
			ret = RPM_INSTALLER_ERR_RPM_SCRIPT_WRONG_ARGS;
			goto err;
		}

		ret = hdl->interface.move(pkgid, dir_list, movetype);
		__rpm_clear_dir_list(dir_list);
		if (ret != 0) {
			_LOGE("interface.move(%s) failed. ret=[%d]", pkgid, ret);
			ret = RPM_INSTALLER_ERR_INTERNAL;
			goto err;
		}

	} else {
		_LOGE("app2ext_init(%s) failed.", pkgid);
		ret = RPM_INSTALLER_ERR_INTERNAL;
	}

err:
	if (hdl != NULL) {
		app2ext_deinit(hdl);
	}

	if (ret == 0) {
		_LOGD("_coretpk_installer_package_move(%s) is done.", pkgid);
		_ri_broadcast_status_notification(pkgid, PKGTYPE_TPK, "end", "ok");
	} else {
		_LOGE("_coretpk_installer_package_move(%s) failed.", pkgid);
		_ri_broadcast_status_notification(pkgid, PKGTYPE_TPK, "end", "fail");
	}

	return ret;
}

int _coretpk_installer_handle_rds_data(const char *pkgid, GList * delete, GList * add, GList * modify, int *updatexml, int *updateres)
{
	int ret = 0;
	GList *list = NULL;
	char handledata[BUF_SIZE] = { '\0' };
	char srcfile[BUF_SIZE] = { '\0' };
	char destfile[BUF_SIZE] = { '\0' };

	/* delete */
	if (delete != NULL) {
		list = g_list_first(delete);
		while (list) {
			char *data = (char *)list->data;
			if (!strcasestr(data, RDS_DELTA_DELETE)) {
				snprintf(handledata, BUF_SIZE, "%s/%s/%s", OPT_USR_APPS, pkgid, data);

				const char *delete_argv[] = { "/bin/rm", "-rf", handledata, NULL };
				ret = _ri_xsystem(delete_argv);
				if (ret == 0) {
					_LOGD("#[delete] success : %s", data);
				} else {
					_LOGD("#[delete] fail : %s", data);
				}
				memset(handledata, '\0', sizeof(handledata));
			}

			list = g_list_next(list);
		}
	} else {
		_LOGD("#There is no deleted data.");
	}

	/* add */
	if (add != NULL) {
		list = g_list_first(add);
		while (list) {
			char *data = (char *)list->data;
			if (!strcasestr(data, RDS_DELTA_ADD)) {
				snprintf(srcfile, BUF_SIZE, "%s/tmp/%s/%s", OPT_USR_APPS, pkgid, data);
				snprintf(destfile, BUF_SIZE, "%s/%s/%s", OPT_USR_APPS, pkgid, data);

				if (__is_dir((char *)srcfile)) {
					const char *mkdir_argv[] = { "/bin/mkdir", "-p", destfile, NULL };
					_ri_xsystem(mkdir_argv);
					_LOGD("#[%s] is created.", destfile);
				} else {
					ret = _installer_util_copy_file(srcfile, destfile);
					if (ret == 0) {
						_LOGD("#[add] success : %s", data);
					} else {
						_LOGD("#[add] fail : %s", data);
					}
				}
				memset(srcfile, '\0', sizeof(srcfile));
				memset(destfile, '\0', sizeof(destfile));
			}

			list = g_list_next(list);
		}
	} else {
		_LOGD("#There is no added data.");
	}

	/* modify */
	if (modify != NULL) {
		list = g_list_first(modify);
		while (list) {
			char *data = (char *)list->data;
			if (!strcasestr(data, RDS_DELTA_MODIFY)) {
				/* If XML is modified, the checking codes for xml has to be executed. */
				if (strcmp(data, CORETPK_XML) == 0) {
					*updatexml = 1;
				}

				if (strcmp(data, RES_XML) == 0)
					*updateres = 1;

				snprintf(srcfile, BUF_SIZE, "%s/tmp/%s/%s", OPT_USR_APPS, pkgid, data);
				snprintf(destfile, BUF_SIZE, "%s/%s/%s", OPT_USR_APPS, pkgid, data);

				ret = _installer_util_copy_file(srcfile, destfile);
				if (ret == 0) {
					_LOGD("#[modify] success : %s", data);
				} else {
					_LOGD("#[modify] fail : %s", data);
				}

				memset(srcfile, '\0', sizeof(srcfile));
				memset(destfile, '\0', sizeof(destfile));
			}
			list = g_list_next(list);
		}
	} else {
		_LOGD("#There is no modified data.");
	}

	return ret;
}

int _coretpk_installer_read_rds_file(const char *pkgid, const char *rdsfile, int *updatexml, int *updateres)
{
	int ret = 0;
	int state = RDS_STATE_NONE;

	char buffer[BUF_SIZE] = { '\0' };
	char buf[BUF_SIZE] = { 0, };
	FILE *fi = NULL;

	GList *delete_list = NULL;
	GList *add_list = NULL;
	GList *modify_list = NULL;

	if (access(rdsfile, F_OK) != 0) {
		if( strerror_r(errno, buf, sizeof(buf)) == 0) {
			_LOGE("access(%s) failed. [%d][%s]", rdsfile, errno, buf);
		}
		return -1;
	}

	fi = fopen(rdsfile, "r");
	if (fi == NULL) {
		if( strerror_r(errno, buf, sizeof(buf)) == 0) {
			_LOGE("fopen(%s) failed. [%d][%s]", rdsfile, errno, buf);
		}
		return -1;
	}

	while (fgets(buffer, BUF_SIZE, fi) != NULL) {
		buffer[strlen(buffer) - 1] = '\0';

		/* check rds state */
		if (buffer[0] == '#') {
			if (strcasestr(buffer, RDS_DELTA_DELETE)) {
				state = RDS_STATE_DELETE;
			} else if (strcasestr(buffer, RDS_DELTA_ADD)) {
				state = RDS_STATE_ADD;
			} else if (strcasestr(buffer, RDS_DELTA_MODIFY)) {
				state = RDS_STATE_MODIFY;
			} else {
				state = RDS_STATE_NONE;
			}
		}

		if (state == RDS_STATE_NONE) {
			_LOGE("Unknown RDS State, INSTALLER_RDS_STATE_NONE");
			continue;
		}

		/* make rds data list */
		switch (state) {
		case RDS_STATE_DELETE:
			_LOGD("RDS_STATE_DELETE data : %s", buffer);
			delete_list = g_list_append(delete_list, g_strdup(buffer));
			break;

		case RDS_STATE_ADD:
			_LOGD("RDS_STATE_ADD data : %s", buffer);
			add_list = g_list_append(add_list, g_strdup(buffer));
			break;

		case RDS_STATE_MODIFY:
			_LOGD("RDS_STATE_MODIFY data : %s", buffer);
			modify_list = g_list_append(modify_list, g_strdup(buffer));
			break;
		}
	}

	ret = _coretpk_installer_handle_rds_data(pkgid, delete_list, add_list, modify_list, updatexml, updateres);
	if (ret != 0) {
		_LOGE("_coretpk_installer_handle_rds_data(%s) failed. ret=[%d]", pkgid, ret);
	}

	if (delete_list != NULL) {
		g_list_free(delete_list);
	}
	if (add_list != NULL) {
		g_list_free(add_list);
	}
	if (modify_list != NULL) {
		g_list_free(modify_list);
	}

	fclose(fi);
	return ret;
}

int _coretpk_installer_package_reinstall(const char *pkgid, const char *clientid)
{
	retvm_if(pkgid == NULL, RPM_INSTALLER_ERR_WRONG_PARAM, "pkgid is NULL.");

	int ret = 0;
	char manifest[BUF_SIZE] = { '\0' };
	char rdsfile[BUF_SIZE] = { '\0' };
	char dirpath[BUF_SIZE] = { '\0' };
	char cwd[BUF_SIZE] = { '\0' };
	char res_xml[BUF_SIZE] = { '\0' };
	char *temp = NULL;
	int updatexml = 0;
	int updateres = 0;
	int visibility = 0;
	pkginfo *pkg_file_info = NULL;
	char buf[BUF_SIZE] = { 0, };

	pkgmgr_installer_send_signal(pi, PKGTYPE_TPK, pkgid, "start", "update");
	_LOGD("[#]start : _coretpk_installer_package_reinstall[%s]", pkgid);

	snprintf(rdsfile, BUF_SIZE, "%s/tmp/%s/%s", OPT_USR_APPS, pkgid, RDS_DELTA_FILE);
	ret = _coretpk_installer_read_rds_file(pkgid, rdsfile, &updatexml, &updateres);
	if (ret != 0) {
		_LOGE("_coretpk_installer_read_rds_file(%s) failed.", pkgid);
		ret = RPM_INSTALLER_ERR_INTERNAL;
		goto err;
	}
	_LOGD("#RDS file reading success");

	pkgmgr_installer_send_signal(pi, PKGTYPE_TPK, pkgid, "install_percent", "30");

	/* getcwd */
	temp = getcwd(cwd, BUF_SIZE);
	if ((temp == NULL) || (cwd[0] == '\0')) {
		if( strerror_r(errno, buf, sizeof(buf)) == 0) {
			_LOGE("getcwd() failed. [%d][%s]", errno, buf);
		}
		ret = RPM_INSTALLER_ERR_INTERNAL;
		goto err;
	}
	_LOGD("#Current working directory is %s.", cwd);

	/* change dir */
	snprintf(dirpath, BUF_SIZE, "%s/%s", OPT_USR_APPS, pkgid);
	ret = chdir(dirpath);
	if (ret != 0) {
		if( strerror_r(errno, buf, sizeof(buf)) == 0) {
			_LOGE("chdir(%s) failed. [%d][%s]", dirpath, errno, buf);
		}
		ret = RPM_INSTALLER_ERR_INTERNAL;
		goto err;
	}

	/* check for signature and certificate */
	ret = _coretpk_installer_verify_signatures(dirpath, pkgid, &visibility, NULL);
	if (ret != 0) {
		_LOGE("_coretpk_installer_verify_signatures(%s, %s) failed. ret=[%d]", dirpath, pkgid, ret);
		goto err;
	}
	_LOGD("signature and certificate verifying success");

	/* chdir */
	ret = chdir(cwd);
	if (ret != 0) {
		if( strerror_r(errno, buf, sizeof(buf)) == 0) {
			_LOGE("chdir(%s) failed. [%d][%s]", cwd, errno, buf);
		}
		ret = RPM_INSTALLER_ERR_INTERNAL;
		goto err;
	}

	if (updatexml) {
		/* convert manifest and copy the file to /opt/share/packages */
		snprintf(manifest, BUF_SIZE, "%s/%s", dirpath, CORETPK_XML);

		/*compare package's api version with platform version*/
		pkg_file_info = _coretpk_installer_get_pkgfile_info(manifest, NULL);
		if (pkg_file_info == NULL) {
			_LOGE("failed to get pkginfo from manifest[%s]", manifest);
			ret = RPM_INSTALLER_ERR_INTERNAL;
			goto err;
		}

		ret = __coretpk_compare_with_platform_version(pkg_file_info->api_version);
		if (ret != RPM_INSTALLER_SUCCESS) {
			if (ret == RPM_INSTALLER_ERR_NOT_SUPPORTED_API_VERSION) {
				_LOGE("Unable to install. Platform version[%s] < Package version[%s]",
					TIZEN_FULL_VERSION, pkg_file_info->api_version);
			}
			ret = RPM_INSTALLER_ERR_INTERNAL;
			goto err;
		}

		ret = _coretpk_parser_convert_manifest(manifest, pkgid, clientid, false, visibility, NULL);
		if (ret != 0) {
			_LOGE("_coretpk_parser_convert_manifest(%s, %s) failed.", manifest, pkgid);
			ret = RPM_INSTALLER_ERR_INVALID_MANIFEST;
			goto err;
		}
		_LOGD("#manifest converting success");

		/* check the manifest file. */
		memset(manifest, '\0', sizeof(manifest));
		snprintf(manifest, BUF_SIZE, "%s/%s.xml", OPT_SHARE_PACKAGES, pkgid);
		/* compare manifest.xml with schema file(/usr/etc/package-manager/preload/manifest.xsd) */
		ret = pkgmgr_parser_check_manifest_validation(manifest);
		if (ret < 0) {
			_LOGE("pkgmgr_parser_check_manifest_validation(%s) failed.", manifest);
			ret = RPM_INSTALLER_ERR_INVALID_MANIFEST;
			goto err;
		}

		/* Parse the manifest to get install location and size. If failed, remove manifest info from DB. */
		ret = pkgmgr_parser_parse_manifest_for_upgrade(manifest, NULL);
		if (ret < 0) {
			_LOGE("pkgmgr_parser_parse_manifest_for_upgrade(%s) failed. ret=[%d]", manifest, ret);
			ret = RPM_INSTALLER_ERR_INTERNAL;
			goto err;
		}
		_LOGD("#manifest parsing success");
	}

	if (updateres) {
		snprintf(res_xml, BUF_SIZE, "%s/%s/%s", OPT_USR_APPS, pkgid, RES_XML);
		/* check existance of /opt/usr/apps/pkgid/res/res.xml* for backward compatibility */
		if (access(res_xml, R_OK) == 0) {
			/* validate it */
			ret = pkgmgr_resource_parser_check_xml_validation(res_xml);
			if (ret < 0) {
				_LOGE("pkgmgr_resource_parser_check_xml_validation(%s) failed.", res_xml);
				ret = RPM_INSTALLER_ERR_INTERNAL;
				goto err;
			}
		}
	}

	pkgmgr_installer_send_signal(pi, PKGTYPE_TPK, pkgid, "install_percent", "60");

	/* register cert info */
	_ri_register_cert(pkgid);

	/* make directory */
	ret = _coretpk_installer_make_directory(pkgid, false);
	if (ret != 0) {
		_LOGE("_coretpk_installer_make_directory(%s) failed.", pkgid);
		goto err;
	}

	_ri_privilege_unregister_package(pkgid);

	/* apply smack to app dir */
	ret = _coretpk_installer_apply_smack(pkgid, 1);
	if (ret != 0) {
		_LOGE("_coretpk_installer_apply_smack(%s) failed.", pkgid);
		goto err;
	}

	/* apply smack by privilege */
	ret = _ri_apply_privilege(pkgid, visibility, NULL);
	if (ret != 0) {
		_LOGE("_ri_apply_privilege(%s) failed. ret=[%d]", pkgid, ret);
	}
	_LOGD("#permission applying success.");

	pkgmgr_installer_send_signal(pi, PKGTYPE_TPK, pkgid, "install_percent", "100");
	ret = RPM_INSTALLER_SUCCESS;

err:

	if (pkg_file_info) {
		_installer_util_free_pkg_info(pkg_file_info);
		pkg_file_info = NULL;
	}

	if (ret == 0) {
		_LOGD("_coretpk_installer_package_reinstall(%s) is done.", pkgid);
		pkgmgr_installer_send_signal(pi, PKGTYPE_TPK, pkgid, "end", "ok");
	} else {
		/* remove db info */
		ret = _coretpk_installer_remove_db_info(pkgid);
		if (ret < 0) {
			_LOGE("_coretpk_installer_remove_db_info is failed.");
		}

		/* remove xml(/opt/share/packages/pkgid.xml) */
		if (access(manifest, F_OK) == 0) {
			(void)remove(manifest);
		}

		/* remove app dir(/opt/usr/apps/pkgid) */
		if (__is_dir(dirpath)) {
			_installer_util_delete_dir(dirpath);
		}

		_LOGE("_coretpk_installer_package_reinstall(%s) failed.", pkgid);
		pkgmgr_installer_send_signal(pi, PKGTYPE_TPK, pkgid, "end", "fail");
	}

	return ret;
}


int __check_installed_package(pkginfo *info)
{
	int ret = 0;
	pkginfo *dbinfo = NULL;
	char *pkgid = info->package_name;

	dbinfo = _rpm_installer_get_pkgname_info(pkgid);
	/* install case */
	if (dbinfo == NULL) {
		_LOGD("[##]csc-core : no existing version. csc install case.");
		return 0;
	}

	ret = _installer_util_compare_version(dbinfo->version, info->version);
	if (ret < VERSION_NEW) {
		/* csc version is not updated so keep existing version */
		_LOGD("[##]csc-core : csc version is not updated. keep existing version.");
		if (dbinfo) {
			free(dbinfo);
			dbinfo = NULL;
		}
		return -1;
	}

	/* upgrade case */
	_LOGD("[##]csc-core : csc version is updated. csc upgrade case.");
	/* remove for clean */
	__ri_remove_updated_dir(pkgid);

	/* unregister cert info */
	_ri_unregister_cert(pkgid);

	ret = _ri_privilege_unregister_package(pkgid);
	if (ret < 0) {
		_LOGE("[##]csc-core : _ri_privilege_unregister_package fail[pkgid=%s].", pkgid);
	}

	ret = pkgmgr_parser_parse_manifest_for_uninstallation(pkgid, NULL);
	if (ret < 0) {
		_LOGE("[##]csc-core : parse uninstall fail[manifest=%s].", pkgid);
	}

	ret = _ri_smack_reload(pkgid, UNINSTALL_REQ);
	if (ret != 0) {
		_LOGE("[##]csc-core : _ri_smack_reload failed[pkgid=%s].", pkgid);
	}

	if (dbinfo) {
		free(dbinfo);
		dbinfo = NULL;
	}

	return 0;
}

int _coretpk_installer_csc_install(const char *path_str, const char *remove_str, const char *csc_script)
{
	retvm_if(path_str == NULL, RPM_INSTALLER_ERR_WRONG_PARAM, "path_str is NULL.");
	retvm_if(remove_str == NULL, RPM_INSTALLER_ERR_WRONG_PARAM, "remove_str is NULL.");
	retvm_if(csc_script == NULL, RPM_INSTALLER_ERR_WRONG_PARAM, "csc_script is NULL.");

	/* ex) rpm-backend -k csc-core -s path=/tmp/org.tizen.corebasicapp2-1.0.0-arm.tpk:op=install:removable=true */

	int ret = 0;
	pkginfo *info = NULL;
	pkginfo *dbinfo = NULL;
	char buff[BUF_SIZE] = { '\0' };
	char manifest[BUF_SIZE] = { '\0' };
	char cwd[BUF_SIZE] = { '\0' };
	char flag_path[BUF_SIZE] = { '\0' };
	char *temp = NULL;
	char *csc_tags[3] = { NULL, };
	int visibility = 0;
	bundle *optional_data = NULL;
	char buf[BUF_SIZE] = { 0, };

	_LOGD("[##]csc-core : start csc_install[path=%s]", path_str);

	info = _coretpk_installer_get_pkgfile_info(path_str, CORETPK_CSC_CMD);
	if (info == NULL || (strlen(info->package_name) == 0)) {
		_LOGE("_coretpk_installer_get_pkgfile_info() failed.");
		ret = RPM_INSTALLER_ERR_INTERNAL;
		goto err;
	}

	_LOGD("[##]csc-core : get pkgid [%s]", info->package_name);

	dbinfo = _rpm_installer_get_pkgname_info(info->package_name);
	if (dbinfo != NULL) {
		_LOGE("csc_upgrade case!");
		free(info);
		free(dbinfo);

		return _coretpk_installer_csc_upgrade(path_str, remove_str, csc_script);
	} else {
		snprintf(flag_path, BUF_SIZE, "%s/%s", CSC_FLAG, info->package_name);
		if (access(flag_path, F_OK) == 0) {
			_LOGD("csc install >> user uninstall case [%s]", info->package_name);
			_LOGD("keep the status. So need not install csc.");

			free(info);
			return 0;
		} else {
			_LOGD("first csc install case [%s]", info->package_name);
		}
	}

	optional_data = bundle_create();
	if (optional_data) {
		bundle_add_str(optional_data, "csc_path", csc_script);
	}

	ret = __check_installed_package(info);
	if (ret < 0) {
		_LOGE("do not install or upgrade. keep exsiting version.");
		ret = 0;
		goto err;
	}

	/* If the directory which will be installed exists, remove it. */
	snprintf(buff, BUF_SIZE, "%s/%s/", OPT_USR_APPS, info->package_name);
	if (__is_dir(buff)) {
		_installer_util_delete_dir(buff);
	}

	_LOGD("[##]csc-core : real path [%s]", buff);

	const char *unzip_argv[] = { "/usr/bin/unzip", "-oqq", path_str, "-d", buff, NULL };
	ret = _ri_xsystem(unzip_argv);
	if (ret != 0) {
		_LOGE("_ri_xsystem(unzip_argv) failed. [%s, %d]", buff, ret);
		goto err;
	}

	_LOGD("[##]csc-core : unzip success[%s]", buff);

	/* getcwd */
	temp = getcwd(cwd, BUF_SIZE);
	if ((temp == NULL) || (cwd[0] == '\0')) {
		if( strerror_r(errno, buf, sizeof(buf)) == 0) {
			_LOGE("getcwd() failed. [%d][%s]", errno, buf);
		}
		ret = RPM_INSTALLER_ERR_INTERNAL;
		goto err;
	}

	/* change dir */
	ret = chdir(buff);
	if (ret != 0) {
		if( strerror_r(errno, buf, sizeof(buf)) == 0) {
			_LOGE("chdir(%s) failed. [%d][%s]", buff, errno, buf);
		}
		ret = RPM_INSTALLER_ERR_INTERNAL;
		goto err;
	}

	_LOGD("[##]csc-core : check signature");

	/* check for signature and certificate */
	ret = _coretpk_installer_verify_signatures(buff, info->package_name, &visibility, NULL);
	if (ret != 0) {
		_LOGE("_coretpk_installer_verify_signatures(%s, %s) failed.", buff, info->package_name);
		goto err;
	}
	_LOGD("[##]csc-core : signature verify success[%s]", buff);


	/* chdir */
	ret = chdir(cwd);
	if (ret != 0) {
		if( strerror_r(errno, buf, sizeof(buf)) == 0) {
			_LOGE("chdir(%s) failed. [%d][%s]", cwd, errno, buf);
		}
		ret = RPM_INSTALLER_ERR_INTERNAL;
		goto err;
	}

	/* convert manifest and copy the file to /opt/share/packages */
	snprintf(manifest, BUF_SIZE, "%s/%s/%s", OPT_USR_APPS, info->package_name, CORETPK_XML);
	ret = _coretpk_parser_convert_manifest(manifest, info->package_name, NULL, false, visibility, optional_data);
	if (ret != 0) {
		_LOGE("_coretpk_parser_convert_manifest(%s, %s) failed.", manifest, info->package_name);
		ret = RPM_INSTALLER_ERR_INVALID_MANIFEST;
		goto err;
	}

	_LOGD("[##]csc-core : manifest converting success");

	/* check the manifest file. */
	memset(manifest, '\0', sizeof(manifest));
	snprintf(manifest, BUF_SIZE, "%s/%s.xml", OPT_SHARE_PACKAGES, info->package_name);
	/* compare manifest.xml with schema file(/usr/etc/package-manager/preload/manifest.xsd) */
	ret = pkgmgr_parser_check_manifest_validation(manifest);
	if (ret < 0) {
		_LOGE("pkgmgr_parser_check_manifest_validation(%s) failed.", manifest);
		ret = RPM_INSTALLER_ERR_INVALID_MANIFEST;
		goto err;
	}

	_LOGD("[##]csc-core : manifest validation success");

	/* Parse the manifest to get install location and size. If installation fails, remove manifest info from DB */
	if (strcmp(remove_str, "true") == 0)
		csc_tags[0] = "removable=true";
	else
		csc_tags[0] = "removable=false";

	csc_tags[1] = "preload=true";
	csc_tags[2] = NULL;

	ret = pkgmgr_parser_parse_manifest_for_installation(manifest, csc_tags);
	if (ret < 0) {
		_LOGE("pkgmgr_parser_parse_manifest_for_installation(%s) failed.", manifest);
		ret = RPM_INSTALLER_ERR_INTERNAL;
		goto err;
	}

	_LOGD("[##]csc-core : register manifest success");

	/* register cert info */
	_ri_register_cert(info->package_name);

	/* make directory */
	ret = _coretpk_installer_make_directory(info->package_name, false);
	if (ret != 0) {
		_LOGE("_coretpk_installer_make_directory(%s) failed.", info->package_name);
		goto err;
	}

	_LOGD("[##]csc-core : make directory success");

	/* apply smack to app dir */
	ret = _coretpk_installer_apply_smack(info->package_name, 1);
	if (ret != 0) {
		_LOGE("_coretpk_installer_apply_smack(%s) failed.", info->package_name);
		goto err;
	}

	_LOGD("[##]csc-core : apply_smack success");

	/* apply smack by privilege */
	ret = _ri_apply_privilege(info->package_name, visibility, NULL);
	if (ret != 0) {
		_LOGE("_ri_apply_privilege(%s) failed. ret=[%d]", info->package_name, ret);
	}

	_LOGD("[##]csc-core : apply_privilege success");
	_LOGD("[##]csc-core : smack_reload success");

	ret = RPM_INSTALLER_SUCCESS;

err:
	if (ret == 0) {
		_LOGD("[##]csc-core : finish csc core success");
		__make_csc_flag(info->package_name);
	} else {
		/* remove xml(/opt/share/packages/pkgid.xml) */
		if (access(manifest, F_OK) == 0) {
			(void)remove(manifest);
		}

		/* remove app dir(/opt/usr/apps/pkgid) */
		snprintf(buff, BUF_SIZE, "%s/%s/", OPT_USR_APPS, info->package_name);
		if (__is_dir(buff)) {
			_installer_util_delete_dir(buff);
		}
		_LOGD("[##]csc-core : finish csc core fail");

	}

	if (info) {
		_installer_util_free_pkg_info(info);
		info = NULL;
	}

	if (optional_data) {
		bundle_free(optional_data);
	}

	return ret;
}

int _coretpk_installer_csc_upgrade(const char *path_str, const char *remove_str, const char *csc_script)
{
	retvm_if(path_str == NULL, RPM_INSTALLER_ERR_WRONG_PARAM, "path_str is NULL.");
	retvm_if(remove_str == NULL, RPM_INSTALLER_ERR_WRONG_PARAM, "remove_str is NULL.");

	int ret = 0;
	pkginfo *info = NULL;
	pkginfo *dbinfo = NULL;
	char buff[BUF_SIZE] = { '\0' };
	char manifest[BUF_SIZE] = { '\0' };
	char cwd[BUF_SIZE] = { '\0' };
	char *temp = NULL;
	char *csc_tags[3] = { NULL, };
	int visibility = 0;
	char *pkgid = NULL;
	bundle *optional_data = NULL;
	char buf[BUF_SIZE] = { 0, };

	_LOGD("[##]csc-core : start csc_upgrade[path=%s]", path_str);

	optional_data = bundle_create();
	if (optional_data) {
		bundle_add_str(optional_data, "csc_path", csc_script);
	}

	info = _coretpk_installer_get_pkgfile_info(path_str, CORETPK_CSC_CMD);
	if (info == NULL || (strlen(info->package_name) == 0)) {
		_LOGE("_coretpk_installer_get_pkgfile_info(%s) failed.", path_str);
		ret = RPM_INSTALLER_ERR_INTERNAL;
		goto err;
	}

	pkgid = info->package_name;

	_LOGD("[##]csc-core : get pkgid [%s]", pkgid);

	dbinfo = _rpm_installer_get_pkgname_info(info->package_name);
	if (dbinfo == NULL) {
		_LOGE("_rpm_installer_get_pkgname_info(%s) failed.", info->package_name);
		ret = RPM_INSTALLER_ERR_INTERNAL;
		goto err;
	}

	if (strcmp(info->version, dbinfo->version) <= 0) {
		/* csc version is not update. */
		_LOGD("[##]csc-core : do not update. csc version is not updated.");
		ret = RPM_INSTALLER_SUCCESS;
		goto err;
	}

	_LOGD("[##]csc-core : compare version is done. version is updated.");

	/* remove dir for clean */
	__ri_remove_updated_dir(pkgid);

	snprintf(buff, BUF_SIZE, "%s/%s/", OPT_USR_APPS, pkgid);
	const char *unzip_argv[] = { "/usr/bin/unzip", "-oqq", path_str, "-d", buff, NULL };
	ret = _ri_xsystem(unzip_argv);
	if (ret != 0) {
		_LOGE("failed to unzip for [%s, %d].", buff, ret);
		goto err;
	}

	_LOGD("[##]csc-core : unzip success[%s]", buff);

	/* getcwd */
	temp = getcwd(cwd, BUF_SIZE);
	if ((temp == NULL) || (cwd[0] == '\0')) {
		if( strerror_r(errno, buf, sizeof(buf)) == 0) {
			_LOGE("getcwd() failed. [%d][%s]", errno, buf);
		}
		ret = RPM_INSTALLER_ERR_INTERNAL;
		goto err;
	}
	_LOGD("#Current working directory is %s.", cwd);

	/* change dir */
	ret = chdir(buff);
	if (ret != 0) {
		if( strerror_r(errno, buf, sizeof(buf)) == 0) {
			_LOGE("chdir(%s) failed. [%d][%s]", buff, errno, buf);
		}
		ret = RPM_INSTALLER_ERR_INTERNAL;
		goto err;
	}

	/* check for signature and certificate */
	ret = _coretpk_installer_verify_signatures(buff, pkgid, &visibility, NULL);
	if (ret != 0) {
		_LOGE("_coretpk_installer_verify_signatures(%s, %s) failed.", buff, pkgid);
		goto err;
	}
	_LOGD("#signature and certificate verifying success");

	/* chdir */
	ret = chdir(cwd);
	if (ret != 0) {
		if( strerror_r(errno, buf, sizeof(buf)) == 0) {
			_LOGE("chdir(%s) failed. [%d][%s]", cwd, errno, buf);
		}
		ret = RPM_INSTALLER_ERR_INTERNAL;
		goto err;
	}

	/* convert manifest and copy the file to /opt/share/packages */
	snprintf(manifest, BUF_SIZE, "%s/%s/%s", OPT_USR_APPS, pkgid, CORETPK_XML);
	ret = _coretpk_parser_convert_manifest(manifest, pkgid, NULL, false, visibility, optional_data);
	if (ret != 0) {
		_LOGE("_coretpk_parser_convert_manifest(%s, %s) failed.", manifest, pkgid);
		ret = RPM_INSTALLER_ERR_INVALID_MANIFEST;
		goto err;
	}

	_LOGD("[##]csc-core : manifest converting success");

	/* check the manifest file. */
	memset(manifest, '\0', sizeof(manifest));
	snprintf(manifest, BUF_SIZE, "%s/%s.xml", OPT_SHARE_PACKAGES, pkgid);
	/* compare manifest.xml with schema file(/usr/etc/package-manager/preload/manifest.xsd) */
	ret = pkgmgr_parser_check_manifest_validation(manifest);
	if (ret < 0) {
		_LOGE("pkgmgr_parser_check_manifest_validation(%s) failed.", manifest);
		ret = RPM_INSTALLER_ERR_INVALID_MANIFEST;
		goto err;
	}

	_LOGD("[##]csc-core : manifest validation success");

	/* set csc tag. */
	if (strcmp(remove_str, "true") == 0)
		csc_tags[0] = "removable=true";
	else
		csc_tags[0] = "removable=false";

	csc_tags[1] = "preload=true";
	csc_tags[2] = NULL;

	/* remove exist csc dbinfo */
	ret = pkgmgr_parser_parse_manifest_for_uninstallation(manifest, NULL);
	if (ret < 0) {
		_LOGE("pkgmgr_parser_parse_manifest_for_uninstallation(%s) failed.", manifest);
		ret = RPM_INSTALLER_ERR_INTERNAL;
		goto err;
	}

	/* insert new csc info */
	ret = pkgmgr_parser_parse_manifest_for_installation(manifest, csc_tags);
	if (ret < 0) {
		_LOGE("pkgmgr_parser_parse_manifest_for_installation(%s) failed.", manifest);
		ret = RPM_INSTALLER_ERR_INTERNAL;
		goto err;
	}

	_LOGD("[##]csc-core : register manifest success");

	/* search_ug_app */
	_coretpk_installer_search_ui_gadget(pkgid);

	/* unregister cert info */
	_ri_unregister_cert(pkgid);

	/* register cert info */
	_ri_register_cert(pkgid);

	/* make directory */
	ret = _coretpk_installer_make_directory(pkgid, false);
	if (ret != 0) {
		_LOGE("_coretpk_installer_make_directory(%s) failed.", pkgid);
		goto err;
	}

	_LOGD("[##]csc-core : make directory success");

	/* Remove origin rule */
	_ri_privilege_unregister_package(pkgid);

	/* apply smack to app dir */
	ret = _coretpk_installer_apply_smack(pkgid, 1);
	if (ret != 0) {
		_LOGE("_coretpk_installer_apply_smack(%s) failed.", pkgid);
		goto err;
	}

	_LOGD("[##]csc-core : apply_smack success");

	/* apply smack by privilege */
	ret = _ri_apply_privilege(pkgid, visibility, NULL);
	if (ret != 0) {
		_LOGE("_ri_apply_privilege(%s) failed. ret=[%d]", pkgid, ret);
	}

	_LOGD("[##]csc-core : apply_privilege success");

	ret = RPM_INSTALLER_SUCCESS;
err:
	if (ret == 0) {
		_LOGD("[##]csc-core : update csc core success");
	} else {
		_LOGD("[##]csc-core : update csc core fail");
	}

	if (info) {
		_installer_util_free_pkg_info(info);
		info = NULL;
	}

	if (dbinfo) {
		free(dbinfo);
		dbinfo = NULL;
	}

	if (optional_data) {
		bundle_free(optional_data);
	}

	return ret;
}

int _coretpk_installer_csc_uninstall(const char *pkgid)
{
	/* ex) rpm-backend -k csc-core -s path=org.tizen.corebasicapp:op=uninstall:removable=true */

	int ret = 0;
	char flag_path[BUF_SIZE] = { 0, };

	ret = _coretpk_installer_prepare_preload_uninstall(pkgid);

	/* remove csc flag */
	snprintf(flag_path, BUF_SIZE, "%s/%s", CSC_FLAG, pkgid);
	if (access(flag_path, F_OK) == 0) {
		(void)remove(flag_path);
		_LOGD("flag_path is removed. [%s]", flag_path);
	} else {
		_LOGD("flag_path is not existed. [%s]", flag_path);
	}

	return ret;
}

#ifdef _APPFW_FEATURE_EXPANSION_PKG_INSTALL
static char *__coretpk_installer_get_pkgid_from_tep(const char *filename)
{
	char *pkg_type = NULL;
	char pkg_file[PKG_STRING_LEN_MAX] = { '\0', };
	char *tmp = NULL;
	char *pkgid = NULL;
	size_t pkgid_len = 0;

	if (strrchr(filename, '/')) {
		strncpy(pkg_file, strrchr(filename, '/') + 1, PKG_STRING_LEN_MAX - 1);
	} else {
		strncpy(pkg_file, filename, PKG_STRING_LEN_MAX - 1);
	}

	pkg_type = strrchr(pkg_file, '.');
	if (pkg_type == NULL) {
		_LOGE("pkg_type is null[%s]", filename);
		return NULL;
	} else {
		pkg_type++;
	}

	if (strcmp(pkg_type, "tep") != 0)
		return NULL;

	tmp = strrchr(pkg_file, '-');
	if (tmp == NULL || strlen(tmp) == 0) {
		_LOGE("Invalid tep file name!!!");
		return NULL;
	}

	pkgid_len = tmp - pkg_file;
	pkgid = calloc(1, pkgid_len + 1);
	retvm_if(pkgid == NULL, NULL, "Insufficient Memory");
	memcpy((void *)pkgid, (const void *)pkg_file, pkgid_len);

	return pkgid;
}

static char *__coretpk_installer_get_tep_name(const char *filename)
{
	char pkg_file[PKG_STRING_LEN_MAX] = { '\0', };
	char *tepid = NULL;

	if (strrchr(filename, '/')) {
		strncpy(pkg_file, strrchr(filename, '/') + 1, PKG_STRING_LEN_MAX - 1);
	} else {
		strncpy(pkg_file, filename, PKG_STRING_LEN_MAX - 1);
	}

	if (strlen(pkg_file) == 0) {
		return NULL;
	} else {
		_LOGD("tep_name is %s\n", pkg_file);
		int len = strlen(pkg_file) + 1;
		tepid = calloc(1, len);
		retvm_if(tepid == NULL, NULL, "Insufficient Memory");
		snprintf(tepid, len, "%s", pkg_file);
	}
	return tepid;

}

int _coretpk_installer_tep_install(const char *tep_path, int tep_move, const char *clientid)
{
	char *pkgid = NULL;
	int ret = RPM_INSTALLER_SUCCESS;
	char *errorstr = NULL;
	pkgmgrinfo_pkginfo_h handle = NULL;
	char *pkg_root_path = NULL;
	char tep_install_path[FILENAME_MAX] = { 0, };
	char tep_dest_file[FILENAME_MAX] = { 0, };
	unsigned long free_space = 0;
	unsigned long file_size = 0;
	pkgmgrinfo_installed_storage storage = PMINFO_INTERNAL_STORAGE;
	char *tep_id = NULL;
	char buf[BUF_SIZE] = { 0, };

	retvm_if(tep_path == NULL, RPM_INSTALLER_ERR_WRONG_PARAM, "tep_file is NULL.");

	pkgid = __coretpk_installer_get_pkgid_from_tep(tep_path);
	if (pkgid == NULL) {
		if (is_tpk_and_tep == false) {
			_ri_broadcast_status_notification("Invalid package", "invalid", "start", "install");
			_ri_broadcast_status_notification("Invalid package", "invalid", "end", "fail");
		}
		goto ERROR;
	}

	if (is_tpk_and_tep == false) {
		_ri_broadcast_status_notification(pkgid, PKGTYPE_TPK, "start", "install");
		/* TODO: Add signature verification? */
		_ri_broadcast_status_notification(pkgid, PKGTYPE_TPK, "install_percent", "20");
	} else {
		_ri_broadcast_status_notification(pkgid, PKGTYPE_TPK, "install_percent", "60");
	}

	/* get pkg installation path */
	ret = pkgmgrinfo_pkginfo_get_pkginfo(pkgid, &handle);
	if (ret) {
		_LOGE("unable to get pkginfo for %s, pkgmgrinfo errno:%d", pkgid, ret);
		goto ERROR;
	}

	if (is_tpk_and_tep == false) {
		_ri_broadcast_status_notification(pkgid, PKGTYPE_TPK, "install_percent", "40");
	}

	ret = pkgmgrinfo_pkginfo_get_installed_storage(handle, &storage);
	if (ret) {
		_LOGE("unable to get installed storage location for %s, pkgmgrinfo errno:%d", pkgid, ret);
		goto ERROR;
	}

	ret = pkgmgrinfo_pkginfo_get_root_path(handle, &pkg_root_path);
	if (ret) {
		_LOGE("unable to get installer pkg's root for %s, pkgmgrinfo errno:%d", pkgid, ret);
		goto ERROR;
	}

	if (storage == PMINFO_INTERNAL_STORAGE) {
		_LOGD("Installed on Internal Storage");
		/* If installed location is internal, move tep to "/opt/usr/apps/<pkgid>/res/tep/ */
		snprintf(tep_install_path, FILENAME_MAX, "%s/res/", pkg_root_path);
	} else if (storage == PMINFO_EXTERNAL_STORAGE) {
		_LOGD("Installed on External install storage");
		/* If installed location is external, move tep to "/opt/storage/sdcard/tep/ */
		snprintf(tep_install_path, FILENAME_MAX, "/opt/storage/sdcard/tep/");
	} else {
		_LOGE("invalid install location for pkg %s", pkgid);
		goto ERROR;
	}

	if (access(tep_install_path, F_OK) != 0) {
		ret = mkdir(tep_install_path, DIRECTORY_PERMISSION_755);
		if (ret < 0) {
			if( strerror_r(errno, buf, sizeof(buf)) == 0) {
				_LOGE("mkdir failed, appdir=[%s], errno=[%d][%s]", tep_install_path, errno, buf);
			}
			goto ERROR;
		}
	}

	ret = _ri_get_available_free_memory(tep_install_path, &free_space);
	if (ret < 0) {
		if( strerror_r(errno, buf, sizeof(buf)) == 0) {
			_LOGE("getting available free memory failed, appdir=[%s], errno=[%d][%s]", tep_install_path, errno, buf);
		}
		goto ERROR;
	}

	file_size = _ri_calculate_file_size(tep_path);

	_LOGE("file size = [%lu], available space = [%lu]", file_size, free_space);

	if (file_size >= free_space) {
		if( strerror_r(errno, buf, sizeof(buf)) == 0) {
			_LOGE("Insufficient storage, file size = [%lu], available space = [%lu], errno=[%d][%s]", file_size, free_space, errno, buf);
		}
		goto ERROR;
	}

	tep_id = __coretpk_installer_get_tep_name(tep_path);
	if (tep_id) {
		_LOGD("tep_id=%s", tep_id);
		snprintf(tep_dest_file, FILENAME_MAX, "%s/%s", tep_install_path, tep_id);
	} else {
		_LOGE("Unable to get tep name");
		goto ERROR;
	}

	if (tep_move == 1) {
		_LOGD("Moving from %s to %s", tep_path, tep_dest_file);
		ret = _installer_util_copy_file(tep_path, tep_dest_file);
		if (ret == 0)
			(void)remove(tep_path);
	} else {
		_LOGD("Copying from %s to %s", tep_path, tep_dest_file);
		if (ret == 0)
			ret = _installer_util_copy_file(tep_path, tep_dest_file);
	}
	if (ret != 0) {
		if( strerror_r(errno, buf, sizeof(buf)) == 0) {
			_LOGE("tep install failed [%s]", buf);
		}
		if (storage != PMINFO_EXTERNAL_STORAGE)
			goto ERROR;
	}

	if (is_tpk_and_tep == false) {
		_ri_broadcast_status_notification(pkgid, PKGTYPE_TPK, "install_percent", "60");
	} else {
		_ri_broadcast_status_notification(pkgid, PKGTYPE_TPK, "install_percent", "80");
	}

	if (storage == PMINFO_EXTERNAL_STORAGE){
		_coretpk_installer_set_smack_label_access(tep_install_path, pkgid);
		_coretpk_installer_set_smack_label_transmute(tep_install_path, "1");
		_coretpk_installer_set_smack_label_access(tep_dest_file, pkgid);
		//2TODO: add smack set code pkg_mkext.c also due to vfat limitation
		//2TODO: read from pkgmgr_parser DB, for all "package_extension_info" table content, apply smack if it's installed in SD card
	} else {
		ret = perm_app_setup_path(pkgid, tep_install_path, APP_PATH_PRIVATE, pkgid);
		if (ret) {
			_LOGE("smack apply for tep failed!!! [ret = %d]", ret);
			goto ERROR;
		}
	}

	if (is_tpk_and_tep == false) {
		_ri_broadcast_status_notification(pkgid, PKGTYPE_TPK, "install_percent", "80");
	}

	if (tep_path) {
		/* tep name would be "<pkgid>-<version>.tep" */
		_LOGE("insert the tep details to pkgmgr_info db");
		ret = pkgmgr_parser_insert_tep(pkgid, tep_id);
		if (ret != 0) {
			_LOGE("pkgmgr_parser_insert_tep_path failed [ret = %d]", ret);
			goto ERROR;
		}
	}
	_ri_broadcast_status_notification(pkgid, PKGTYPE_TPK, "install_percent", "100");
	_ri_broadcast_status_notification(pkgid, PKGTYPE_TPK, "end", "ok");

	if (handle) {
		pkgmgrinfo_pkginfo_destroy_pkginfo(handle);
	}
	if (tep_id)
		free(tep_id);
	return ret;

ERROR:
	_ri_error_no_to_string(ret, &errorstr);
	_ri_broadcast_status_notification(pkgid, PKGTYPE_TPK, "error", errorstr);

	if (handle) {
		pkgmgrinfo_pkginfo_destroy_pkginfo(handle);
	}
	if (tep_id)
		free(tep_id);
	_LOGE("_coretpk_installer_install_package(%s) failed.", pkgid);
	_ri_broadcast_status_notification(pkgid, PKGTYPE_TPK, "end", "fail");
	return ret;
}

int _coretpk_installer_tep_uninstall(const char *pkgid)
{
	int ret = 0;
	_LOGD("clear tep for %s\n", pkgid);
	ret = pkgmgr_parser_delete_tep(pkgid);
	return ret;
}
#endif
