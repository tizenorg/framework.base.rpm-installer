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
#include <unistd.h>
#include <glib.h>
#include <openssl/sha.h>
#include <openssl/evp.h>
#include <vconf.h>
#include <unzip.h>
#include <sys/smack.h>
#include <ctype.h>

#include <pkgmgr-info.h>
#include <pkgmgr_parser.h>
#include <privilege-control.h>
#include <privilege_manager.h>
#include <app_manager.h>
#include <app2ext_interface.h>
#include <package-manager.h>

#include "coretpk-installer-internal.h"
#include "coretpk-installer-type.h"
/*use rpm-installer exceptions*/
#include "rpm-installer-util.h"
/*because the logic of coretpk and rpm are similar, use rpm functions.*/
#include "rpm-installer.h"
#include "rpm-installer-type.h"

extern pkgmgr_installer *pi;
extern GList *privilege_list;

int _coretpk_installer_get_group_id(char *pkgid, char **result);
void _coretpk_installer_set_privilege_setup_path(char *pkgid, char *dirpath, app_path_type_t type, char *label);

static int __get_unzip_size(const char *item, unsigned long long *size)
{
	if (!item || !size) {
		_LOGE("Invalid argument.");
		return PMINFO_R_ERROR;
	}
	int ret = 0;
	unzFile uzf = unzOpen64(item);
	if(uzf== NULL)
	{
		_LOGE("Fail to open item : %s", item);
		*size = 0;
		return PMINFO_R_ERROR;
	} else {
		ret = unzGoToFirstFile(uzf);
		if(ret != UNZ_OK) {
			_LOGE("error get first zip file ");
			unzClose(uzf);
			*size = 0;
			return PMINFO_R_ERROR;
		} else {
			do{
				ret = unzOpenCurrentFile(uzf);
				if(ret != UNZ_OK) {
					_LOGE("error unzOpenCurrentFile ");
					unzClose(uzf);
					*size = 0;
					return PMINFO_R_ERROR;
				}

				unz_file_info fileInfo = {0};
				char* filename = (char*) calloc(1, BUF_SIZE);
				ret= unzGetCurrentFileInfo(uzf, &fileInfo, filename, (BUF_SIZE-1), NULL, 0, NULL, 0);
				*size = (unsigned long long)fileInfo.uncompressed_size + *size;
				if(ret != UNZ_OK) {
					_LOGE("error get current file info");
					unzCloseCurrentFile(uzf);
					*size = 0;
					break;
				}

				if (filename) {
					free(filename);
					filename = NULL;
				}
			}while(unzGoToNextFile(uzf) == UNZ_OK);
		}
	}
	unzClose(uzf);

	return PMINFO_R_OK;
}

static int __is_default_external_storage()
{
	int ret = 0;
	int storage = 0;
	int mmc_status = VCONFKEY_SYSMAN_MMC_REMOVED;

	ret = vconf_get_int("db/setting/default_memory/install_applications", &storage);
	retvm_if(ret != 0, PMINFO_R_ERROR, "vconf_get_int(db/setting/default_memory/install_applications) is failed.");

	if (storage == 1) {
		ret = vconf_get_int(VCONFKEY_SYSMAN_MMC_STATUS, &mmc_status);
		retvm_if(ret != 0, PMINFO_R_ERROR, "vconf_get_int(VCONFKEY_SYSMAN_MMC_STATUS) is failed.");

		if((mmc_status == VCONFKEY_SYSMAN_MMC_REMOVED) || (mmc_status == VCONFKEY_SYSMAN_MMC_INSERTED_NOT_MOUNTED)) {
			_LOGD("mmc_status is MMC_REMOVED or NOT_MOUNTED.");
		} else {
			_LOGD("mmc_status is MMC_MOUNTED.");
			return PMINFO_R_OK;
		}
	}

	return PMINFO_R_ERROR;
}

static void __apply_smack_for_mmc(const char *pkgid)
{
	char dirpath[BUF_SIZE] = {'\0'};

	snprintf(dirpath, BUF_SIZE, "%s/%s/.mmc", OPT_USR_APPS, pkgid);
	if (access(dirpath, F_OK) != 0) {
		_LOGE("Cannot access to [%s].", dirpath);
		return;
	}
	memset(dirpath, '\0', BUF_SIZE);

	// [pkgid]/.mmc/bin
	snprintf(dirpath, BUF_SIZE, "%s/.mmc/bin", pkgid);
	_coretpk_installer_set_privilege_setup_path((char*)pkgid, dirpath, APP_PATH_PRIVATE, (char*)pkgid);
	memset(dirpath, '\0', BUF_SIZE);

	// [pkgid]/.mmc/lib
	snprintf(dirpath, BUF_SIZE, "%s/.mmc/lib", pkgid);
	_coretpk_installer_set_privilege_setup_path((char*)pkgid, dirpath, APP_PATH_PRIVATE, (char*)pkgid);
	memset(dirpath, '\0', BUF_SIZE);

	// [pkgid]/.mmc/lost+found
	snprintf(dirpath, BUF_SIZE, "%s/.mmc/lost+found", pkgid);
	_coretpk_installer_set_privilege_setup_path((char*)pkgid, dirpath, APP_PATH_PRIVATE, (char*)pkgid);
	memset(dirpath, '\0', BUF_SIZE);

	// [pkgid]/.mmc/res
	snprintf(dirpath, BUF_SIZE, "%s/.mmc/res", pkgid);
	_coretpk_installer_set_privilege_setup_path((char*)pkgid, dirpath, APP_PATH_PRIVATE, (char*)pkgid);
	memset(dirpath, '\0', BUF_SIZE);

	return;
}

static int __pre_upgrade_for_mmc(const char *pkgid, const char *pkgfile, GList **dir_list, app2ext_handle **handle)
{
	int ret = 0;
	unsigned long long archive_size_byte = 0;
	int archive_size_mega = 0;

	ret = __is_default_external_storage();
	if (ret < 0) {
		_LOGD("Upgrade storage is internal.");
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
		_LOGE("@app2ext init failed\n");
		return PMINFO_R_ERROR;
	}
	if ((&((*handle)->interface) != NULL) && ((*handle)->interface.pre_upgrade != NULL) && ((*handle)->interface.post_upgrade != NULL) &&
			((*handle)->interface.disable != NULL)) {
		ret = (*handle)->interface.disable(pkgid);
		if (ret != APP2EXT_SUCCESS) {
			_LOGE("Unmount ret[%d]", ret);
		}
		*dir_list = __rpm_populate_dir_list();
		if (*dir_list == NULL) {
			_LOGE("@ \nError in populating the directory list\n");
			return PMINFO_R_ERROR;
		}
		ret = (*handle)->interface.pre_upgrade(pkgid, *dir_list, archive_size_mega);
		if (ret == APP2EXT_ERROR_MMC_STATUS) {
			_LOGE("@app2xt MMC is not here, go internal\n");
		} else if (ret == APP2EXT_SUCCESS){
			_LOGD("@pre_upgrade done, go internal\n");
		}
		else {
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

static int __post_upgrade_for_mmc(app2ext_handle *handle, const char *pkgid, GList *dir_list)
{
	int ret = __is_default_external_storage();
	if (ret != 0) {
		_LOGD("Upgrade storage is internal.");
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

static int __pre_install_for_mmc(const char *pkgid, const char *pkgfile, GList **dir_list, app2ext_handle **handle)
{
	int ret = 0;
	unsigned long long archive_size_byte = 0;
	int archive_size_mega = 0;

	ret = __is_default_external_storage();
	if (ret != 0) {
		_LOGD("Installed storage is internal.");
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
		_LOGE("@app2ext init failed\n");
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
			_LOGE("@ \nError in populating the directory list\n");
			return PMINFO_R_ERROR;
		}
		ret = (*handle)->interface.pre_install(pkgid, *dir_list, archive_size_mega);
		if (ret == APP2EXT_ERROR_MMC_STATUS) {
			_LOGE("@app2xt MMC is not here, go internal\n");
		} else if (ret == APP2EXT_SUCCESS){
			_LOGD("@pre_install done, go internal\n");
		}
		else {
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

static int __post_install_for_mmc(app2ext_handle *handle, const char *pkgid, GList *dir_list, int install_status)
{
	int ret = __is_default_external_storage();
	if (ret != 0) {
		_LOGD("Installed storage is internal.");
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

static char *__find_info_from_xml(const char *manifest, const char *find_info)
{
	const char *val = NULL;
	const xmlChar *node;
	xmlTextReaderPtr reader;
	char *info_val = NULL;
	int ret = -1;

	if(manifest == NULL) {
		_LOGE("input argument is NULL\n");
		return NULL;
	}

	if(find_info == NULL) {
		_LOGE("find_info is NULL\n");
		return NULL;
	}

	reader = xmlReaderForFile(manifest, NULL, 0);

	if (reader) {
		if (_child_element(reader, -1)) {
			node = xmlTextReaderConstName(reader);
			if (!node) {
				_LOGE("xmlTextReaderConstName value is NULL\n");
				goto end;
			}

			if (!strcmp(ASCII(node), "manifest")) {
				ret = _ri_get_attribute(reader,(char*)find_info,&val);
				if(ret != 0){
					_LOGE("error in getting the attribute value");
					goto end;
				}

				if(val) {
					info_val = strdup(val);
					if(info_val == NULL) {
						_LOGE("malloc failed!!");
					}
				}
			} else {
				_LOGE("unable to create xml reader\n");
			}
		}
	} else {
		_LOGE("xmlReaderForFile value is NULL\n");
	}

end:
	if (reader) {
		xmlFreeTextReader(reader);
	}

	if(val)
		free((void*)val);

	return info_val;
}

static int __coretpk_privilege_func(const char *name, void *user_data)
{
	int ret = 0;
	const char *perm[] = {NULL, NULL};
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
	char appdir[BUF_SIZE] = {'\0'};

	ret = pkgmgrinfo_appinfo_is_ui_gadget(handle, &is_ug);
	retvm_if(ret < 0, RPM_INSTALLER_ERR_PKG_NOT_FOUND, "Failed to get is_ui_gadget.\n");

	if (is_ug == true) {

		/*get pkgid*/
		ret = pkgmgrinfo_appinfo_get_pkgid(handle, &pkgid);
		retvm_if(ret < 0, RPM_INSTALLER_ERR_PKG_NOT_FOUND, "Failed to get pkgid\n");

		_LOGD("@[%s] has ui-gadget", pkgid);

		/*check bin directory*/
		snprintf(appdir, BUF_SIZE, "%s/%s/bin", USR_APPS, pkgid);
		if (access(appdir, F_OK) != 0) {
			/*permission(755)*/
			ret = mkdir(appdir, DIRECTORY_PERMISSION_755);
			if (ret < 0) {
				_LOGL("mkdir()", errno);
				return -1;
			}
		}

		/*get exec*/
		ret = pkgmgrinfo_appinfo_get_exec(handle, &exec);
		retvm_if(ret < 0, RPM_INSTALLER_ERR_PKG_NOT_FOUND, "Failed to get exec\n");

		/*make symlink to exec*/
		const char *ln_argv[] = { "/bin/ln", "-sf", "/usr/bin/ug-client", exec, NULL };
		ret = _ri_xsystem(ln_argv);
		retvm_if(ret < 0, RPM_INSTALLER_ERR_INTERNAL, "Failed to exec ln_argv\n");

		_LOGD("@[%s] success symlink to [/usr/bin/ug-client]", exec);

		* (bool *) user_data = true;
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

static int __pkg_remove_update(const char *pkgid)
{
	int ret = 0;
	char buff[BUF_SIZE] = {'\0'};
	char rootpath[BUF_SIZE] = {'\0'};

	if (pkgid == NULL) {
		_LOGE("pkgid is NULL.");
		return -1;
	}

	// start
	_ri_broadcast_status_notification(pkgid, "coretpk", "start", "update");

	// remove dir for clean (/opt/usr/apps/[pkgid])
	snprintf(rootpath, BUF_SIZE, "%s/%s/", OPT_USR_APPS, pkgid);
	if (__is_dir(rootpath)) {
		_rpm_delete_dir(rootpath);
	}

	// Remove origin rule
	_ri_privilege_unregister_package(pkgid);

	// unzip pkg path from factory-reset data
	memset(rootpath, '\0', BUF_SIZE);
	snprintf(rootpath, BUF_SIZE, "opt/usr/apps/%s/*", pkgid);
	const char *pkg_argv[] = { "/usr/bin/unzip", "-oX", OPT_ZIP_FILE, rootpath, "-d", "/", NULL };
	ret = _ri_xsystem(pkg_argv);
	if (ret != 0) {
		_LOGE("/usr/bin/unzip(%s) failed.", rootpath);
	}

	_ri_broadcast_status_notification(pkgid, "coretpk", "install_percent", "30");

	// remove opt xml
	snprintf(buff, BUF_SIZE, "%s/%s.xml", OPT_SHARE_PACKAGES, pkgid);
	(void)remove(buff);

	// updated usr xml
	memset(buff, '\0', BUF_SIZE);
	snprintf(buff, BUF_SIZE, "%s/%s.xml", USR_SHARE_PACKAGES, pkgid);

	_LOGD("manifest = [%s].",buff);

	ret = pkgmgr_parser_parse_manifest_for_upgrade(buff, NULL);
	if (ret < 0) {
		_LOGE("pkgmgr_parser_parse_manifest_for_upgrade(%s) is failed.", pkgid);
		return ret;
	}
	_LOGD("pkgmgr_parser_parse_manifest_for_upgrade() is ok.");

	_ri_broadcast_status_notification(pkgid, "coretpk", "install_percent", "60");

	// apply smack for pkg root path
	memset(buff, '\0', BUF_SIZE);
	snprintf(buff, BUF_SIZE, "%s/%s", OPT_USR_APPS, pkgid);
	_ri_privilege_setup_path(pkgid, buff, PERM_APP_PATH_ANY_LABEL, pkgid);

	// apply smack for defined directory
	__rpm_apply_smack((char*)pkgid, 0);

	// apply privilege
	ret = _ri_apply_privilege((char*)pkgid, 0);
	if (ret != 0) {
		_LOGE("_ri_apply_privilege(%s) failed. ret = [%d]", pkgid, ret);
	} else {
		_LOGD("_ri_apply_privilege(%s) success.", pkgid);
	}

	// reload smack
	ret = _ri_smack_reload(pkgid, UPGRADE_REQ);
	if (ret != 0) {
		_LOGE("_ri_smack_reload(%s) failed.", pkgid);
	}

	// finish
	if (ret != 0) {
		_ri_broadcast_status_notification(pkgid, "coretpk", "end", "fail");
	} else {
		_ri_broadcast_status_notification(pkgid, "coretpk", "install_percent", "100");
		_ri_broadcast_status_notification(pkgid, "coretpk", "end", "ok");
	}

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
	int res = smack_lsetlabel(path, label, SMACK_LABEL_ACCESS);
	if (res != 0)
	{
		_LOGE("smack set label(%s) failed[%d] (path:[%s]))", label, res, path);
		return -1;
	}
	return 0;
}

int _coretpk_installer_get_smack_label_access(const char *path, char **label)
{
	int res = smack_lgetlabel(path, label, SMACK_LABEL_ACCESS);
	if (res != 0)
	{
		_LOGE("Error in getting smack ACCESS label failed. result[%d] (path:[%s]))", res, path);
		return -1;
	}
	return 0;
}

int _coretpk_installer_set_smack_label_transmute(const char *path, const char *flag)
{
	int res = smack_lsetlabel(path, flag, SMACK_LABEL_TRANSMUTE);
	if (res != 0)
	{
		_LOGE("smack set label(%s) failed[%d] (path:[%s]))", flag, res, path);
		return -1;
	}
	return 0;
}

int _coretpk_installer_verify_privilege_list(GList *privilege_list, int visibility, const char *api_version)
{
	char *error_privilege_name = NULL;
	GList *list = NULL;
	int ret = 0;

	ret = privilege_manager_verify_privilege(api_version, PRVMGR_PACKAGE_TYPE_CORE, privilege_list, visibility, &error_privilege_name);
	if (ret != PRVMGR_ERR_NONE) {
		_LOGE("privilege_manager_verify_privilege_list(PRVMGR_PACKAGE_TYPE_CORE) failed. ret = [%d][%s]", ret, error_privilege_name);
		fprintf(stdout, "\n verify_privilege_list(PRVMGR_PACKAGE_TYPE_CORE) failed. [%d][%s]\n", ret, error_privilege_name);

		if (!error_privilege_name) {
			ret = RPM_INSTALLER_ERR_SIG_VERIFICATION_FAILED;
			goto err;
		}

		if (strstr(error_privilege_name, "[DEPRECATED_PRIVILEGE]") != NULL)
			ret = RPM_INSTALLER_ERR_PRIVILEGE_USING_LEGACY_FAILED;
		else if (strstr(error_privilege_name, "[NO_EXIST_PRIVILEGE]") != NULL)
			ret = RPM_INSTALLER_ERR_PRIVILEGE_UNKNOWN;
		else if (strstr(error_privilege_name, "[MISMATCHED_PRIVILEGE_LEVEL]") != NULL)
			ret = RPM_INSTALLER_ERR_PRIVILEGE_UNAUTHORIZED;
		else {
			_LOGE("Unidentified privilege error : [%s]", error_privilege_name);
			ret = RPM_INSTALLER_ERR_SIG_VERIFICATION_FAILED;
		}
	} else {
		_LOGD("privilege_manager_verify_privilege_list(PRVMGR_PACKAGE_TYPE_CORE) is ok.");
	}

err:

	if (error_privilege_name)
		free(error_privilege_name);

	list = g_list_first(privilege_list);
	while (list) {
		if (list->data) {
			free(list->data);
		}
		list = g_list_next(list);
	}
	g_list_free(privilege_list);
	privilege_list = NULL;

	return ret;
}

void _coretpk_installer_search_ui_gadget(const char *pkgid)
{
	int ret = 0;
	bool is_ug_pkg = false;
	pkgmgrinfo_pkginfo_h pkghandle = NULL;

	ret = pkgmgrinfo_pkginfo_get_pkginfo(pkgid, &pkghandle);
	retm_if(ret < 0, "@Failed to get the pkginfo handle.");

	/* search ug app */
	ret = pkgmgrinfo_appinfo_get_list(pkghandle, PM_UI_APP, __ui_gadget_func, &is_ug_pkg);
	tryvm_if(ret < 0, ret = RPM_INSTALLER_ERR_INTERNAL, "Fail to get applist");

	/*if there is ug app,  apply privilege*/
	if (is_ug_pkg == true) {
		ret = pkgmgrinfo_pkginfo_foreach_privilege(pkghandle, __coretpk_privilege_func, NULL);
		tryvm_if(ret < 0, ret = RPM_INSTALLER_ERR_INTERNAL, "Fail to get privilege list");
	}

catch :
	pkgmgrinfo_pkginfo_destroy_pkginfo(pkghandle);
}

int _coretpk_backend_interface(const char *reqcommand, const ri_frontend_cmdline_arg *data)
{
	if (reqcommand == NULL || data == NULL) {
		_LOGE("reqcommand or data is NULL.");
		return -1;
	}

	if (strncmp(reqcommand, CORETPK_INSTALL, strlen(CORETPK_INSTALL)) == 0) {
		return _coretpk_installer_prepare_package_install(data->pkgid, data->clientid);
	}  else if (strncmp(reqcommand, CORETPK_UNINSTALL, strlen(CORETPK_UNINSTALL)) == 0) {
		return _coretpk_installer_prepare_package_uninstall(data->pkgid);
	} else if (strncmp(reqcommand, CORETPK_DIRECTORY_INSTALL, strlen(CORETPK_DIRECTORY_INSTALL)) == 0) {
		return _coretpk_installer_prepare_directory_install(data->pkgid, data->clientid);
	} else if (strncmp(reqcommand, CORETPK_MOVE, strlen(CORETPK_MOVE)) == 0) {
		return _coretpk_installer_package_move(data->pkgid, data->move_type);
	} else if (strncmp(reqcommand, CORETPK_REINSTALL, strlen(CORETPK_REINSTALL)) == 0) {
		return _coretpk_installer_package_reinstall(data->pkgid, data->clientid);
	} else {
		return -1;
	}
}

#if 0
static char * _coretpk_installer_get_pkg_path(const char *pkg_path, const char *pkgid)
{
	int ret = 0;
	char buff[BUF_SIZE] = {'\0'};
	char *real_path = NULL;

	snprintf(buff, BUF_SIZE, "%s/%s", pkg_path, pkgid);
	do {
		if (__is_dir(buff)) break;
		memset(buff, '\0', BUF_SIZE);
		snprintf(buff, BUF_SIZE, "%s/%s", OPT_USR_APPS, pkgid);
		if (__is_dir(buff)) break;
		memset(buff, '\0', BUF_SIZE);
		snprintf(buff, BUF_SIZE, "/opt/apps/%s", pkgid);
		if (__is_dir(buff)) break;
		memset(buff, '\0', BUF_SIZE);
		snprintf(buff, BUF_SIZE, "%s/%s", USR_APPS, pkgid);
		if (__is_dir(buff)) break;
	} while (0);

	ret = chdir(buff);
	if (ret != 0) {
		_LOGE("chdir() failed [%s]\n", strerror(errno));
		return NULL;
	}

	real_path = (char *)malloc(strlen(buff) + 1);
	if (real_path == NULL) {
		_LOGE("Malloc failed!\n");
		return NULL;
	}
	memset(real_path, '\0', strlen(buff) + 1);
	memcpy(real_path, buff, strlen(buff));

	return real_path;
}
#endif

int _coretpk_installer_verify_signatures(const char *root_path, const char *pkgid, int *visibility)
{
	int ret = 0;
	char buff[BUF_SIZE] = {'\0'};
	const char *pkg_path = root_path;

	_LOGD("root_path=[%s], pkgid=[%s]", root_path, pkgid);

#if 0
	// check for signature and certificate
	pkg_path = _coretpk_installer_get_pkg_path(root_path, pkgid);
	if (pkg_path == NULL) {
		_LOGE("pkg_path is NULL.");
		return 0;
	}
#endif

	ret = chdir(root_path);
	if (ret != 0) {
		_LOGE("chdir(%s) failed. [%s]", root_path, strerror(errno));
	}

	// author-signature.xml is mandatory
	snprintf(buff, BUF_SIZE, "%s/author-signature.xml", pkg_path);
	if (access(buff, F_OK) == 0) {
		_LOGD("author-signature.xml is found, path=[%s]", buff);
		ret = _ri_verify_sig_and_cert(buff, visibility);
		if (ret) {
			_LOGE("_ri_verify_sig_and_cert() failed, path=[%s]", buff);
			ret = -1;
			goto end;
		}
		_LOGD("_ri_verify_sig_and_cert succeed, path=[%s]", buff);
	} else {
		_LOGE("cannot access xml, path=[%s]", buff);
		ret = -1;
		goto end;
	}
	memset(buff, '\0', BUF_SIZE);

	// signature1.xml is mandatory
	snprintf(buff, BUF_SIZE, "%s/signature1.xml", pkg_path);
	if (access(buff, F_OK) == 0) {
		_LOGD("signature1.xml is found, path=[%s]", pkg_path);
		ret = _ri_verify_sig_and_cert(buff, visibility);
		if (ret) {
			_LOGE("_ri_verify_sig_and_cert() failed, path=[%s]", buff);
			ret = -1;
			goto end;
		}
		_LOGD("_ri_verify_sig_and_cert() succeed, path=[%s]", buff);
	} else {
		_LOGE("cannot access xml, path=[%s]", buff);
		ret = -1;
		goto end;
	}
	memset(buff, '\0', BUF_SIZE);
	ret = 0;

end:
#if 0
	if(pkg_path){
		free(pkg_path);
		pkg_path = NULL;
	}
#endif

	return ret;
}

char* _coretpk_installer_load_directory(char *directory,char *pkgfile)
{
	DIR *dir;
	struct dirent entry;
	struct dirent *result;
	int ret = 0;
	char *buf = NULL;
	char *pkgname = NULL;
	char xml_file[MAX_BUF_SIZE] = {'\0'};

	buf = malloc(BUF_SIZE);
	if (buf == NULL) {
		_LOGE("malloc() failed.");
		return NULL;
	}

	dir = opendir(directory);
	if (!dir) {
		_LOGL("opendir()", errno);
		free(buf);
		return NULL;
	}

	_LOGD("loading manifest files, directory=[%s]", directory);

	for (ret = readdir_r(dir, &entry, &result);
			ret == 0 && result != NULL;
			ret = readdir_r(dir, &entry, &result)) {
		char *manifest = NULL;

		if (!strcmp(entry.d_name, ".") ||
			!strcmp(entry.d_name, "..")) {
			continue;
		}

		manifest = _manifest_to_package(entry.d_name);
		if (!manifest) {
			_LOGE("failed to convert file to xml, file=[%s].", entry.d_name);
			continue;
		}

		memset(xml_file,'\0',MAX_BUF_SIZE);
		snprintf(xml_file,MAX_BUF_SIZE-1,"%s/%s", directory, manifest);
		_LOGD("manifest=[%s], path=[%s]", manifest, xml_file);

		ret = _get_package_name_from_xml(xml_file, &pkgname);
		if (ret != PMINFO_R_OK || pkgname == NULL) {
			_LOGE("unable to read, xml_file=[%s]", xml_file);
			free(manifest);
			continue;
		}

		if (pkgname[0] != '\0') {
			snprintf(buf, BUF_SIZE, "%s/%s", directory, manifest);
			free(manifest);
			break;
		}

		free(manifest);
	}

	closedir(dir);

	if (pkgname) {
		free(pkgname);
		pkgname = NULL;
	}


	return buf;
}

pkginfo *_coretpk_installer_get_pkg_info(char *manifest)
{
	pkginfo *info = NULL;
	char *tmp_pkgid = NULL;
	char *tmp_version = NULL;
	char *tmp_api_version = NULL;
	char buff[BUF_SIZE] = {'\0'};

	if (manifest == NULL || strlen(manifest) >= BUF_SIZE) {
		_LOGE("invalid parameter");
		goto err;
	}

	info = calloc(1, sizeof(pkginfo));
	if (info == NULL) {
		_LOGE("calloc() failed.");
		goto err;
	}

	strcpy(buff, manifest);
	tmp_pkgid = __find_info_from_xml(buff, "package");
	if (tmp_pkgid != NULL) {
		strncpy(info->package_name, tmp_pkgid, sizeof(info->package_name) - 1);
		free(tmp_pkgid);
	} else {
		_LOGE("can not get pkgid");
		goto err;
	}

	tmp_version = __find_info_from_xml(buff, "version");
	if (tmp_version != NULL) {
		strncpy(info->version, tmp_version, sizeof(info->version) - 1);
		free(tmp_version);
	} else {
		_LOGE("can not get version");
		goto err;
	}

	tmp_api_version = __find_info_from_xml(buff, "api-version");
	if (tmp_version != NULL) {
		strncpy(info->api_version, tmp_api_version, sizeof(info->api_version) - 1);
		free(tmp_api_version);
	} else {
		_LOGE("can not get api-version");
	}

	_LOGD("pkgid=[%s], version=[%s], api-version=[%s]", info->package_name, info->version, info->api_version);

err:
	return info;
}

pkginfo *_coretpk_installer_get_pkgfile_info(char *pkgfile)
{
	pkginfo *info = NULL;
	int ret = 0;
	char cwd[BUF_SIZE] = {'\0'};
	char buff[BUF_SIZE] = {'\0'};
	char manifest[BUF_SIZE] = { '\0'};
	char *temp = NULL;

	char *tmp_pkgid = NULL;
	char *tmp_version = NULL;
	char *tmp_api_version = NULL;

	temp = getcwd(cwd, BUF_SIZE);
	if ((temp == NULL) || (cwd[0] == '\0')) {
		_LOGL("getcwd()", errno);
		return NULL;
	}

	ret = mkdir(TEMP_DIR, DIRECTORY_PERMISSION_644);
	if (ret < 0) {
		if (access(TEMP_DIR, F_OK) == 0) {
			_rpm_delete_dir(TEMP_DIR);
			ret = mkdir(TEMP_DIR, DIRECTORY_PERMISSION_644);
			if (ret < 0) {
				_LOGL("mkdir()", errno);
				return NULL;
			}
		} else {
			_LOGL("access()", errno);
			return NULL;
		}
	}

	ret = chdir(TEMP_DIR);
	if (ret != 0) {
		_LOGL("chdir()", errno);
		goto err;
	}

	_LOGD("switched to %s", TEMP_DIR);

	snprintf(manifest, BUF_SIZE, "%s", CORETPK_XML);
	const char *unzip_argv[] = { "/usr/bin/unzip", "-o", pkgfile, manifest, "-d", TEMP_DIR, NULL };
	ret = _ri_xsystem(unzip_argv);
	if (ret != 0) {
		_LOGE("cannot find manifest in the package.");
		ret = RPM_INSTALLER_ERR_NO_MANIFEST;
		goto err;
	}

	char* manifestpath = _coretpk_installer_load_directory(TEMP_DIR, pkgfile);
	if (manifestpath != NULL && strlen(manifestpath) < BUF_SIZE) {
		strcpy(buff, manifestpath);
		free(manifestpath);
	}

	if (buff[0] == '\0') {
		_LOGE("cannot find manifest in the package.");
		goto err;
	}

	_LOGD("manifest file=[%s]",buff);

	info = calloc(1, sizeof(pkginfo));
	if (info == NULL) {
		_LOGE("calloc() failed.");
		goto err;
	}

	tmp_pkgid = __find_info_from_xml(buff, "package");
	if (tmp_pkgid != NULL) {
		strncpy(info->package_name, tmp_pkgid, sizeof(info->package_name) - 1);
		free(tmp_pkgid);
	} else {
		_LOGE("can not get pkgid");
		goto err;
	}

	tmp_version = __find_info_from_xml(buff, "version");
	if (tmp_version != NULL) {
		strncpy(info->version, tmp_version, sizeof(info->version) - 1);
		free(tmp_version);
	} else {
		_LOGE("can not get version");
		goto err;
	}

	tmp_api_version = __find_info_from_xml(buff, "api-version");
	if (tmp_version != NULL) {
		strncpy(info->api_version, tmp_api_version, sizeof(info->api_version) - 1);
		free(tmp_api_version);
	} else {
		_LOGE("can not get api-version");
	}

	_LOGD("pkgid=[%s], version=[%s], api-version=[%s]", info->package_name, info->version, info->api_version);

	info->is_widget = _coretpk_parser_is_widget(buff);

err:
	_rpm_delete_dir(TEMP_DIR);

	ret = chdir(cwd);
	if (ret != 0) {
		_LOGL("chdir()", errno);
	}

	return info;
}

int _coretpk_installer_get_configuration_value(char *value)
{
	char buffer[BUF_SIZE] = {'\0'};
	char *p = NULL;
	FILE *fi = NULL;
	int len = 0;
	int ret = 0;

	if (access(CORETPK_CONFIG_PATH, F_OK) != 0) {
		/* if there is no ini file, signature has to be checked */
		return 1;
	}

	fi = fopen(CORETPK_CONFIG_PATH, "r");
	if (fi == NULL) {
		_LOGL("fopen()", errno);
		return 0;
	}

	while (fgets(buffer, BUF_SIZE, fi) != NULL) {
		/* buffer will be like signature=off\n\0*/
		if (strncmp(buffer, value, strlen(value)) == 0) {
			len = strlen(buffer);
			/*remove newline character*/
			buffer[len - 1] = '\0';
			p = strchr(buffer, '=');
			if (p) {
				p++;
				if (strcmp(p, "on") == 0) {
					ret = 1;
				} else {
					ret = 0;
				}
			}
		} else {
			continue;
		}
	}

	fclose(fi);
	return ret;
}

int _coretpk_installer_apply_file_policy(char *filepath)
{
	int ret = 0;

	if (access(filepath, F_OK) == 0) {
		/*permission(644)*/
		ret = chmod(filepath, FILE_PERMISSION_644);
		if (ret != 0) {
			_LOGL("chmod()", errno);
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
	char fullpath[BUF_SIZE] = {'\0'};

	if (access(dirpath, F_OK) != 0) {
		_LOGE("skip! empty dirpath=[%s]", dirpath);
		return 0;
	}

	dir = opendir(dirpath);
	if (!dir) {
		_LOGE("opendir(%s) failed. [%d][%s]", dirpath, errno, strerror(errno));
		return -1;
	}

	// permission(755)
	ret = _coretpk_installer_change_mode(dirpath, DIRECTORY_PERMISSION_755);
	if (ret != 0) {
		_LOGE("_coretpk_installer_change_mode is failed, dirpath=[%s]", dirpath);
	}

	for (ret = readdir_r(dir, &entry, &result); ret == 0 && result != NULL; ret = readdir_r(dir, &entry, &result)){
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

		// sub dir
		if (entry.d_type == DT_DIR) {
			snprintf(fullpath, BUF_SIZE, "%s/%s", dirpath, entry.d_name);

			// owner:group
			if (appowner == true) {
				ret = _coretpk_installer_change_directory_owner(fullpath, APP_OWNER_ID, APP_GROUP_ID);
				if (ret != 0) {
					_LOGE("_coretpk_installer_change_directory_owner failed, fullpath=[%s]", fullpath);
				}
			}
		// sub file
		} else {
			snprintf(fullpath, BUF_SIZE, "%s/%s", dirpath, entry.d_name);

			// permission(input mode)
			ret = _coretpk_installer_change_mode(fullpath, mode);
			if (ret != 0) {
				_LOGE("_coretpk_installer_change_mode failed, fullpath=[%s]", fullpath);
			}

			// owner:group
			if (appowner == true) {
				ret = _coretpk_installer_change_file_owner(fullpath, APP_OWNER_ID, APP_GROUP_ID);
				if (ret != 0) {
					_LOGE("_coretpk_installer_change_file_owner failed, fullpath=[%s]", fullpath);
				}
			}
		}

		// find next dir
		if (entry.d_type == DT_DIR) {
			ret = _coretpk_installer_apply_directory_policy(fullpath, mode, appowner);
			if(ret != 0 ){
				_LOGE("_coretpk_installer_apply_directory_policy failed, fullpath=[%s]", fullpath);
			}
		}
		memset(fullpath, '\0', BUF_SIZE);
	}

	closedir(dir);

	return ret;
}

int _coretpk_installer_make_directory_for_ext(char *pkgid)
{
	char ext_pkg_base_path[BUF_SIZE] = {0, };
	char temp_path[BUF_SIZE] = {0, };
	char pkg_shared_data_path[BUF_SIZE] = {0, };
	char *shared_data_label = NULL;
	int res = 0;

	if (access(OPT_STORAGE_SDCARD, F_OK) != 0) {
		_LOGL("There is no OPT_STORAGE_SDCARD", errno);
		return -1;
	}

	/*pkg root path*/
	if (access(OPT_STORAGE_SDCARD_APP_ROOT, F_OK) != 0) {
		/*permission(755)*/
		res = mkdir(OPT_STORAGE_SDCARD_APP_ROOT, DIRECTORY_PERMISSION_755);
		if (res < 0) {
			_LOGL("mkdir()", errno);
			return -1;
			}
	}

	/*app root path*/
	snprintf(ext_pkg_base_path, BUF_SIZE, "%s/%s", OPT_STORAGE_SDCARD_APP_ROOT, pkgid);
	res = mkdir(ext_pkg_base_path, 0500);
	if (res == -1 && errno != EEXIST)
	{
		_LOGE("mkdir() is failed. error = [%d] strerror = [%s]", errno, strerror(errno));
		return -1;
	}

	res = _coretpk_installer_set_smack_label_access(ext_pkg_base_path, "_");
	if (res != 0)
	{
		_LOGE("_coretpk_installer_set_smack_label_access() is failed.");
		return -1;
	}

	//data
	memset(temp_path, 0, BUF_SIZE);
	strcpy(temp_path, ext_pkg_base_path);
	strncat(temp_path, "/data", strlen("/data"));
	res = mkdir(temp_path, 0700);
	if (res == -1 && errno != EEXIST)
	{
		_LOGE("mkdir() is failed. error = [%d] strerror = [%s]", errno, strerror(errno));
		return -1;
	}
	res = _coretpk_installer_set_smack_label_access(temp_path, pkgid);
	if (res != 0)
	{
		_LOGE("_coretpk_installer_set_smack_label_access() is failed.");
		return -1;
	}

	//cache
	memset(temp_path, 0, BUF_SIZE);
	strcpy(temp_path, ext_pkg_base_path);
	strncat(temp_path, "/cache", strlen("/cache"));
	res = mkdir(temp_path, 0700);
	if (res == -1 && errno != EEXIST)
	{
		_LOGE("mkdir() is failed. error = [%d] strerror = [%s]", errno, strerror(errno));
		return -1;
	}
	res = _coretpk_installer_set_smack_label_access(temp_path, pkgid);
	if (res != 0)
	{
		_LOGE("_coretpk_installer_set_smack_label_access() is failed.");
		return -1;
	}

	//shared
	memset(temp_path, 0, BUF_SIZE);
	strcpy(temp_path, ext_pkg_base_path);
	strncat(temp_path, "/shared", strlen("/shared"));
	res = mkdir(temp_path, 0500);
	if (res == -1 && errno != EEXIST)
	{
		_LOGE("mkdir() is failed. error = [%d] strerror = [%s]", errno, strerror(errno));
		return -1;
	}
	res = _coretpk_installer_set_smack_label_access(temp_path, "_");
	if (res != 0)
	{
		_LOGE("_coretpk_installer_set_smack_label_access() is failed.");
		return -1;
	}

	snprintf(pkg_shared_data_path, BUF_SIZE, "%s/%s/%s", OPT_USR_APPS, pkgid , "shared/data");

	res = access(pkg_shared_data_path, F_OK);
	if (res == 0)
	{
		_LOGD("Exist shared/data folder (path:[%s])", pkg_shared_data_path);
		res = _coretpk_installer_get_smack_label_access(pkg_shared_data_path, &shared_data_label);
		if (res != 0)
		{
			_LOGE("_coretpk_installer_get_smack_label_access() is failed.");
			return -1;
		}

		//shared/data
		strncat(temp_path, "/data", strlen("/data"));
		res = mkdir(temp_path, 0705);
		if (res == -1 && errno != EEXIST)
		{
			_LOGE("mkdir() is failed. error = [%d] strerror = [%s]", errno, strerror(errno));
			return -1;
		}

		res = _coretpk_installer_set_smack_label_access(temp_path, shared_data_label);
		if (res != 0)
		{
			_LOGE("_coretpk_installer_set_smack_label_access() is failed.");
			return -1;
		}

		res = _coretpk_installer_set_smack_label_transmute(temp_path, "1");
		if (res != 0)
		{
			_LOGE("_coretpk_installer_set_smack_label_transmute() is failed.");
//			return -1;
		}

		//shared/cache
		memset(temp_path, 0, BUF_SIZE);
		strcpy(temp_path, ext_pkg_base_path);
		strncat(temp_path, "/shared", strlen("/shared"));
		strncat(temp_path, "/cache", strlen("/cache"));
		res = mkdir(temp_path, 0700);
		if (res == -1 && errno != EEXIST)
		{
			_LOGE("mkdir() is failed. error = [%d] strerror = [%s]", errno, strerror(errno));
			return -1;
		}
		res = _coretpk_installer_set_smack_label_access(temp_path, shared_data_label);
		if (res != 0)
		{
			_LOGE("_coretpk_installer_set_smack_label_access() is failed.");
			return -1;
		}
		res = _coretpk_installer_set_smack_label_transmute(temp_path, "1");
		if (res != 0)
		{
			_LOGE("_coretpk_installer_set_smack_label_transmute() is failed.");
//			return -1;
		}

	}
	else if (res == -1 && errno == ENOENT)
	{
		_LOGD("Directory dose not exist. path: %s, errno: %d (%s)",
				pkg_shared_data_path, errno, strerror(errno));
		return 0;
	}
	else
	{
		_LOGE("access() failed. path: %s, errno: %d (%s)",
				pkg_shared_data_path, errno, strerror(errno));
		return -1;
	}

	return 0;
}


int _coretpk_installer_make_directory(char *pkgid)
{
	int ret = 0;
	char appdir[BUF_SIZE] = {'\0'};
	char rootfile[BUF_SIZE] = {'\0'};
	char *groupid = NULL;

	// check param
	if (pkgid == NULL) {
		_LOGE("pkgid is NULL.");
		return -1;
	}

	// root
	memset(appdir, '\0', BUF_SIZE);
	snprintf(appdir, BUF_SIZE, "%s/%s", OPT_USR_APPS, pkgid);
	if (access(appdir, F_OK) != 0) {
		// permission(755)
		ret = mkdir(appdir, DIRECTORY_PERMISSION_755);
		if (ret < 0) {
			_LOGE("mkdir(%s) failed. [%d][%s]", appdir, errno, strerror(errno));
		}
	}
	ret = _coretpk_installer_apply_directory_policy(appdir, PERM_BASE, false);
	if (ret != 0) {
		_LOGE("_coretpk_installer_apply_directory_policy() failed, appdir=[%s], ret=[%d]", appdir, ret);
		return -1;
	}

	// bin
	memset(appdir, '\0', BUF_SIZE);
	snprintf(appdir, BUF_SIZE, "%s/%s/bin", OPT_USR_APPS, pkgid);
	if (access(appdir, F_OK) != 0) {
		memset(appdir, '\0', BUF_SIZE);
		snprintf(appdir, BUF_SIZE, "%s/%s/bin", USR_APPS, pkgid);
		if (access(appdir, F_OK) != 0) {
			_LOGE("[%s] is not existed.", appdir);
			return -1;
		}
	}
	ret = _coretpk_installer_apply_directory_policy(appdir, PERM_BASE | PERM_EXECUTE, false);
	if (ret != 0) {
		_LOGE("_coretpk_installer_apply_directory_policy() failed, appdir=[%s], ret=[%d]", appdir, ret);
		return -1;
	}

	// data
	memset(appdir, '\0', BUF_SIZE);
	snprintf(appdir, BUF_SIZE, "%s/%s/data", OPT_USR_APPS, pkgid);
	if (access(appdir, F_OK) != 0) {
		// permission(755)
		ret = mkdir(appdir, DIRECTORY_PERMISSION_755);
		if (ret < 0) {
			_LOGE("mkdir failed, appdir=[%s], errno=[%d][%s]", appdir, errno, strerror(errno));
		}
	}
	ret = _coretpk_installer_apply_directory_policy(appdir, PERM_BASE, true);
	if (ret != 0) {
		_LOGE("_coretpk_installer_apply_directory_policy() failed, appdir=[%s], ret=[%d]", appdir, ret);
		return -1;
	}

	//lib
	memset(appdir, '\0', BUF_SIZE);
	snprintf(appdir, BUF_SIZE, "%s/%s/lib", OPT_USR_APPS, pkgid);
	if (access(appdir, F_OK) != 0) {
		memset(appdir, '\0', BUF_SIZE);
		snprintf(appdir, BUF_SIZE, "%s/%s/lib", USR_APPS, pkgid);
	}
	ret = _coretpk_installer_apply_directory_policy(appdir, PERM_BASE | PERM_EXECUTE, false);
	if (ret != 0) {
		_LOGE("_coretpk_installer_apply_directory_policy() failed, appdir=[%s], ret=[%d]", appdir, ret);
		return -1;
	}

	// res
	memset(appdir, '\0', BUF_SIZE);
	snprintf(appdir, BUF_SIZE, "%s/%s/res", OPT_USR_APPS, pkgid);
	if (access(appdir, F_OK) != 0) {
		memset(appdir, '\0', BUF_SIZE);
		snprintf(appdir, BUF_SIZE, "%s/%s/res", USR_APPS, pkgid);
	}
	ret = _coretpk_installer_apply_directory_policy(appdir, PERM_BASE, false);
	if (ret != 0) {
		_LOGE("_coretpk_installer_apply_directory_policy() failed, appdir=[%s], ret=[%d]", appdir, ret);
		return -1;
	}

	// cache
	memset(appdir, '\0', BUF_SIZE);
	snprintf(appdir, BUF_SIZE, "%s/%s/cache", OPT_USR_APPS, pkgid);
	if (access(appdir, F_OK) != 0) {
		// permission(755)
		ret = mkdir(appdir, DIRECTORY_PERMISSION_755);
		if (ret < 0) {
			_LOGE("mkdir failed, appdir=[%s], errno=[%d][%s]", appdir, errno, strerror(errno));
		}
	}
	ret = _coretpk_installer_apply_directory_policy(appdir, PERM_BASE, true);
	if (ret != 0) {
		_LOGE("_coretpk_installer_apply_directory_policy() failed, appdir=[%s], ret=[%d]", appdir, ret);
		return -1;
	}

	// shared
	memset(appdir, '\0', BUF_SIZE);
	snprintf(appdir, BUF_SIZE, "%s/%s/shared", OPT_USR_APPS, pkgid);
	if (access(appdir, F_OK) != 0) {
		ret = mkdir(appdir, DIRECTORY_PERMISSION_755);
		if (ret < 0) {
			_LOGE("mkdir(%s) failed. [%d][%s]", appdir, errno, strerror(errno));
		}
	}
	ret = _coretpk_installer_apply_directory_policy(appdir, PERM_BASE, false);
	if (ret != 0) {
		_LOGE("_coretpk_installer_apply_directory_policy() failed, appdir=[%s], ret=[%d]", appdir, ret);
		return -1;
	}
	memset(appdir, '\0', BUF_SIZE);
	snprintf(appdir, BUF_SIZE, "%s/%s/shared", USR_APPS, pkgid);
	if (access(appdir, F_OK) != 0) {
		ret = mkdir(appdir, DIRECTORY_PERMISSION_755);
		if (ret < 0) {
			_LOGE("mkdir failed. appdir=[%s], errno=[%d][%s]", appdir, errno, strerror(errno));
		}
	}
	ret = _coretpk_installer_apply_directory_policy(appdir, PERM_BASE, false);
	if (ret != 0) {
		_LOGE("_coretpk_installer_apply_directory_policy() failed, appdir=[%s], ret=[%d]", appdir, ret);
		return -1;
	}

	// shared/data
	memset(appdir, '\0', BUF_SIZE);
	snprintf(appdir, BUF_SIZE, "%s/%s/shared/data", OPT_USR_APPS, pkgid);
	ret = _coretpk_installer_apply_directory_policy(appdir, PERM_BASE, true);
	if (ret != 0) {
		_LOGE("_coretpk_installer_apply_directory_policy() failed, appdir=[%s], ret=[%d]", appdir, ret);
		return -1;
	}

	// shared/cache
	memset(appdir, '\0', BUF_SIZE);
	snprintf(appdir, BUF_SIZE, "%s/%s/shared/cache", OPT_USR_APPS, pkgid);
	if (access(appdir, F_OK) != 0) {
		ret = mkdir(appdir, DIRECTORY_PERMISSION_755);
		if (ret < 0) {
			_LOGE("mkdir failed. appdir=[%s], errno=[%d][%s]", appdir, errno, strerror(errno));
		}
	}
	ret = _coretpk_installer_apply_directory_policy(appdir, PERM_BASE, true);
	if (ret != 0) {
		_LOGE("_coretpk_installer_apply_directory_policy() failed, appdir=[%s], ret=[%d]", appdir, ret);
		return -1;
	}

	// shared/res
	memset(appdir, '\0', BUF_SIZE);
	snprintf(appdir, BUF_SIZE, "%s/%s/shared/res", OPT_USR_APPS, pkgid);
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

	// shared/trusted
	memset(appdir, '\0', BUF_SIZE);
	snprintf(appdir, BUF_SIZE, "%s/%s/shared/trusted", OPT_USR_APPS, pkgid);
	if (access(appdir, F_OK) != 0) {
		ret = _coretpk_installer_get_group_id(pkgid, &groupid);
		if (ret == 0) {
			ret = mkdir(appdir, DIRECTORY_PERMISSION_755);
			if (ret < 0) {
				_LOGE("mkdir failed, appdir=[%s], errno=[%d][%s]", appdir, errno, strerror(errno));
			}
			free(groupid);
		}
	}
	ret = _coretpk_installer_apply_directory_policy(appdir, PERM_BASE, true);
	if (ret != 0) {
		_LOGE("_coretpk_installer_apply_directory_policy() failed, appdir=[%s], ret=[%d]", appdir, ret);
		return -1;
	}

	// [pkgid]/tizen-manifest.xml
	snprintf(rootfile, BUF_SIZE, "%s/%s/%s", OPT_USR_APPS, pkgid, CORETPK_XML);
	ret = _coretpk_installer_apply_file_policy(rootfile);
	if (ret != 0) {
		_LOGE("_coretpk_installer_apply_file_policy() failed, rootfile=[%s]", rootfile);
		return -1;
	}
	memset(rootfile, '\0', BUF_SIZE);
	snprintf(rootfile, BUF_SIZE, "%s/%s/%s", USR_APPS, pkgid, CORETPK_XML);
	ret = _coretpk_installer_apply_file_policy(rootfile);
	if (ret != 0) {
		_LOGE("_coretpk_installer_apply_file_policy() failed, rootfile=[%s]", rootfile);
		return -1;
	}

	// [pkgid]/author-signature.xml
	memset(rootfile, '\0', BUF_SIZE);
	snprintf(rootfile, BUF_SIZE, "%s/%s/%s", OPT_USR_APPS, pkgid, AUTHOR_SIGNATURE_XML);
	ret = _coretpk_installer_apply_file_policy(rootfile);
	if (ret != 0) {
		_LOGE("_coretpk_installer_apply_file_policy() failed, rootfile=[%s]", rootfile);
		return -1;
	}
	memset(rootfile, '\0', BUF_SIZE);
	snprintf(rootfile, BUF_SIZE, "%s/%s/%s", USR_APPS, pkgid, AUTHOR_SIGNATURE_XML);
	ret = _coretpk_installer_apply_file_policy(rootfile);
	if (ret != 0) {
		_LOGE("_coretpk_installer_apply_file_policy() failed, rootfile=[%s]", rootfile);
		return -1;
	}

	// [pkgid]/signature1.xml
	memset(rootfile, '\0', BUF_SIZE);
	snprintf(rootfile, BUF_SIZE, "%s/%s/%s", OPT_USR_APPS, pkgid, SIGNATURE1_XML);
	ret = _coretpk_installer_apply_file_policy(rootfile);
	if (ret != 0) {
		_LOGE("_coretpk_installer_apply_file_policy() failed, rootfile=[%s]", rootfile);
		return -1;
	}
	memset(rootfile, '\0', BUF_SIZE);
	snprintf(rootfile, BUF_SIZE, "%s/%s/%s", USR_APPS, pkgid, SIGNATURE1_XML);
	ret = _coretpk_installer_apply_file_policy(rootfile);
	if (ret != 0) {
		_LOGE("_coretpk_installer_apply_file_policy() failed, rootfile=[%s]", rootfile);
		return -1;
	}

	// /opt/share/packages/[pkgid].xml
	memset(rootfile, '\0', BUF_SIZE);
	snprintf(rootfile, BUF_SIZE, "%s/%s.xml", OPT_SHARE_PACKAGES, pkgid);
	ret = _coretpk_installer_apply_file_policy(rootfile);
	if (ret != 0) {
		_LOGE("_coretpk_installer_apply_file_policy() failed, rootfile=[%s]", rootfile);
		return -1;
	}
	memset(rootfile, '\0', BUF_SIZE);
	snprintf(rootfile, BUF_SIZE, "%s/%s.xml", USR_SHARE_PACKAGES, pkgid);
	ret = _coretpk_installer_apply_file_policy(rootfile);
	if (ret != 0) {
		_LOGE("_coretpk_installer_apply_file_policy() failed, rootfile=[%s]", rootfile);
		return -1;
	}

	// for external storage
	if (_coretpk_installer_get_configuration_value(INI_VALUE_MAKE_EXT_DIRECTORY)) {
		int ret = _coretpk_installer_make_directory_for_ext(pkgid);
		if (ret != 0) {
			_LOGE("_coretpk_installer_make_directory_for_ext() failed, pkgid=[%s]", pkgid);
			return -1;
		}
	}

	return ret;
}

int _coretpk_installer_change_mode(char *path, int mode)
{
	int ret = 0;

	ret = chmod(path, mode);
	if (ret != 0) {
		_LOGL("chmod()", errno);
		return -1;
	}

	return ret;
}

int _coretpk_installer_change_file_owner(char *path, int ownerid, int groupid)
{
	int ret = 0;

	if (access(path, F_OK) == 0) {
		ret = chown(path, ownerid, groupid);
		if (ret != 0) {
			_LOGL("chown()", errno);
			return -1;
		}
	}

	return ret;
}

int _coretpk_installer_change_directory_owner(char *dirpath, int ownerid, int groupid)
{
	int ret = 0;

	if (__is_dir(dirpath)) {
		ret = chown(dirpath, ownerid, groupid);
		if (ret != 0) {
			_LOGL("chown()", errno);
			return -1;
		}
	}

	return ret;
}

void _coretpk_installer_set_privilege_setup_path_for_ext(char *pkgid, char *dirpath, app_path_type_t type, char *label)
{
	char path[BUF_SIZE] = {'\0'};

	snprintf(path, BUF_SIZE, "%s/%s", OPT_STORAGE_SDCARD_APP_ROOT, dirpath);
	if (access(path, F_OK) == 0) {
		_ri_privilege_setup_path(pkgid, path, type, label);
	}
}

void _coretpk_installer_set_privilege_setup_path(char *pkgid, char *dirpath, app_path_type_t type, char *label)
{
	char path[BUF_SIZE] = {'\0'};

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

int _coretpk_installer_get_group_id(char *pkgid, char **result)
{
	int ret = 0;
	const char *value = NULL;
	char author_signature[BUF_SIZE] = {'\0'};
	char *e_rootcert = NULL;
	char *d_rootcert = NULL;
	gsize d_size = 0;
	unsigned char hashout[BUF_SIZE] = {'\0'};
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

	/*get root certificate*/
	ret = pkgmgrinfo_pkginfo_get_cert_value(handle, PMINFO_AUTHOR_SIGNER_CERT, &value);
	if (ret < 0 || value == NULL) {
		_LOGE("failed to get cert value.");
		goto err;
	}

	/*decode cert*/
	d_rootcert = (char *)g_base64_decode(value, &d_size);
	if (d_rootcert == NULL)	{
		_LOGE("failed to execute decode.");
		goto err;
	}

	/*hash*/
	EVP_Digest(d_rootcert, d_size, hashout, &h_size, EVP_sha1(), NULL);
	if (h_size <= 0) {
		_LOGE("@Failed to get hash.");
		goto err;
	}

	/*encode cert*/
	e_rootcert = g_base64_encode((const guchar *)hashout, h_size);
	if (e_rootcert == NULL) {
		_LOGE("failed to execute encode.");
		goto err;
	}
	e_size = strlen(e_rootcert);
	_LOGD("encoding done, len=[%d]", e_size);

	/*replace / to #*/
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

	/*destroy cert*/
	if (handle) {
		pkgmgrinfo_pkginfo_destroy_certinfo(handle);
	}

	return ret;
}

int _coretpk_installer_apply_smack_for_ext(char *pkgname)
{
	int ret = 0;
	char dirpath[BUF_SIZE] = {'\0'};

	// approot
	snprintf(dirpath, BUF_SIZE, "%s", pkgname);
	_coretpk_installer_set_privilege_setup_path_for_ext(pkgname, dirpath, APP_PATH_ANY_LABEL, "_");
	memset(dirpath, '\0', BUF_SIZE);

	// [pkgid]/data
	snprintf(dirpath, BUF_SIZE, "%s/data", pkgname);
	_coretpk_installer_set_privilege_setup_path_for_ext(pkgname, dirpath, APP_PATH_PRIVATE, pkgname);
	memset(dirpath, '\0', BUF_SIZE);

	// [pkgid]/cache
	snprintf(dirpath, BUF_SIZE, "%s/cache", pkgname);
	_coretpk_installer_set_privilege_setup_path_for_ext(pkgname, dirpath, APP_PATH_PRIVATE, pkgname);
	memset(dirpath, '\0', BUF_SIZE);

	// [pkgid]/shared
	snprintf(dirpath, BUF_SIZE, "%s/shared", pkgname);
	_coretpk_installer_set_privilege_setup_path_for_ext(pkgname, dirpath, APP_PATH_ANY_LABEL, "_");
	memset(dirpath, '\0', BUF_SIZE);

	// [pkgid]/shared/data
	snprintf(dirpath, BUF_SIZE, "%s/shared/data", pkgname);
	_coretpk_installer_set_privilege_setup_path_for_ext(pkgname, dirpath, APP_PATH_PUBLIC_RO, NULL);

	return ret;
}

int _coretpk_installer_apply_smack(char *pkgname, int flag)
{
	int ret = 0;
	char dirpath[BUF_SIZE] = {'\0'};
	char manifest[BUF_SIZE] = {'\0'};
	char *groupid = NULL;
	char *shared_data_label = NULL;

	_ri_privilege_register_package(pkgname);

	// app root
	snprintf(dirpath, BUF_SIZE, "%s", pkgname);
	_coretpk_installer_set_privilege_setup_path(pkgname, dirpath, APP_PATH_ANY_LABEL, "_");
	memset(dirpath, '\0', BUF_SIZE);

	// shared
	snprintf(dirpath, BUF_SIZE, "%s/shared", pkgname);
	_coretpk_installer_set_privilege_setup_path(pkgname, dirpath, APP_PATH_ANY_LABEL, "_");
	memset(dirpath, '\0', BUF_SIZE);

	// shared/res
	snprintf(dirpath, BUF_SIZE, "%s/shared/res", pkgname);
	_coretpk_installer_set_privilege_setup_path(pkgname, dirpath, APP_PATH_ANY_LABEL, "_");
	memset(dirpath, '\0', BUF_SIZE);

	// shared/data
	snprintf(dirpath, BUF_SIZE, "%s/shared/data", pkgname);
	_coretpk_installer_set_privilege_setup_path(pkgname, dirpath, APP_PATH_PUBLIC_RO, NULL);
	memset(dirpath, '\0', BUF_SIZE);

	// shared/cache
	snprintf(dirpath, BUF_SIZE, "%s/%s/shared/data", OPT_USR_APPS, pkgname);
	ret = _coretpk_installer_get_smack_label_access(dirpath, &shared_data_label);
	if (ret == 0) {
		memset(dirpath, '\0', BUF_SIZE);
		snprintf(dirpath, BUF_SIZE, "%s/%s/shared/cache", OPT_USR_APPS, pkgname);
		ret  = _coretpk_installer_set_smack_label_access(dirpath, shared_data_label);
		if (ret != 0) {
			_LOGE("_coretpk_installer_apply_directory_policy() failed, appdir=[%s], ret=[%d]", dirpath, ret);
		}
		ret = _coretpk_installer_set_smack_label_transmute(dirpath, "1");
		if (ret != 0) {
			_LOGE("_coretpk_installer_apply_directory_policy() failed, appdir=[%s], ret=[%d]", dirpath, ret);
		}
	}

	// shared/trusted
	memset(dirpath, '\0', BUF_SIZE);
	snprintf(dirpath, BUF_SIZE, "%s/shared/trusted", pkgname);
	if (_coretpk_installer_get_configuration_value(INI_VALUE_SIGNATURE)) {
		ret = _coretpk_installer_get_group_id(pkgname, &groupid);
		if (ret == 0) {
			LOGD("groupid = [%s] for shared/trusted.", groupid);
			_coretpk_installer_set_privilege_setup_path(pkgname, dirpath, APP_PATH_GROUP_RW, groupid);
			if (groupid)
				free(groupid);
		} else {
			LOGE("_coretpk_installer_get_group_id(%s) failed.", pkgname);
			return -1;
		}
	}
	memset(dirpath, '\0', BUF_SIZE);

	// bin
	snprintf(dirpath, BUF_SIZE, "%s/bin", pkgname);
	_coretpk_installer_set_privilege_setup_path(pkgname, dirpath, APP_PATH_PRIVATE, pkgname);
	memset(dirpath, '\0', BUF_SIZE);

	// data
	snprintf(dirpath, BUF_SIZE, "%s/data", pkgname);
	_coretpk_installer_set_privilege_setup_path(pkgname, dirpath, APP_PATH_PRIVATE, pkgname);
	memset(dirpath, '\0', BUF_SIZE);

	// lib
	snprintf(dirpath, BUF_SIZE, "%s/lib", pkgname);
	_coretpk_installer_set_privilege_setup_path(pkgname, dirpath, APP_PATH_PRIVATE, pkgname);
	memset(dirpath, '\0', BUF_SIZE);

	// res
	snprintf(dirpath, BUF_SIZE, "%s/res", pkgname);
	_coretpk_installer_set_privilege_setup_path(pkgname, dirpath, APP_PATH_PRIVATE, pkgname);
	memset(dirpath, '\0', BUF_SIZE);

	// cache
	snprintf(dirpath, BUF_SIZE, "%s/cache", pkgname);
	_coretpk_installer_set_privilege_setup_path(pkgname, dirpath, APP_PATH_PRIVATE, pkgname);
	memset(dirpath, '\0', BUF_SIZE);

	// tizen-manifest.xml
	snprintf(dirpath, BUF_SIZE, "%s/%s", pkgname, CORETPK_XML);
	_coretpk_installer_set_privilege_setup_path(pkgname, dirpath, APP_PATH_PRIVATE, pkgname);
	memset(dirpath, '\0', BUF_SIZE);

	// author-signature.xml
	snprintf(dirpath, BUF_SIZE, "%s/%s", pkgname, AUTHOR_SIGNATURE_XML);
	_coretpk_installer_set_privilege_setup_path(pkgname, dirpath, APP_PATH_PRIVATE, pkgname);
	memset(dirpath, '\0', BUF_SIZE);

	// signature1.xml
	snprintf(dirpath, BUF_SIZE, "%s/%s", pkgname, SIGNATURE1_XML);
	_coretpk_installer_set_privilege_setup_path(pkgname, dirpath, APP_PATH_PRIVATE, pkgname);
	memset(dirpath, '\0', BUF_SIZE);

	// [pkgid].xml
	snprintf(manifest, BUF_SIZE, "%s/%s.xml", OPT_SHARE_PACKAGES, pkgname);
	if (access(manifest, F_OK) == 0) {
		_ri_privilege_setup_path(pkgname, manifest, APP_PATH_PRIVATE, pkgname);
	}

	// external storage
	if (_coretpk_installer_get_configuration_value(INI_VALUE_MAKE_EXT_DIRECTORY)) {
		if (access(OPT_STORAGE_SDCARD, F_OK) == 0) {
			ret = _coretpk_installer_apply_smack_for_ext(pkgname);
			if (ret != 0) {
				_LOGE("_coretpk_installer_apply_smack_for_ext(%s) failed.", pkgname);
				return -1;
			}
		}
	}

	return ret;
}

static char * __getprivilege(const char* pBuf)
{
	const char* pKey = "<privilege>";
	const char* p = NULL;
	const char* pStart = NULL;
	const char* pEnd = NULL;

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

	char *pRes = (char*)malloc(len + 1);
	if(pRes == NULL){
		_LOGE("malloc failed!!");
		return NULL;
	}
	strncpy(pRes, pStart, len);
	pRes[len] = 0;

	return pRes;
}

int _coretpk_installer_apply_privilege(char *pkgid, char *pkgPath, int apiVisibility)
{
	int ret = 0;
	FILE *fp = NULL;
	char *find_str = NULL;
	char buf[BUF_SIZE] = {0};
	char manifest[BUF_SIZE] = {'\0'};
	const char *perm[] = {NULL, NULL};
	int apptype = PERM_APP_TYPE_EFL;
	char *tmp_api_version = NULL;

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
	if (fp == NULL)	{
		_LOGE("Fail get : %s\n", manifest);
		return -1;
	}

	tmp_api_version = __find_info_from_xml(manifest, "api-version");
	if (tmp_api_version) {
		ret = _ri_privilege_set_package_version(pkgid, tmp_api_version);
		if (ret != 0) {
			_LOGE("failed to set pkg version for privilege, ret[%d]", ret);
			return -1;
		} else
			_LOGD("api-version fot privilege has done successfully.");
		free(tmp_api_version);
	} else {
		_LOGE("failed to get api version from native app manifest");
		if (fp)
			fclose(fp);
		return -1;
	}

	/*reload privilege*/
	_ri_privilege_enable_permissions(pkgid, apptype, perm, 1);

	while (fgets(buf, BUF_SIZE, fp) != NULL) {
		__str_trim(buf);

		if (strstr(buf, "<privilege>")) {
			find_str = __getprivilege(buf);
			if (find_str !=  NULL) {
				_LOGD("privilege = [%s]", find_str);
				perm[0] = find_str;

				ret = _ri_privilege_enable_permissions(pkgid, apptype, perm, 1);
				if(ret < 0) {
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

	if (fp != NULL)
		fclose(fp);

	return 0;
}

int _coretpk_installer_package_install(char *pkgfile, char *pkgid, char *clientid)
{
	int ret = 0;
	char buff[BUF_SIZE] = {'\0'};
	char manifest[BUF_SIZE] = {'\0'};
	char cwd[BUF_SIZE] = {'\0'};
	char *temp = NULL;
	char rwmanifest[BUF_SIZE] = {'\0'};
	int visibility = 0;
	pkginfo *info = NULL;

	/* for external installation */
	app2ext_handle *handle = NULL;
	GList *dir_list = NULL;
	int install_status = APP2EXT_STATUS_SUCCESS;

	/*check param*/
	if (pkgfile == NULL || pkgid == NULL) {
		_LOGE("invalid input parameter, pkgfile or pkgid is NULL.");
		return RPM_INSTALLER_ERR_WRONG_PARAM;
	}

	/*send event for start*/
	_ri_broadcast_status_notification(pkgid, "coretpk", "start", "install");
	_LOGD("[#]start : _coretpk_installer_package_install[%s]", pkgid);

	/*send event for install_percent*/
	_ri_broadcast_status_notification(pkgid, "coretpk", "install_percent", "30");

	/*If the directory which will be installed exists, remove it.*/
	snprintf(buff, BUF_SIZE, "%s/%s/", OPT_USR_APPS, pkgid);
	if (__is_dir(buff)) {
		_rpm_delete_dir(buff);
	}

	/* pre_install */
	ret = __pre_install_for_mmc(pkgid, pkgfile, &dir_list, &handle);
	if (ret < 0) {
		_LOGE("__pre_install_for_mmc is failed.");
		goto err;
	}

	const char *unzip_argv[] = { "/usr/bin/unzip", "-o", pkgfile, "-d", buff, NULL };
	ret = _ri_xsystem(unzip_argv);
	if (ret != 0) {
		_LOGE("failed to unzip for path=[%s], ret=[%d]", buff, ret);
		goto err;
	}
	_LOGD("unzip is done successfully, path=[%s]", buff);

	/*getcwd*/
	temp = getcwd(cwd, BUF_SIZE);
	if ((temp == NULL) || (cwd[0] == '\0')) {
		_LOGL("getcwd()", errno);
		ret = RPM_INSTALLER_ERR_INTERNAL;
		goto err;
	}
	_LOGD("current working directory, path=[%s]", cwd);

	/*change dir*/
	ret = chdir(buff);
	if (ret != 0) {
		_LOGL("chdir()", errno);
		ret = RPM_INSTALLER_ERR_INTERNAL;
		goto err;
	}

	/*check for signature and certificate*/
	if (_coretpk_installer_get_configuration_value(INI_VALUE_SIGNATURE)) {
		ret = _coretpk_installer_verify_signatures(buff, pkgid, &visibility);
		if (ret < 0) {
			_LOGE("failed to verify signature and certificate, pkgid=[%s].", pkgid);
			ret = RPM_INSTALLER_ERR_SIG_VERIFICATION_FAILED;
			goto err;
		}
		_LOGD("signature and certificate are verified successfully.");
	}

   /*chdir*/
	ret = chdir(cwd);
	if (ret != 0) {
		_LOGL("chdir()", errno);
		ret = RPM_INSTALLER_ERR_INTERNAL;
		goto err;
	}

	/*convert manifest and copy the file to /opt/share/packages*/
	snprintf(manifest, BUF_SIZE, "%s/%s/%s", OPT_USR_APPS, pkgid, CORETPK_XML);
	ret = _coretpk_parser_convert_manifest(manifest, pkgid, clientid, false, visibility, NULL);
	if (ret != 0) {
		_LOGE("failed to convert the manifest.");
		ret = RPM_INSTALLER_ERR_INVALID_MANIFEST;
		goto err;
	}
	_LOGD("manifest is converted successfully.");

	if (strstr(pkgfile, ".wgt") != NULL) {
		_LOGD("wgt file=[%s]", pkgfile);

		if (strstr(manifest, OPT_USR_APPS)) {
				snprintf(rwmanifest, BUF_SIZE, "%s/%s.xml", OPT_SHARE_PACKAGES, pkgid);
				const char *rw_xml_category[] = { CORETPK_CATEGORY_CONVERTER, rwmanifest, NULL };
				ret = _ri_xsystem(rw_xml_category);
		}
	}

	/*check the manifest file.*/
	memset(manifest, '\0', sizeof(manifest));
	snprintf(manifest, BUF_SIZE, "%s/%s.xml", OPT_SHARE_PACKAGES, pkgid);
	/*compare manifest.xml with schema file(/usr/etc/package-manager/preload/manifest.xsd)*/
	ret = pkgmgr_parser_check_manifest_validation(manifest);
	if(ret < 0) {
		_LOGE("invalid manifest file");
		ret = RPM_INSTALLER_ERR_INVALID_MANIFEST;
		goto err;
	}

	/*Parse the manifest to get install location and size. If installation fails, remove manifest info from DB*/
	ret = pkgmgr_parser_parse_manifest_for_installation(manifest, NULL);
	if (ret < 0) {
		_LOGE("failed to parse the manifest.");
		ret = RPM_INSTALLER_ERR_INTERNAL;
		goto err;
	}
	_LOGD("manifest parsing done successfully.");

	/*search_ug_app*/
	_coretpk_installer_search_ui_gadget(pkgid);

	/*send event for install_percent*/
	_ri_broadcast_status_notification(pkgid, "coretpk", "install_percent", "60");

	/*register cert info*/
	_ri_register_cert(pkgid);

	/*make directory*/
	ret = _coretpk_installer_make_directory(pkgid);
	if (ret != 0) {
		_LOGE("failed to make the directory.");
		goto err;
	}

	/*apply smack to app dir*/
	ret = _coretpk_installer_apply_smack(pkgid, 1);
	if (ret != 0) {
		_LOGE("failed to apply the smack.");
		goto err;
	}

	info = _coretpk_installer_get_pkgfile_info(pkgfile);
	if (info == NULL || (strlen(info->package_name) == 0)) {
		_LOGE("failed to get pkg info");
		ret = RPM_INSTALLER_ERR_INTERNAL;
		goto err;
	}

	if (strlen(info->api_version) != 0) {
		ret = _ri_privilege_set_package_version(pkgid, info->api_version);
		if (ret != 0)
			_LOGE("failed to set pkg version for privilege, ret[%d]", ret);
		else
			_LOGD("api-version fot privilege has done successfully.");
	} else {
		_LOGD("failed to retrieve api_version of package");
	}

	/*apply smack by privilege*/
	ret = _ri_apply_privilege(pkgid, visibility);
	if (ret != 0) {
		_LOGE("failed to apply permission, ret=[%d]", ret);
	}
	_LOGD("permission applying done successfully.");

	// Check privilege and visibility
	if (privilege_list) {
		ret = _coretpk_installer_verify_privilege_list(privilege_list, visibility, info->api_version);
		if (ret != 0) {
			goto err;
		} else {
			_LOGD("_coretpk_installer_verify_privilege_list done.");
		}
	}

#if 0
	/*reload smack*/
	ret = _ri_smack_reload(pkgid, REQUEST_TYPE_INSTALL);
	if (ret != 0) {
		_LOGD("failed to reload the smack.");
	}
#endif

	/*send event for install_percent*/
	_ri_broadcast_status_notification(pkgid, "coretpk", "install_percent", "100");

	ret = RPM_INSTALLER_SUCCESS;

err:
	/* post_install */
	if (ret != 0) {
		install_status = APP2EXT_STATUS_FAILED;
	}
	_LOGD("install status is [%d].", install_status);
	if (__post_install_for_mmc(handle, pkgid, dir_list, install_status)  < 0) {
		_LOGE("__post_install_for_mmc is failed.");
		ret = -1;
	}

	if (info != NULL) {
		free(info);
		info = NULL;
	}

	if (ret == 0) {
		_LOGD("_coretpk_installer_package_install is done.");
		_ri_broadcast_status_notification(pkgid, "coretpk", "end", "ok");
	} else {
		/*remove db info*/
		if (_coretpk_installer_remove_db_info(pkgid) < 0) {
			_LOGE("_coretpk_installer_remove_db_info is failed.");
		}

		/*remove xml(/opt/share/packages/pkgid.xml)*/
		if (access(manifest, F_OK) == 0) {
			(void)remove(manifest);
		}

		/*remove app dir(/opt/usr/apps/pkgid)*/
		snprintf(buff, BUF_SIZE, "%s/%s/", OPT_USR_APPS, pkgid);
		if (__is_dir(buff)) {
			_rpm_delete_dir(buff);
		}

		/*remove ext app dir(/opt/storage/sdcard/apps/pkgid)*/
		if (_coretpk_installer_get_configuration_value(INI_VALUE_MAKE_EXT_DIRECTORY)) {
			char extpath[BUF_SIZE] = {'\0'};
			snprintf(extpath, BUF_SIZE, "%s/%s", OPT_STORAGE_SDCARD_APP_ROOT, pkgid);
			if (__is_dir(extpath)) {
				_rpm_delete_dir(extpath);
			}
		}

		char *errorstr = NULL;
		_ri_error_no_to_string(ret, &errorstr);
		_ri_broadcast_status_notification(pkgid, "coretpk", "error", errorstr);
		sleep(2);

		_LOGE("_coretpk_installer_package_install is failed.");
		_ri_broadcast_status_notification(pkgid, "coretpk", "end", "fail");
	}

	return ret;
}

int _coretpk_installer_package_uninstall(const char *pkgid)
{
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

int _coretpk_installer_package_upgrade(char *pkgfile, char *pkgid, char *clientid)
{
	int ret = 0;
	char buff[BUF_SIZE] = {'\0'};
	char manifest[BUF_SIZE] = { '\0'};
	char cwd[BUF_SIZE] = {'\0'};
	char rwmanifest[BUF_SIZE] = {'\0'};
	pkgmgrinfo_pkginfo_h pkghandle = NULL;
	char *temp = NULL;
	int visibility = 0;
	pkginfo *info = NULL;

	/* for external upgrade */
	app2ext_handle *handle = NULL;
	GList *dir_list = NULL;

	/*check param*/
	if (pkgfile == NULL || pkgid == NULL) {
		_LOGE("invalid input parameter, pkgfile or pkgid is NULL.");
		return RPM_INSTALLER_ERR_WRONG_PARAM;
	}

	/*send event for start*/
	_ri_broadcast_status_notification(pkgid, "coretpk", "start", "update");

	/*terminate running app*/
	ret = pkgmgrinfo_pkginfo_get_pkginfo(pkgid, &pkghandle);
	if (ret < 0) {
		_LOGE("failed to get the pkginfo handle.");
		ret = RPM_INSTALLER_ERR_PKG_NOT_FOUND;
		goto err;
	}
	pkgmgrinfo_appinfo_get_list(pkghandle, PMINFO_UI_APP, __ri_check_running_app, NULL);
	pkgmgrinfo_pkginfo_destroy_pkginfo(pkghandle);

    /*remove dir for clean*/
	__ri_remove_updated_dir(pkgid);

	/* pre_upgrade */
	ret = __pre_upgrade_for_mmc(pkgid, pkgfile, &dir_list, &handle);
	if (ret < 0) {
		_LOGE("__pre_upgrade_for_mmc is failed.");
		goto err;
	}

	snprintf(buff, BUF_SIZE, "%s/%s/", OPT_USR_APPS, pkgid);
	const char *unzip_argv[] = { "/usr/bin/unzip", "-o", pkgfile, "-d", buff, NULL };
	ret = _ri_xsystem(unzip_argv);
	if (ret != 0) {
		_LOGE("failed to unzip for [%s, %d].", buff, ret);
		goto err;
	}
	_LOGD("#unzip[%s] success.", buff);

	/*send event for install_percent*/
	_ri_broadcast_status_notification(pkgid, "coretpk", "install_percent", "30");

	/*getcwd*/
	temp = getcwd(cwd, BUF_SIZE);
	if ((temp == NULL) || (cwd[0] == '\0')) {
		_LOGL("getcwd()", errno);
		ret = RPM_INSTALLER_ERR_INTERNAL;
		goto err;
	}
	_LOGD("#Current working directory is %s.", cwd);

	/*change dir*/
	ret = chdir(buff);
	if (ret != 0) {
		_LOGL("chdir()", errno);
		ret = RPM_INSTALLER_ERR_INTERNAL;
		goto err;
	}

	/*check for signature and certificate*/
	if (_coretpk_installer_get_configuration_value(INI_VALUE_SIGNATURE)) {
		ret = _coretpk_installer_verify_signatures(buff, pkgid, &visibility);
		if (ret < 0) {
			_LOGE("@Failed to verify signature and certificate[%s].", pkgid);
			ret = RPM_INSTALLER_ERR_SIG_VERIFICATION_FAILED;
			goto err;
		}
		_LOGD("#signature and certificate verifying success");
	}

   /*chdir*/
	ret = chdir(cwd);
	if (ret != 0) {
		_LOGL("chdir()", errno);
		ret = RPM_INSTALLER_ERR_INTERNAL;
		goto err;
	}

	/*convert manifest and copy the file to /opt/share/packages*/
	snprintf(manifest, BUF_SIZE, "%s/%s/%s", OPT_USR_APPS, pkgid, CORETPK_XML);
	ret = _coretpk_parser_convert_manifest(manifest, pkgid, clientid, false, visibility, NULL);
	if (ret != 0) {
		_LOGE("@Failed to convert the manifest.");
		ret = RPM_INSTALLER_ERR_INVALID_MANIFEST;
		goto err;
	}
	_LOGD("#manifest converting success");

	if (strstr(pkgfile, ".wgt") != NULL) {
		_LOGD("wgt file = [%s]", pkgfile);

		if (strstr(manifest, OPT_USR_APPS)) {
				snprintf(rwmanifest, BUF_SIZE, "%s/%s.xml", OPT_SHARE_PACKAGES, pkgid);
				const char *rw_xml_category[] = { CORETPK_CATEGORY_CONVERTER, rwmanifest, NULL };
				ret = _ri_xsystem(rw_xml_category);
		}
	}

	/*check the manifest file.*/
	memset(manifest, '\0', sizeof(manifest));
	snprintf(manifest, BUF_SIZE, "%s/%s.xml", OPT_SHARE_PACKAGES, pkgid);
	/*compare manifest.xml with schema file(/usr/etc/package-manager/preload/manifest.xsd)*/
	ret = pkgmgr_parser_check_manifest_validation(manifest);
	if(ret < 0) {
		_LOGE("@invalid manifest file");
		ret = RPM_INSTALLER_ERR_INVALID_MANIFEST;
		goto err;
	}

	/*send event for install_percent*/
	_ri_broadcast_status_notification(pkgid, "coretpk", "install_percent", "60");

	/*Parse the manifest to get install location and size. If fails, remove manifest info from DB.*/
	ret = pkgmgr_parser_parse_manifest_for_upgrade(manifest, NULL);
	if (ret < 0) {
		_LOGE("@parsing manifest failed.");
		ret = RPM_INSTALLER_ERR_INTERNAL;
		goto err;
	}
	_LOGD("#parsing manifest success.");

	/*search_ug_app*/
	_coretpk_installer_search_ui_gadget(pkgid);

	/*unregister cert info*/
	_ri_unregister_cert(pkgid);

	/*register cert info*/
	_ri_register_cert(pkgid);

	/*make directory*/
	ret = _coretpk_installer_make_directory(pkgid);
	if (ret != 0) {
		_LOGE("@Failed to make the directory");
		goto err;
	}

	// Remove origin rule
	_ri_privilege_unregister_package(pkgid);

	/*apply smack to app dir*/
	ret = _coretpk_installer_apply_smack(pkgid, 1);
	if (ret != 0) {
		_LOGE("@Failed to apply the smack.");
		goto err;
	}

	/*apply smack by privilege*/
	ret = _ri_apply_privilege(pkgid, visibility);
	if (ret != 0) {
		_LOGE("@Failed to apply permission[%d].", ret);
	}
	_LOGD("#permission applying success.");

	info = _coretpk_installer_get_pkgfile_info(pkgfile);
	if (info == NULL || strlen(info->package_name) == 0) {
		_LOGE("failed to get pkg info");
		ret = RPM_INSTALLER_ERR_INTERNAL;
		goto err;
	}

	// Check privilege and visibility
	if (privilege_list) {
		ret = _coretpk_installer_verify_privilege_list(privilege_list, visibility, info->api_version);
		if (ret != 0) {
			goto err;
		} else {
			_LOGD("_coretpk_installer_verify_privilege_list(PRVMGR_PACKAGE_TYPE_CORE) is ok.");
		}
	}

#if 0
	/*reload smack*/
	ret = _ri_smack_reload(pkgid, REQUEST_TYPE_UPGRADE);
	if (ret != 0) {
		_LOGE("@Failed to reload the smack.");
	}
#endif

	/*send event for install_percent*/
	_ri_broadcast_status_notification(pkgid, "coretpk", "install_percent", "100");
	ret = RPM_INSTALLER_SUCCESS;

err:
	/* post_upgrade */
	if (__post_upgrade_for_mmc(handle, pkgid, dir_list) < 0) {
		_LOGE("__post_upgrade_for_mmc is failed.");
		ret = -1;
	}

	if (info != NULL) {
		free(info);
		info = NULL;
	}

	if (ret == 0) {
		_LOGD("[#]end : _coretpk_installer_package_upgrade");
		_ri_broadcast_status_notification(pkgid, "coretpk", "end", "ok");
	} else {

		/*TODO:need to add recovery logic*/

		char *errorstr = NULL;
		_ri_error_no_to_string(ret, &errorstr);
		_ri_broadcast_status_notification(pkgid, "coretpk", "error", errorstr);
		sleep(2);

		_LOGE("[@]end : _coretpk_installer_package_upgrade");
		_ri_broadcast_status_notification(pkgid, "coretpk", "end", "fail");
	}

	return ret;
}

char* _coretpk_installer_get_pkgid_from_directory_path(char *dirpath)
{
	char* subpath = strrchr(dirpath, '/');
	return subpath + 1;
}

int _coretpk_installer_directory_install(char *dirpath, char *clientid)
{
	int ret = 0;
	char manifest[BUF_SIZE] = {'\0'};
	char cwd[BUF_SIZE] = {'\0'};
	char *temp = NULL;
	char *pkgid = NULL;
	int visibility = 0;

	// check param
	if (dirpath == NULL) {
		_LOGE("dirpath is NULL.");
		return RPM_INSTALLER_ERR_WRONG_PARAM;
	}

	_LOGD("directory_install start: dirpath = [%s]", dirpath);

	// getcwd
	temp = getcwd(cwd, BUF_SIZE);
	if ((temp == NULL) || (cwd[0] == '\0')) {
		_LOGE("getcwd() failed. [%d][%s]", errno, strerror(errno));
		ret = RPM_INSTALLER_ERR_INTERNAL;
		goto err;
	}

	_LOGD("Current working directory is [%s].", cwd);

	// change dir
	ret = chdir(dirpath);
	if (ret != 0) {
		_LOGE("chdir(%s) failed. [%d][%s]", dirpath, errno, strerror(errno));
		ret = RPM_INSTALLER_ERR_INTERNAL;
		goto err;
	}

	// check for signature and certificate
	if (_coretpk_installer_get_configuration_value(INI_VALUE_SIGNATURE)) {
		pkgid = _coretpk_installer_get_pkgid_from_directory_path(dirpath);
		_LOGD("pkgid=[%s]", pkgid);

		ret = _coretpk_installer_verify_signatures(dirpath, pkgid, &visibility);
		if (ret < 0) {
			_LOGE("_coretpk_installer_verify_signatures(%s, %s) failed.", dirpath, pkgid);
			ret = RPM_INSTALLER_ERR_SIG_VERIFICATION_FAILED;
			goto err;
		}
		_LOGD("verify_signatures(%s, %s) succeed!", dirpath, pkgid);
	}

  // chdir
	ret = chdir(cwd);
	if (ret != 0) {
		_LOGE("chdir(%s) failed. [%d][%s]", cwd, errno, strerror(errno));
		ret = RPM_INSTALLER_ERR_INTERNAL;
		goto err;
	}

	// convert manifest and copy the file to /usr/share/packages
	snprintf(manifest, BUF_SIZE, "%s/%s", dirpath, CORETPK_XML);
	if (pkgid == NULL) {
		pkgid = _coretpk_installer_get_pkgid_from_directory_path(dirpath);
		_LOGD("pkgid = [%s]", pkgid);
	}

	ret = _coretpk_parser_convert_manifest(manifest, pkgid, clientid, false, visibility, NULL);
	if (ret != 0) {
		_LOGE("_coretpk_parser_convert_manifest() failed. manifest = [%s], pkgid = [%s]", manifest, pkgid);
		ret = RPM_INSTALLER_ERR_INVALID_MANIFEST;
		goto err;
	}
	_LOGD("convert_manifest(%s, %s) succeed!", manifest, pkgid);

	// check the manifest file
	memset(manifest, '\0', sizeof(manifest));
	if (strstr(dirpath, OPT_USR_APPS)) {
		snprintf(manifest, BUF_SIZE, "%s/%s.xml", OPT_SHARE_PACKAGES, pkgid);
	} else {
		snprintf(manifest, BUF_SIZE, "%s/%s.xml", USR_SHARE_PACKAGES, pkgid);
	}
	_LOGD("manifest = [%s]", manifest);

	// compare manifest.xml with schema file(/usr/etc/package-manager/preload/manifest.xsd)
	ret = pkgmgr_parser_check_manifest_validation(manifest);
	if(ret < 0) {
		_LOGE("pkgmgr_parser_check_manifest_validation(%s) failed.", manifest);
		ret = RPM_INSTALLER_ERR_INVALID_MANIFEST;
		goto err;
	}

	// Parse the manifest to get install location and size. If installation fails, remove manifest info from DB
	ret = pkgmgr_parser_parse_manifest_for_installation(manifest, NULL);
	if (ret < 0) {
		_LOGE("pkgmgr_parser_parse_manifest_for_installation(%s) failed.", manifest);
		ret = RPM_INSTALLER_ERR_INTERNAL;
		goto err;
	}
	_LOGD("parse_manifest(%s) succeed!", manifest);

	// register cert info
	_ri_register_cert(pkgid);

	// make directory
	ret = _coretpk_installer_make_directory(pkgid);
	if (ret != 0) {
		_LOGE("_coretpk_installer_make_directory(%s) failed.", pkgid);
		goto err;
	}
	_LOGD("make_directory(%s) succeed!", pkgid);

	// apply smack to app dir
	ret = _coretpk_installer_apply_smack(pkgid, 1);
	if (ret != 0) {
		_LOGE("_coretpk_installer_apply_smack(%s) failed.", pkgid);
	}
	_LOGD("apply_smack(%s) succeed!", pkgid);

	// apply smack by privilege
	ret = _ri_apply_privilege(pkgid, visibility);
	if (ret != 0) {
		_LOGE("_ri_apply_privilege(%s, %d) failed. ret = [%d]", pkgid, visibility, ret);
	}
	_LOGD("apply_privilege(%s, %d) succeed!", pkgid, visibility);

	ret = RPM_INSTALLER_SUCCESS;

err:
	_LOGD("directory_install end: dirpath = [%s], ret = [%d]", dirpath, ret);

	return ret;
}

int _coretpk_installer_prepare_package_install(char *pkgfile, char *clientid)
{
	int ret = 0;
	pkginfo *info = NULL;
	pkginfo *dbinfo = NULL;
	char *pkgid = NULL;

	_LOGD("start");

	info = _coretpk_installer_get_pkgfile_info(pkgfile);
	if (info == NULL || (strlen(info->package_name) == 0)) {
		_LOGE("failed to get the pkg info.");
		ret = RPM_INSTALLER_ERR_INTERNAL;
		goto err;
	}

	pkgid = strdup(info->package_name);
	if (pkgid == NULL) {
		_LOGE("strdup() failed.");
		ret = RPM_INSTALLER_ERR_INTERNAL;
		goto err;
	}

	dbinfo = _rpm_installer_get_pkgname_info(info->package_name);

	if (dbinfo == NULL) {
		/*package is not installed. Go for installation.*/
		_LOGD("start to install");
		ret = _coretpk_installer_package_install(pkgfile, pkgid, clientid);
	} else if (strcmp(info->version, dbinfo->version) > 0) {
		/*upgrade */
		_LOGD("start to upgrade");
		ret = _coretpk_installer_package_upgrade(pkgfile, info->package_name, clientid);
	} else if (strcmp(info->version, dbinfo->version) < 0) {
		/*downgrade*/
		_LOGD("start to downgrade");
		ret = _coretpk_installer_package_upgrade(pkgfile, info->package_name, clientid);
	} else {
		/*same package. Reinstall it. Manifest should be parsed again */
		_LOGD("start to reinstall");
		ret = _coretpk_installer_package_upgrade(pkgfile, info->package_name, clientid);
	}

	if (ret != 0) {
		_LOGE("result=[%d]", ret);
	} else {
		_LOGD("success");
	}

	if (info) {
		free(info);
		info = NULL;
	}
	if (dbinfo) {
		free(dbinfo);
		dbinfo = NULL;
	}

	if (pkgid) {
		free(pkgid);
		pkgid = NULL;
	}

	return ret;

err:
	if (info) {
		free(info);
		info = NULL;
	}

	_ri_broadcast_status_notification("Invalid package", "invalid", "start", "install");
	_ri_broadcast_status_notification("Invalid package", "invalid", "end", "fail");

	return ret;
}

int _coretpk_installer_prepare_package_uninstall(const char *pkgid)
{
	if (pkgid == NULL) {
		_LOGE("pkgid is NULL.");
		return RPM_INSTALLER_ERR_WRONG_PARAM;
	}

	_LOGD("pkgid=[%s]", pkgid);

	int ret = 0;
	pkginfo *dbinfo = NULL;

	dbinfo = _rpm_installer_get_pkgname_info(pkgid);
	if (dbinfo == NULL) {
		_LOGE("[%s] is not installed.", pkgid);
		return RPM_INSTALLER_ERR_PACKAGE_NOT_INSTALLED;
	}

	ret = _coretpk_installer_package_uninstall(pkgid);
	if (ret != 0) {
		_LOGE("_coretpk_installer_package_uninstall() failed, pkgid=[%s], ret=[%d]", pkgid, ret);
	} else {
		_LOGD("_coretpk_installer_package_uninstall() is done successfully, pkgid=[%s]", pkgid);
	}

	if (dbinfo) {
		free(dbinfo);
		dbinfo = NULL;
	}

	return ret;
}

int _coretpk_installer_prepare_directory_install(char *dirpath, char *clientid)
{
	int ret = 0;

	ret = _coretpk_installer_directory_install(dirpath, clientid);
	_LOGD("path=[%s], result=[%d]", dirpath, ret);

	return ret;
}

int _coretpk_installer_package_move(char* pkgid, int move_type)
{
	app2ext_handle *hdl = NULL;
	int ret = 0;
	int movetype = -1;
	GList *dir_list = NULL;
	pkgmgrinfo_pkginfo_h pkghandle = NULL;

	_ri_broadcast_status_notification(pkgid, "coretpk", "start", "move");
	_LOGD("[#]start : _coretpk_installer_package_move[%s][%d]", pkgid, move_type);

	if (move_type == PM_MOVE_TO_INTERNAL) {
		movetype = APP2EXT_MOVE_TO_PHONE;
	} else if (move_type == PM_MOVE_TO_SDCARD) {
		movetype = APP2EXT_MOVE_TO_EXT;
	} else {
		ret = RPM_INSTALLER_ERR_WRONG_PARAM;
		goto err;
	}

	ret = pkgmgrinfo_pkginfo_get_pkginfo(pkgid, &pkghandle);
	if (ret < 0) {
		_LOGE("@Failed to get the pkginfo handle.");
		ret = RPM_INSTALLER_ERR_PKG_NOT_FOUND;
		goto err;
	}

	/* Terminate the running instance of app */
	pkgmgrinfo_appinfo_get_list(pkghandle, PM_UI_APP, __ri_check_running_app, NULL);
	pkgmgrinfo_pkginfo_destroy_pkginfo(pkghandle);

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
		_LOGD("[#]end : _coretpk_installer_package_move");
		_ri_broadcast_status_notification(pkgid, "coretpk", "end", "ok");
	} else {
		_LOGE("[@]end : _coretpk_installer_package_move");
		_ri_broadcast_status_notification(pkgid, "coretpk", "end", "fail");
	}

	return ret;
}

int _coretpk_installer_copy_file( const char *src_path, const char *dst_path)
{
	int ret = 0;
	FILE *src, *dst;
	int rc = 0;
	unsigned char temp_buf[8192] = {'\0',};
	size_t size_of_uchar = sizeof(unsigned char);
	size_t size_of_temp_buf = sizeof(temp_buf);

    src = fopen(src_path, "r");
    if (src == NULL) {
		_LOGE("@Failed to open(). path=%s, E:%d(%s)", src_path, errno, strerror(errno));
        return  -1;
    }

    dst = fopen(dst_path, "w");
    if (dst == NULL) {
    	/*No such file or directory*/
    	if (errno == ENOENT) {
    		/*make the path of parent dir for the data*/
			char *path = strdup(dst_path);
			if (!path) {
				_LOGE("Memory allocation failed");
				goto err;
			}
			char *p = strrchr(path, '/');
			if (p) {
				p++;
			} else {
				ret = -1;
				free(path);
				goto err;
			}
			int idx = strlen(path) - strlen(p);
			path[idx] = '\0';

			/*make the parent dir*/
			const char *mkdir_argv[] = { "/bin/mkdir", "-p", path, NULL };
			ret = _ri_xsystem(mkdir_argv);
			if (ret != 0) {
				_LOGE("Failed to make parent dir.");
			}

			_LOGD("#[%s] is created.", path);
			free(path);

			/*open the file*/
			dst = fopen(dst_path, "w");
			if (dst == NULL) {
				_LOGE("Failed to open dst file. file=%s, E:%d(%s)", dst_path, errno, strerror(errno));
				ret = -1;
				goto err;
			}
    	} else {
			_LOGE("Failed to open dst file. file=%s, E:%d(%s)", dst_path, errno, strerror(errno));
			ret = -1;
			goto err;
    	}
    }

    while (!feof(src)) {
        rc = fread( temp_buf, size_of_uchar, size_of_temp_buf, src);
        fwrite( temp_buf, size_of_uchar, rc, dst);
    }

 err:
 	 if (src) {
 		 fclose(src);
 	 }
 	 if (dst) {
 		 fclose(dst);
 	 }

    return  ret;
}

int _coretpk_installer_handle_rds_data(char *pkgid, GList *delete, GList *add, GList *modify, int *updatexml)
{
	int ret = 0;
	GList *list = NULL;
	char handledata[BUF_SIZE] = {'\0'};
	char srcfile[BUF_SIZE] = {'\0'};
	char destfile[BUF_SIZE] = {'\0'};

	/*delete*/
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

	/*add*/
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
		   			ret =_coretpk_installer_copy_file(srcfile, destfile);
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

	/*modify*/
	if (modify != NULL) {
		list = g_list_first(modify);
		while (list) {
			char *data = (char *)list->data;
			if (!strcasestr(data, RDS_DELTA_MODIFY)) {
				/*If XML is modified, the checking codes for xml has to be executed.*/
				if (strcmp(data, CORETPK_XML) == 0) {
					*updatexml = 1;
				}

				snprintf(srcfile, BUF_SIZE, "%s/tmp/%s/%s", OPT_USR_APPS, pkgid, data);
				snprintf(destfile, BUF_SIZE, "%s/%s/%s", OPT_USR_APPS, pkgid, data);

				ret =_coretpk_installer_copy_file(srcfile, destfile);
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

int _coretpk_installer_read_rds_file(char *pkgid, char *rdsfile, int *updatexml)
{
	int ret = 0;
	int state = RDS_STATE_NONE;

	char buffer[BUF_SIZE] = {'\0'};
	FILE *fi = NULL;

	GList *delete_list = NULL;
	GList *add_list = NULL;
	GList *modify_list = NULL;

	if (access(rdsfile, F_OK) != 0) {
		_LOGL("access()", errno);
		return -1;
	}

	fi = fopen(rdsfile, "r");
	if (fi == NULL) {
		_LOGL("fopen()", errno);
		return -1;
	}

	while (fgets(buffer, BUF_SIZE, fi) != NULL) {
		buffer[strlen(buffer) - 1] = '\0';

		/*check rds state*/
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

		/*make rds data list*/
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

	ret = _coretpk_installer_handle_rds_data(pkgid, delete_list, add_list, modify_list, updatexml);
	if (ret != 0) {
		_LOGE("@Failed to handle rds data.");
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

int _coretpk_installer_package_reinstall(char *pkgid, char *clientid)
{
	int ret = 0;
	char manifest[BUF_SIZE] = {'\0'};
	char rdsfile[BUF_SIZE] = {'\0'};
	char dirpath[BUF_SIZE] = {'\0'};
	char cwd[BUF_SIZE] = {'\0'};
	char *temp = NULL;
	int updatexml = 0;
	int visibility = 0;
	pkginfo *info = NULL;

	/*check param*/
	if (pkgid == NULL) {
		_LOGE("@The input param[pkgid] is NULL.");
		return RPM_INSTALLER_ERR_WRONG_PARAM;
	}

	pkgmgr_installer_send_signal(pi, "coretpk", pkgid, "start", "update");
	_LOGD("[#]start : _coretpk_installer_package_reinstall[%s]", pkgid);

	snprintf(rdsfile, BUF_SIZE, "%s/tmp/%s/%s", OPT_USR_APPS, pkgid, RDS_DELTA_FILE);
	ret = _coretpk_installer_read_rds_file(pkgid, rdsfile, &updatexml);
	if (ret != 0) {
		_LOGE("@Failed to read the rds file.");
		ret = RPM_INSTALLER_ERR_INTERNAL;
		goto err;
	}
	_LOGD("#RDS file reading success");

	pkgmgr_installer_send_signal(pi, "coretpk", pkgid, "install_percent", "30");

	/*getcwd*/
	temp = getcwd(cwd, BUF_SIZE);
	if ((temp == NULL) || (cwd[0] == '\0')) {
		_LOGL("getcwd()", errno);
		ret = RPM_INSTALLER_ERR_INTERNAL;
		goto err;
	}
	_LOGD("#Current working directory is %s.", cwd);

	/*change dir*/
	snprintf(dirpath, BUF_SIZE, "%s/%s", OPT_USR_APPS, pkgid);
	ret = chdir(dirpath);
	if (ret != 0) {
		_LOGL("chdir()", errno);
		ret = RPM_INSTALLER_ERR_INTERNAL;
		goto err;
	}

	/*check for signature and certificate*/
	if (_coretpk_installer_get_configuration_value(INI_VALUE_SIGNATURE)) {

		pkgid = _coretpk_installer_get_pkgid_from_directory_path(dirpath);
		_LOGD("pkgid[%s]", pkgid);

		ret = _coretpk_installer_verify_signatures(dirpath, pkgid, &visibility);
		if (ret < 0) {
			_LOGE("failed to verify signature and certificate, pkgid=[%s].", pkgid);
			ret = RPM_INSTALLER_ERR_SIG_VERIFICATION_FAILED;
			goto err;
		}
		_LOGD("signature and certificate verifying success");
	}

   /*chdir*/
	ret = chdir(cwd);
	if (ret != 0) {
		_LOGL("chdir()", errno);
		ret = RPM_INSTALLER_ERR_INTERNAL;
		goto err;
	}

	if (updatexml) {
		/*convert manifest and copy the file to /opt/share/packages*/
		snprintf(manifest, BUF_SIZE, "%s/%s", dirpath, CORETPK_XML);
		if (pkgid == NULL) {
			pkgid = _coretpk_installer_get_pkgid_from_directory_path(dirpath);
			_LOGD("pkgid[%s]", pkgid);
		}
		ret = _coretpk_parser_convert_manifest(manifest, pkgid, clientid, false, visibility, NULL);
		if (ret != 0) {
			_LOGE("@Failed to convert the manifest.");
			ret = RPM_INSTALLER_ERR_INVALID_MANIFEST;
			goto err;
		}
		_LOGD("#manifest converting success");

		/*check the manifest file.*/
		memset(manifest, '\0', sizeof(manifest));
		snprintf(manifest, BUF_SIZE, "%s/%s.xml", OPT_SHARE_PACKAGES, pkgid);
		/*compare manifest.xml with schema file(/usr/etc/package-manager/preload/manifest.xsd)*/
		ret = pkgmgr_parser_check_manifest_validation(manifest);
		if(ret < 0) {
			_LOGE("@invalid manifest file");
			ret = RPM_INSTALLER_ERR_INVALID_MANIFEST;
			goto err;
		}

		/*Parse the manifest to get install location and size. If failed, remove manifest info from DB.*/
		ret = pkgmgr_parser_parse_manifest_for_upgrade(manifest, NULL);
		if (ret < 0) {
			_LOGE("@Failed to parse the manifest.");
			ret = RPM_INSTALLER_ERR_INTERNAL;
			goto err;
		}
		_LOGD("#manifest parsing success");
	}

	pkgmgr_installer_send_signal(pi, "coretpk", pkgid, "install_percent", "60");

	/*register cert info*/
	_ri_register_cert(pkgid);

	/*make directory*/
	ret = _coretpk_installer_make_directory(pkgid);
	if (ret != 0) {
		_LOGE("@Failed to make directory");
		goto err;
	}

	_ri_privilege_unregister_package(pkgid);

	/*apply smack to app dir*/
	ret = _coretpk_installer_apply_smack(pkgid, 1);
	if (ret != 0) {
		_LOGE("@Failed to apply smack.");
		goto err;
	}

	/*apply smack by privilege*/
	ret = _ri_apply_privilege(pkgid, visibility);
	if (ret != 0) {
		_LOGE("@Failed to apply permission[%d].", ret);
	}
	_LOGD("#permission applying success.");

	info = _coretpk_installer_get_pkg_info(manifest);
	if (info == NULL || strlen(info->package_name) == 0) {
		_LOGE("failed to get pkg info");
		ret = RPM_INSTALLER_ERR_INTERNAL;
		goto err;
	}

	// Check privilege and visibility
	if (privilege_list) {
		ret = _coretpk_installer_verify_privilege_list(privilege_list, visibility, info->api_version);
		if (ret != 0) {
			goto err;
		} else {
			_LOGD("_coretpk_installer_verify_privilege_list(PRVMGR_PACKAGE_TYPE_CORE) is ok.");
		}
	}

#if 0
	/*reload smack*/
	ret = _ri_smack_reload(pkgid, REQUEST_TYPE_UPGRADE);
	if (ret != 0) {
		_LOGE("@Failed to reload the smack.");
	}
#endif

	pkgmgr_installer_send_signal(pi, "coretpk", pkgid, "install_percent", "100");
	ret = RPM_INSTALLER_SUCCESS;

err:

	if (info != NULL) {
		free(info);
		info = NULL;
	}

	if (ret == 0) {
		_LOGD("[#]end : _coretpk_installer_package_reinstall");
		pkgmgr_installer_send_signal(pi, "coretpk", pkgid, "end", "ok");
	} else {
		/*remove db info*/
		ret = _coretpk_installer_remove_db_info(pkgid);
		if (ret < 0) {
			_LOGE("_coretpk_installer_remove_db_info is failed.");
		}

		/*remove xml(/opt/share/packages/pkgid.xml)*/
		if (access(manifest, F_OK) == 0) {
			(void)remove(manifest);
		}

		/*remove app dir(/opt/usr/apps/pkgid)*/
		if (__is_dir(dirpath)) {
			_rpm_delete_dir(dirpath);
		}

		_LOGE("[@]end : _coretpk_installer_package_reinstall");
		pkgmgr_installer_send_signal(pi, "coretpk", pkgid, "end", "fail");
	}

	return ret;
}

int _coretpk_installer_csc_install(char *path_str, char *remove_str)
{
	int ret = 0;
	pkginfo *info = NULL;
	char buff[BUF_SIZE] = {'\0'};
	char manifest[BUF_SIZE] = {'\0'};
	char cwd[BUF_SIZE] = {'\0'};
	char *temp = NULL;
	char *csc_tags[3] = {NULL, };
	int visibility = 0;

	/*check param*/
	if (path_str == NULL || remove_str == NULL) {
		_LOGE("@The input param[pkgfile or pkgid] is NULL.");
		return RPM_INSTALLER_ERR_WRONG_PARAM;
	}

	_LOGD("[##]csc-core : start csc_install[path=%s]", path_str);

	info = _coretpk_installer_get_pkgfile_info(path_str);
	if (info == NULL || (strlen(info->package_name) == 0)) {
		_LOGE("[@@]end : _coretpk_installer_prepare_package_install: failed to get the pkg info.");
		ret = RPM_INSTALLER_ERR_INTERNAL;
		goto err;
	}

	_LOGD("[##]csc-core : get pkgid [%s]", info->package_name);

	/*If the directory which will be installed exists, remove it.*/
	snprintf(buff, BUF_SIZE, "%s/%s/", OPT_USR_APPS, info->package_name);
	if (__is_dir(buff)) {
		_rpm_delete_dir(buff);
	}

	_LOGD("[##]csc-core : real path [%s]", buff);

	const char *unzip_argv[] = { "/usr/bin/unzip", "-o", path_str, "-d", buff, NULL };
	ret = _ri_xsystem(unzip_argv);
	if (ret != 0) {
		_LOGE("@Failed to unzip for [%s, %d].", buff, ret);
		goto err;
	}

	_LOGD("[##]csc-core : unzip success[%s]", buff);

	/*getcwd*/
	temp = getcwd(cwd, BUF_SIZE);
	if ((temp == NULL) || (cwd[0] == '\0')) {
		_LOGL("getcwd()", errno);
		ret = RPM_INSTALLER_ERR_INTERNAL;
		goto err;
	}

	/*change dir*/
	ret = chdir(buff);
	if (ret != 0) {
		_LOGL("chdir()", errno);
		ret = RPM_INSTALLER_ERR_INTERNAL;
		goto err;
	}

	_LOGD("[##]csc-core : check signature");

	/*check for signature and certificate*/
	if (_coretpk_installer_get_configuration_value(INI_VALUE_SIGNATURE)) {
		ret = _coretpk_installer_verify_signatures(buff, info->package_name, &visibility);
		if (ret < 0) {
			_LOGE("@Failed to verify signature and certificate[%s].", info->package_name);
			ret = RPM_INSTALLER_ERR_SIG_VERIFICATION_FAILED;
			goto err;
		}
		_LOGD("[##]csc-core : signature verify success[%s]", buff);
	}

   /*chdir*/
	ret = chdir(cwd);
	if (ret != 0) {
		_LOGL("chdir()", errno);
		ret = RPM_INSTALLER_ERR_INTERNAL;
		goto err;
	}

	/*convert manifest and copy the file to /opt/share/packages*/
	snprintf(manifest, BUF_SIZE, "%s/%s/%s", OPT_USR_APPS, info->package_name, CORETPK_XML);
	ret = _coretpk_parser_convert_manifest(manifest, info->package_name, NULL, false, visibility, NULL);
	if (ret != 0) {
		_LOGE("@Failed to convert the manifest.");
		ret = RPM_INSTALLER_ERR_INVALID_MANIFEST;
		goto err;
	}

	_LOGD("[##]csc-core : manifest converting success");

	/*check the manifest file.*/
	memset(manifest, '\0', sizeof(manifest));
	snprintf(manifest, BUF_SIZE, "%s/%s.xml", OPT_SHARE_PACKAGES, info->package_name);
	/*compare manifest.xml with schema file(/usr/etc/package-manager/preload/manifest.xsd)*/
	ret = pkgmgr_parser_check_manifest_validation(manifest);
	if(ret < 0) {
		_LOGE("@invalid manifest file");
		ret = RPM_INSTALLER_ERR_INVALID_MANIFEST;
		goto err;
	}

	_LOGD("[##]csc-core : manifest validation success");

	/*Parse the manifest to get install location and size. If installation fails, remove manifest info from DB*/
	if (strcmp(remove_str,"true")==0)
		csc_tags[0] = "removable=true";
	else
		csc_tags[0] = "removable=false";

	csc_tags[1] = "preload=true";
	csc_tags[2] = NULL;

	ret = pkgmgr_parser_parse_manifest_for_installation(manifest, csc_tags);
	if (ret < 0) {
		_LOGE("@Failed to parse the manifest.");
		ret = RPM_INSTALLER_ERR_INTERNAL;
		goto err;
	}

	_LOGD("[##]csc-core : register manifest success");

	/*register cert info*/
	_ri_register_cert(info->package_name);

	/*make directory*/
	ret = _coretpk_installer_make_directory(info->package_name);
	if (ret != 0) {
		_LOGE("@Failed to make the directory");
		goto err;
	}

	_LOGD("[##]csc-core : make directory success");

	/*apply smack to app dir*/
	ret = _coretpk_installer_apply_smack(info->package_name, 1);
	if (ret != 0) {
		_LOGE("@Failed to apply the smack.");
		goto err;
	}

	_LOGD("[##]csc-core : apply_smack success");

	/*apply smack by privilege*/
	ret = _ri_apply_privilege(info->package_name, visibility);
	if (ret != 0) {
		_LOGE("@Failed to apply permission[%d].", ret);
	}

	_LOGD("[##]csc-core : apply_privilege success");

#if 0
	/*reload smack*/
	ret = _ri_smack_reload(info->package_name, REQUEST_TYPE_INSTALL);
	if (ret != 0) {
		_LOGD("@Failed to reload the smack.");
	}
#endif

	_LOGD("[##]csc-core : smack_reload success");

	ret = RPM_INSTALLER_SUCCESS;

err:
	if (ret == 0) {
		_LOGD("[##]csc-core : finish csc core success");
	} else {
		/*remove xml(/opt/share/packages/pkgid.xml)*/
		if (access(manifest, F_OK) == 0) {
			(void)remove(manifest);
		}

		/*remove app dir(/opt/usr/apps/pkgid)*/
		snprintf(buff, BUF_SIZE, "%s/%s/", OPT_USR_APPS, info->package_name);
		if (__is_dir(buff)) {
			_rpm_delete_dir(buff);
		}
		_LOGD("[##]csc-core : finish csc core fail");

	}

	if (info) {
		free(info);
		info = NULL;
	}

	return ret;
}
