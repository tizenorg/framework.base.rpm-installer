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

#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <stdarg.h>
#include <unistd.h>
#include <sys/wait.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <regex.h>

#include "pkgmgr-info.h"

#include "librpminternals.h"
#include "installer-type.h"

int _librpm_app_is_installed(const char *pkgid)
{
	int ret;
	pkgmgrinfo_pkginfo_h handle = NULL;

	/*Get handle */
	ret = pkgmgrinfo_pkginfo_get_pkginfo(pkgid, &handle);
	if (ret != PMINFO_R_OK) {
		ret = 0;
		_LOGD("%s:App not installed", pkgid);
	} else {
		ret = 1;
		_LOGD("%s:App Installed", pkgid);
	}

	if (handle)
		pkgmgrinfo_pkginfo_destroy_pkginfo(handle);

	return ret;
}

int _librpm_get_installed_package_info(const char *pkgid, package_manager_pkg_detail_info_t * pkg_detail_info)
{
	int ret;
	pkgmgrinfo_pkginfo_h handle = NULL;
	char *temp = NULL;
	long long temp_size = 0;
	long long data_size = 0;
	char data_path[BUF_SIZE] = { 0, };

	/*Get handle */
	ret = pkgmgrinfo_pkginfo_get_pkginfo(pkgid, &handle);
	tryvm_if(ret != PMINFO_R_OK, ret = LIBRPM_ERROR, "pkgmgrinfo_pkginfo_get_pkginfo(%s) failed.", pkgid);
	/*Name */
	ret = pkgmgrinfo_pkginfo_get_pkgname(handle, &temp);
	tryvm_if(ret != PMINFO_R_OK, ret = LIBRPM_ERROR, "pkgmgrinfo_pkginfo_get_pkgname(%s) failed.", pkgid);
	strncpy(pkg_detail_info->pkg_name, temp, PKG_NAME_STRING_LEN_MAX - 1);
	 /*ID*/ ret = pkgmgrinfo_pkginfo_get_pkgid(handle, &temp);
	tryvm_if(ret != PMINFO_R_OK, ret = LIBRPM_ERROR, "pkgmgrinfo_pkginfo_get_pkgid(%s) failed.", pkgid);
	strncpy(pkg_detail_info->pkgid, temp, PKG_NAME_STRING_LEN_MAX - 1);
	/*Version */
	ret = pkgmgrinfo_pkginfo_get_version(handle, &temp);
	tryvm_if(ret != PMINFO_R_OK, ret = LIBRPM_ERROR, "pkgmgrinfo_pkginfo_get_version(%s) failed.", pkgid);
	strncpy(pkg_detail_info->version, temp, PKG_VERSION_STRING_LEN_MAX - 1);
	/*Description */
	ret = pkgmgrinfo_pkginfo_get_description(handle, &temp);
	tryvm_if(ret != PMINFO_R_OK, ret = LIBRPM_ERROR, "pkgmgrinfo_pkginfo_get_description(%s) failed.", pkgid);
	strncpy(pkg_detail_info->pkg_description, temp, PKG_VALUE_STRING_LEN_MAX - 1);
	/*Size */
	ret = pkgmgrinfo_pkginfo_get_root_path(handle, &temp);
	tryvm_if(ret != PMINFO_R_OK, ret = LIBRPM_ERROR, "pkgmgrinfo_pkginfo_get_root_path(%s) failed.", pkgid);
	snprintf(data_path, BUF_SIZE - 1, "%s/%s/data", OPT_USR_APPS, pkgid);

	data_size = _librpm_calculate_dir_size(data_path);
	if (data_size < 0) {
		_LOGE("_librpm_calculate_dir_size(%s) failed.", data_path);
		data_size = 0;
		pkg_detail_info->data_size = 0;

	} else {
		data_size += BLOCK_SIZE;
		data_size /= 1024;
		pkg_detail_info->data_size = (int)data_size;
	}

	temp_size = _librpm_calculate_dir_size(temp);
	if (temp_size < 0) {
		_LOGE("_librpm_calculate_dir_size(%s) failed.", temp);
		temp_size = 0;
		ret = LIBRPM_ERROR;
	} else {
		temp_size += BLOCK_SIZE;	/* the function does not adds 4096 bytes for the directory size itself */
		temp_size /= 1024;
		ret = LIBRPM_SUCCESS;
	}

	if (ret == LIBRPM_SUCCESS) {
		if (strstr(temp, OPT_USR_APPS)) {
			pkg_detail_info->installed_size = (int)temp_size;
			pkg_detail_info->app_size = (int)(temp_size - data_size);
		} else {
			pkg_detail_info->app_size = (int)temp_size;
			pkg_detail_info->installed_size = (int)(data_size + temp_size);
		}
	} else {
		pkg_detail_info->app_size = 0;
		pkg_detail_info->installed_size = 0;
	}

 catch:
	if (handle)
		pkgmgrinfo_pkginfo_destroy_pkginfo(handle);
	return ret;

}

int _librpm_get_package_header_info(const char *pkg_path, package_manager_pkg_detail_info_t * pkg_detail_info)
{
	_LOGE("librpm not using/supported");
	return LIBRPM_ERROR;
}

long long _librpm_calculate_dir_size(const char *dirname)
{
	long long total = 0;
	long long ret = 0;
	int q = 0;					/*quotient */
	int r = 0;					/*remainder */
	DIR *dp = NULL;
	struct dirent entry, *result;
	struct stat fileinfo;
	char abs_filename[FILENAME_MAX] = { 0, };
	if (dirname == NULL) {
		_LOGE("dirname is NULL");
		return LIBRPM_ERROR;
	}
	dp = opendir(dirname);
	if (dp != NULL) {
		for (ret = readdir_r(dp, &entry, &result);
				ret == 0 && result != NULL;
				ret = readdir_r(dp, &entry, &result)) {

			if (!strcmp(entry.d_name, ".") || !strcmp(entry.d_name, "..")) {
				continue;
			}
			snprintf(abs_filename, FILENAME_MAX, "%s/%s", dirname, entry.d_name);
			if (stat(abs_filename, &fileinfo) < 0)
				perror(abs_filename);
			else {
				if (S_ISDIR(fileinfo.st_mode)) {
					total += fileinfo.st_size;
					if (strcmp(entry.d_name, ".")
						&& strcmp(entry.d_name, "..")) {
						ret = _librpm_calculate_dir_size(abs_filename);
						total = total + ret;
					}
				} else {
					/*It is a file. Calculate the actual
					   size occupied (in terms of 4096 blocks) */
					q = (fileinfo.st_size / BLOCK_SIZE);
					r = (fileinfo.st_size % BLOCK_SIZE);
					if (r) {
						q = q + 1;
					}
					total += q * BLOCK_SIZE;
				}
			}
		}
		(void)closedir(dp);
	} else {
		_LOGE("Couldn't open the directory\n");
		return -1;
	}
	return total;

}
