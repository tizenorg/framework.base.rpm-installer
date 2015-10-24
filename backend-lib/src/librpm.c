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
#include <sys/time.h>
#include <vconf.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <ctype.h>
#include <unzip.h>

#include "librpminternals.h"
#include "installer-type.h"
#define READ_SIZE 8192

static int __installer_util_unzip_file(const char *pkg_path, char *file_name_to_unzip, char *out_path)
{
	if (pkg_path == NULL || file_name_to_unzip == NULL || out_path == NULL) {
		_LOGE("File path is NULL");
		return -1;
	}

	FILE *fout = NULL;
	char *zipfilename = (char *)pkg_path;
	int ret = 0;
	char *unzipped_file = NULL;
	char *filename = NULL;
	int length = 0;

	unzFile zip = unzOpen(zipfilename);
	if (zip == NULL) {
		_LOGE("FAIL: unzOpen(%s)", zipfilename);
		return -1;
	}
	ret = unzGoToFirstFile(zip);
	if (ret != UNZ_OK) {
		_LOGE("FAIL: unzGoToFirstFile(): %d", ret);
		goto catch;
	}
	do {
		ret = unzOpenCurrentFile(zip);
		if (ret != UNZ_OK) {
			_LOGE("FAIL: unzOpenCurrentFile(): %d", ret);
			goto catch;
		}
		unz_file_info fileInfo;
		memset(&fileInfo, 0, sizeof(unz_file_info));
		ret = unzGetCurrentFileInfo(zip, &fileInfo, NULL, 0, NULL, 0, NULL, 0);
		if (ret != UNZ_OK) {
			_LOGE("FAIL: unzGetCurrentFileInfo(): %d", ret);
			goto catch;
		}
		filename = (char *)malloc(fileInfo.size_filename + 1);
		if (filename == NULL) {
			_LOGE("FAIL: malloc()");
			goto catch;
		}
		memset(filename, 0, fileInfo.size_filename + 1);
		ret = unzGetCurrentFileInfo(zip, &fileInfo, filename, fileInfo.size_filename + 1, NULL, 0, NULL, 0);
		if (ret != UNZ_OK) {
			_LOGE("FAIL: unzGetCurrentFileInfo(): %d", ret);
			goto catch;
		}
		filename[fileInfo.size_filename] = '\0';
		_LOGD("%s\n", filename);
		if (strstr(filename, file_name_to_unzip) != NULL) {
			char *ptr = NULL;
			_LOGD("file found %s\n", file_name_to_unzip);
			if (strstr(file_name_to_unzip, "/") != NULL) {
				ptr = strrchr(file_name_to_unzip, '/');
				if (!ptr)
					goto catch;
				ptr++;
			} else {
				ptr = file_name_to_unzip;
			}
			length = strlen(ptr) + strlen(out_path) + 2;
			unzipped_file = (char *)malloc(length);
			if (unzipped_file == NULL) {
				_LOGE("FAIL: malloc()");
				goto catch;
			}
			memset(unzipped_file, 0, length);
			strncpy(unzipped_file, out_path, length);
			strncat(unzipped_file, "/", length - strlen(unzipped_file) - 1);
			strncat(unzipped_file, ptr, length - strlen(unzipped_file) - 1);
			unsigned char buffer[READ_SIZE] = { 0, };
			fout = fopen(unzipped_file, "w");
			if (fout == NULL) {
				_LOGE("error opening %s\n", unzipped_file);
				goto catch;
			}
			do {
				ret = unzReadCurrentFile(zip, buffer, READ_SIZE);
				if (ret < 0) {
					_LOGE("error %d with zipfile in unzReadCurrentFile", ret);
					goto catch;
				}
				if (ret > 0) {
					if (fwrite(buffer, ret, 1, fout) != 1) {
						ret = UNZ_ERRNO;
						_LOGE("error %d in writing extracted file", ret);
						goto catch;
					}
				}
			} while (ret > 0);
			fclose(fout);
			unzCloseCurrentFile(zip);
			free(unzipped_file);
			free(filename);
			unzClose(zip);
			return 0;
		}
		free(filename);
		filename = NULL;
		unzCloseCurrentFile(zip);
	} while (unzGoToNextFile(zip) == UNZ_OK);
	_LOGE("file not found");

 catch:
	if (filename)
		free(filename);
	if (unzipped_file)
		free(unzipped_file);
	if (fout)
		fclose(fout);
	unzClose(zip);
	return -1;
}

static int __installer_util_delete_dir(const char *dir_path)
{
	if (dir_path == NULL) {
		_LOGD("dir_path is NULL.");
		return -1;
	}

	int ret = 0;
	DIR *dp = NULL;
	struct dirent entry, *result;
	char abs_filename[FILENAME_MAX] = { 0, };
	struct stat stFileInfo = { 0 };
	char buf[BUF_SIZE] = { 0, };

	_LOGD("delete_dir=[%s]", dir_path);

	dp = opendir(dir_path);
	if (dp == NULL) {
		ret = -1;
		if( strerror_r(errno, buf, sizeof(buf)) == 0) {
			_LOGE("opendir(%s) failed. [%d][%s]", dir_path, errno, buf);
		}
		goto catch;
	}

	for (ret = readdir_r(dp, &entry, &result);
			ret == 0 && result != NULL;
			ret = readdir_r(dp, &entry, &result)) {

		snprintf(abs_filename, FILENAME_MAX, "%s/%s", dir_path, entry.d_name);
		if (lstat(abs_filename, &stFileInfo) < 0) {
			_LOGE("lstat(%s) failed.", abs_filename);
			perror(abs_filename);
			continue;
		}

		if (S_ISDIR(stFileInfo.st_mode)) {
			if (strcmp(entry.d_name, ".") && strcmp(entry.d_name, "..")) {
				__installer_util_delete_dir(abs_filename);
				(void)remove(abs_filename);
			}
		} else {
			(void)remove(abs_filename);
		}
	}

	(void)closedir(dp);
	dp = NULL;

	(void)remove(dir_path);

 catch:
	return ret;
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

static char *__get_value(const char *pBuf, const char *pKey, int seperator)
{
	const char *p = NULL;
	const char *pStart = NULL;
	const char *pEnd = NULL;

	p = strstr(pBuf, pKey);
	if (p == NULL)
		return NULL;

	pStart = p + strlen(pKey) + 1;
	pEnd = strchr(pStart, seperator);
	if (pEnd == NULL)
		return NULL;

	size_t len = pEnd - pStart;
	if (len <= 0)
		return NULL;

	char *pRes = (char *)malloc(len + 1);
	if (pRes == NULL) {
		_LOGE("malloc() failed.");
		return NULL;
	}

	strncpy(pRes, pStart, len);
	pRes[len] = 0;

	_LOGD("key = [%s], value = [%s]", pKey, pRes);
	return pRes;
}

static int __read_pkg_detail_info(const char *pkg_path, const char *manifest, package_manager_pkg_detail_info_t *pkg_detail_info)
{
	int ret = 0;
	FILE *fp = NULL;
	char buf[BUF_SIZE] = { 0 };
	char icon_path[BUF_SIZE] = { 0 };
	char *pkgid = NULL;
	char *version = NULL;
	char *label = NULL;
	char *icon = NULL;
	char *api_version = NULL;

	if (pkg_detail_info == NULL) {
		_LOGE("pkg_details_info is NULL");
		return -1;
	}

	fp = fopen(manifest, "r");
	if (fp == NULL) {
		_LOGE("fopen(%s) failed.", manifest);
		return -1;
	}

	while (fgets(buf, BUF_SIZE, fp) != NULL) {
		__str_trim(buf);

#if 0
		if (strstr(buf, "?xml") != NULL) {
			memset(buf, 0x00, BUF_SIZE);
			continue;
		}
#endif

		if (pkgid == NULL) {
			pkgid = __get_value(buf, "package=", '"');
		}

		if (version == NULL) {
			version = strstr(buf, "version=");
			/* if the result substring is "api-version", search again */
			if (version && (buf != version) && *(char *)(version - 1) == '-') {
				version = version + strlen("api-version=");
				version = __get_value(version, "version=", '"');
			} else {
				version = __get_value(buf, "version=", '"');
			}
		}

		if (api_version == NULL) {
			api_version = __get_value(buf, "api-version=", '"');
		}

		if (label == NULL) {
			label = __get_value(buf, "<label", '<');
		}

		if (icon == NULL) {
			icon = __get_value(buf, "<icon", '<');
		}

		char *privilege = __get_value(buf, "<privilege", '<');
		if (privilege != NULL) {
			pkg_detail_info->privilege_list = g_list_append(pkg_detail_info->privilege_list, privilege);
		}

		memset(buf, 0x00, BUF_SIZE);
	}
	fclose(fp);

	strncpy(pkg_detail_info->pkg_type, "rpm", PKG_NAME_STRING_LEN_MAX - 1);
	pkg_detail_info->pkg_type[strlen("rpm")] = '\0';

	if (pkgid) {
		strncpy(pkg_detail_info->pkgid, pkgid, PKG_NAME_STRING_LEN_MAX - 1);
		strncpy(pkg_detail_info->pkg_name, pkgid, PKG_NAME_STRING_LEN_MAX - 1);

		free(pkgid);
	}

	if (version) {
		strncpy(pkg_detail_info->version, version, PKG_NAME_STRING_LEN_MAX - 1);

		free(version);
	}

	if (api_version) {
		strncpy(pkg_detail_info->api_version, api_version, PKG_NAME_STRING_LEN_MAX - 1);

		free(api_version);
	}

	if (label) {
		strncpy(pkg_detail_info->label, label, PKG_NAME_STRING_LEN_MAX - 1);

		free(label);
	}

	if (icon) {
		snprintf(icon_path, BUF_SIZE, "shared/res/%s", icon);

		ret = __installer_util_unzip_file(pkg_path, icon_path, "/tmp/coretpk-unzip");
		if (ret == 0) {
			struct stat fileinfo;

			memset(icon_path, 0x00, BUF_SIZE);
			snprintf(icon_path, BUF_SIZE, "/tmp/coretpk-unzip/%s", icon);

			if (lstat(icon_path, &fileinfo) < 0) {
				_LOGE("lstat(%s) failed.", icon_path);
			} else {
				FILE *icon_fp = NULL;
				pkg_detail_info->icon_size = fileinfo.st_size + 1;
				pkg_detail_info->icon_buf = (char *)calloc(1, (sizeof(char) * pkg_detail_info->icon_size));
				if (pkg_detail_info->icon_buf == NULL) {
					_LOGE("calloc failed!!");
					free(icon);
					return -1;
				}

				icon_fp = fopen(icon_path, "r");
				if (icon_fp) {
					int readbyte = fread(pkg_detail_info->icon_buf, 1, pkg_detail_info->icon_size - 1, icon_fp);
					_LOGD("icon_size = [%d], readbyte = [%d]", pkg_detail_info->icon_size, readbyte);

					fclose(icon_fp);
				} else {
					_LOGE("fopen(%s) failed.", icon_path);
				}
			}
		} else {
			_LOGE("unzip(%s) failed.", icon_path);
		}

		free(icon);
	}

	return 0;
}

static int __is_core_tpk_app(const char *pkg_path, package_manager_pkg_detail_info_t * pkg_detail_info)
{
	int ret = 0;
	char *delete_dir = "/tmp/coretpk-unzip";

	__installer_util_delete_dir(delete_dir);

	ret = mkdir("/tmp/coretpk-unzip", 0755);
	if (ret != 0) {
		_LOGE("mkdir(/tmp/coretpk-unzip) failed.");
		return -1;
	}

	/* In case of installation request, pkgid contains the pkgpath */
	ret = __installer_util_unzip_file(pkg_path, "tizen-manifest.xml", "/tmp/coretpk-unzip");
	if (ret == 0) {
		_LOGD("[%s] is core-tpk.", pkg_path);

		if (access("/tmp/coretpk-unzip/tizen-manifest.xml", R_OK) == 0) {
			_LOGD("tizen-manifest.xml is found.");
		} else {
			_LOGE("tizen-manifest.xml is not found.");
			__installer_util_delete_dir(delete_dir);
			return -1;
		}

		ret = __read_pkg_detail_info(pkg_path, "/tmp/coretpk-unzip/tizen-manifest.xml", pkg_detail_info);
		if (ret != 0) {
			_LOGE("__read_pkg_detail_info() failed. [%s]", pkg_path);
			__installer_util_delete_dir(delete_dir);
			return -1;
		}

		ret = 1;
	} else {
		_LOGE("[%s] is not core-tpk.", pkg_path);
		ret = -1;
	}

	__installer_util_delete_dir(delete_dir);
	return ret;
}

void pkg_native_plugin_on_unload(void)
{
	_LOGD("pkg_native_plugin_on_unload() is called.");

	return;
}

int pkg_plugin_app_is_installed(const char *pkgid)
{
	if (pkgid == NULL) {
		_LOGE("pkgid is NULL.");
		return LIBRPM_ERROR;
	}

	_LOGD("pkg_plugin_app_is_installed(%s) is called.", pkgid);

	int ret = -1;
	ret = _librpm_app_is_installed(pkgid);
	if (ret == -1) {
		_LOGE("_librpm_app_is_installed(%s) failed.", pkgid);
		return LIBRPM_ERROR;
	}
	// 1 for installed, 0 for not installed
	if (ret == 1) {
		_LOGD("pkgid[%s] is installed.", pkgid);
		return LIBRPM_SUCCESS;
	} else {
		_LOGD("pkgid[%s] is not installed.", pkgid);
		return LIBRPM_ERROR;
	}
}

int pkg_plugin_get_installed_apps_list(const char *category, const char *option, package_manager_pkg_info_t ** list, int *count)
{
	_LOGD("pkg_plugin_get_installed_apps_list() is called.");

	return LIBRPM_SUCCESS;
}

int pkg_plugin_get_app_detail_info(const char *pkgid, package_manager_pkg_detail_info_t * pkg_detail_info)
{
	if (pkgid == NULL || pkg_detail_info == NULL) {
		_LOGE("pkgid or pkg_detail_info is NULL.");
		return LIBRPM_ERROR;
	}

	_LOGD("pkg_plugin_get_app_detail_info(%s) is called.", pkgid);

	int ret = 0;
	time_t install_time = 0;

	/* pkgtype is by default rpm */
	strncpy(pkg_detail_info->pkg_type, "rpm", sizeof(pkg_detail_info->pkg_type));

	/* Get the installed package info from rpm db */
	ret = _librpm_get_installed_package_info(pkgid, pkg_detail_info);
	if (ret) {
		_LOGE("_librpm_get_installed_package_info(%s) failed.", pkgid);
		return LIBRPM_ERROR;
	}

	/* Min Platform Version */
	pkg_detail_info->min_platform_version[0] = '\0';

	/* Optional ID */
	pkg_detail_info->optional_id[0] = '\0';

	/* Installed Time */
	pkg_detail_info->installed_time = install_time;

	return LIBRPM_SUCCESS;
}

int pkg_plugin_get_app_detail_info_from_package(const char *pkg_path, package_manager_pkg_detail_info_t * pkg_detail_info)
{
	if (pkg_path == NULL || pkg_detail_info == NULL) {
		_LOGE("pkg_path or pkg_detail_info is NULL.");
		return LIBRPM_ERROR;
	}

	_LOGD("pkg_plugin_get_app_detail_info_from_package(%s) is called.", pkg_path);

	int ret = 0;
	long long data_size = 0;
	char *str = NULL;
	char dirname[BUF_SIZE] = { '\0' };
	time_t install_time = 0;

	if (__is_core_tpk_app(pkg_path, pkg_detail_info) == 1) {
		return LIBRPM_SUCCESS;
	}

	/* populate pkg type */
	str = strrchr(pkg_path, 46);	/* 46 is ASCII for . */
	if (str == NULL) {
		_LOGE("strrchr is NULL.");
		return LIBRPM_ERROR;
	}
	strncpy(pkg_detail_info->pkg_type, (str + 1), PKG_NAME_STRING_LEN_MAX - 1);

	/* populate rpm header specific info (name, version, description, size) */
	ret = _librpm_get_package_header_info(pkg_path, pkg_detail_info);
	if (ret) {
		return LIBRPM_ERROR;
	}

	/*get data_size. If pkg is not installed it will be 0 */
	snprintf(dirname, BUF_SIZE - 1, "%s/%s/data", OPT_USR_APPS, pkg_detail_info->pkgid);

	data_size = _librpm_calculate_dir_size(dirname);
	if (data_size < 0) {
		_LOGE("Calculate dir size failed\n");
		pkg_detail_info->data_size = 0;
	} else {
		data_size += BLOCK_SIZE;	/* the function does not adds 4096
									   bytes for the directory size itself */

		pkg_detail_info->data_size = data_size / 1024;
	}

	/* Min Platform Version */
	pkg_detail_info->min_platform_version[0] = '\0';

	/* Optional ID */
	pkg_detail_info->optional_id[0] = '\0';

	/* Total Installed Size */
	pkg_detail_info->installed_size = pkg_detail_info->app_size + pkg_detail_info->data_size;

	/* Installed Time */
	pkg_detail_info->installed_time = install_time;

	return LIBRPM_SUCCESS;
}

API int pkg_plugin_on_load(pkg_plugin_set * set)
{
	if (set == NULL) {
		_LOGE("set is NULL.");
		return LIBRPM_ERROR;
	}

	_LOGD("pkg_plugin_on_load() is called.");
	memset(set, 0x00, sizeof(pkg_plugin_set));
	set->plugin_on_unload = pkg_native_plugin_on_unload;
	set->pkg_is_installed = pkg_plugin_app_is_installed;
	set->get_installed_pkg_list = pkg_plugin_get_installed_apps_list;
	set->get_pkg_detail_info = pkg_plugin_get_app_detail_info;
	set->get_pkg_detail_info_from_package = pkg_plugin_get_app_detail_info_from_package;

	return LIBRPM_SUCCESS;
}
