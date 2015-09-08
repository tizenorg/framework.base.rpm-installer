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
/*rpm specific headers*/
#include <rpmlib.h>
#include <header.h>
#include <rpmts.h>
#include <rpmdb.h>
#include <vconf.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <ctype.h>

#include "librpminternals.h"
#include "rpm-installer-util.h"

#define BASEDIR						"/opt/share"
#define BUFFSIZE						1024

static int __xsystem(const char *argv[])
{
	int status = 0;
	pid_t pid;
	pid = fork();
	switch (pid) {
	case -1:
		perror("fork failed");
		return -1;
	case 0:
		/* child */
		execvp(argv[0], (char *const *)argv);
		_exit(-1);
	default:
		/* parent */
		break;
	}
	if (waitpid(pid, &status, 0) == -1) {
		perror("waitpid failed");
		return -1;
	}
	if (WIFSIGNALED(status)) {
		perror("signal");
		return -1;
	}
	if (!WIFEXITED(status)) {
		/* shouldn't happen */
		perror("should not happen");
		return -1;
	}
	return WEXITSTATUS(status);
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

	char *pRes = (char*)malloc(len + 1);
	if(pRes == NULL){
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
	char buf[BUFFSIZE] = {0};
	char icon_path[BUFFSIZE] = {0};
	char *pkgid = NULL;
	char *version = NULL;
	char *label = NULL;
	char *icon = NULL;
	char *api_version = NULL;

	if(pkg_detail_info == NULL){
		_LOGE("pkg_details_info is NULL");
		return -1;
	}

	fp = fopen(manifest, "r");
	if (fp == NULL)	{
		_LOGE("fopen(%s) failed.", manifest);
		return -1;
	}

	while (fgets(buf, BUFFSIZE, fp) != NULL) {
		__str_trim(buf);

		if (strstr(buf, "?xml") != NULL)
		{
			memset(buf, 0x00, BUFFSIZE);
			continue;
		}

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

		memset(buf, 0x00, BUFFSIZE);
	}
	fclose(fp);

	strncpy(pkg_detail_info->pkg_type, "coretpk", strlen("coretpk"));
	pkg_detail_info->pkg_type[strlen("coretpk")] = '\0';

	if (pkgid) {
		strncpy(pkg_detail_info->pkgid, pkgid, strlen(pkgid));
		strncpy(pkg_detail_info->pkg_name, pkgid, strlen(pkgid));

		free(pkgid);
	}

	if (version) {
		if (strlen(version) < PKG_VERSION_STRING_LEN_MAX)
			strncpy(pkg_detail_info->version, version, strlen(version));
		else
			_LOGE("version name too long");
		free(version);
	}

	if (api_version) {
		strncpy(pkg_detail_info->api_version, api_version, strlen(api_version));

		free(api_version);
	}

	if (label) {
		strncpy(pkg_detail_info->label, label, strlen(label));

		free(label);
	}

	if (icon) {
		snprintf(icon_path, BUFFSIZE, "shared/res/%s", icon);
		const char *unzip_icon_argv[] = { "/usr/bin/unzip", pkg_path, icon_path, "-d", "/tmp/coretpk-unzip", NULL };

		ret = __xsystem(unzip_icon_argv);
		if (ret == 0) {
			struct stat fileinfo;

			memset(icon_path, 0x00, BUFFSIZE);
			snprintf(icon_path, BUFFSIZE, "/tmp/coretpk-unzip/shared/res/%s", icon);

			if (lstat(icon_path, &fileinfo) < 0) {
				_LOGE("lstat(%s) failed.", icon_path);
			} else {
				FILE *icon_fp = NULL;
				pkg_detail_info->icon_size = fileinfo.st_size + 1;
				pkg_detail_info->icon_buf = (char*) calloc(1, (sizeof(char) * pkg_detail_info->icon_size));
				if(pkg_detail_info->icon_buf == NULL){
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

static int __is_core_tpk_app(const char *pkg_path, package_manager_pkg_detail_info_t *pkg_detail_info)
{
	int ret = 0;
	const char *unzip_argv[] = { "/usr/bin/unzip", pkg_path, "tizen-manifest.xml", "-d", "/tmp/coretpk-unzip", NULL };
	const char *delete_argv[] = { "/bin/rm", "-rf", "/tmp/coretpk-unzip", NULL };

	__xsystem(delete_argv);

	ret = mkdir("/tmp/coretpk-unzip", 0755);
	if (ret != 0) {
		_LOGE("mkdir(/tmp/coretpk-unzip) failed.");
		return -1;
	}

	/* In case of installation request, pkgid contains the pkgpath */
	ret = __xsystem(unzip_argv);
	if (ret == 0) {
		_LOGD("[%s] is core-tpk.", pkg_path);

		if (access("/tmp/coretpk-unzip/tizen-manifest.xml", R_OK) == 0) {
			_LOGD("tizen-manifest.xml is found.");
		} else {
			_LOGE("tizen-manifest.xml is not found.");
			__xsystem(delete_argv);
			return -1;
		}

		ret = __read_pkg_detail_info(pkg_path, "/tmp/coretpk-unzip/tizen-manifest.xml", pkg_detail_info);
		if (ret != 0) {
			_LOGE("__read_pkg_detail_info() failed. [%s]", pkg_path);
			__xsystem(delete_argv);
			return -1;
		}

		ret = 1;
	} else {
		_LOGE("[%s] is not core-tpk.", pkg_path);
		ret = -1;
	}

	__xsystem(delete_argv);
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
	}
	else {
		_LOGD("pkgid[%s] is not installed.", pkgid);
		return LIBRPM_ERROR;
	}
}

int pkg_plugin_get_installed_apps_list(const char *category, const char *option, package_manager_pkg_info_t **list, int *count)
{
	_LOGD("pkg_plugin_get_installed_apps_list() is called.");

	return LIBRPM_SUCCESS;
}

int pkg_plugin_get_app_detail_info(const char *pkgid, package_manager_pkg_detail_info_t *pkg_detail_info)
{
	if (pkgid == NULL || pkg_detail_info == NULL) {
		_LOGE("pkgid or pkg_detail_info is NULL.");
		return LIBRPM_ERROR;
	}

	_LOGD("pkg_plugin_get_app_detail_info(%s) is called.", pkgid);

	int ret = 0;
	char dirname[BUFFSIZE] = {'\0'};
	long long data_size = 0;
	char buff[BUFFSIZE] = {'\0'};
	time_t install_time = 0;

	/* pkgtype is by default rpm */
	strncpy(pkg_detail_info->pkg_type, "rpm", sizeof(pkg_detail_info->pkg_type));

	/* Get the installed package info from rpm db */
	ret = _librpm_get_installed_package_info(pkgid, pkg_detail_info);
	if (ret) {
		_LOGE("_librpm_get_installed_package_info(%s) failed.", pkgid);
		return LIBRPM_ERROR;
	}

	/* get data_size */
	snprintf(dirname, BUFFSIZE-1, "/opt/usr/apps/%s/data", pkgid);
	data_size = _librpm_calculate_dir_size(dirname);
	if (data_size < 0) {
		_LOGE("_librpm_calculate_dir_size(%s) failed.", dirname);
		pkg_detail_info->data_size = 0 ;
	}
	else {
		data_size += BLOCK_SIZE; /* the function does not adds 4096 bytes for the directory size itself*/
		pkg_detail_info->data_size = data_size/1024 ;
	}

	/* Min Platform Version */
	pkg_detail_info->min_platform_version[0] = '\0';

	/* Optional ID*/
	pkg_detail_info->optional_id[0] = '\0';

	/* Total Installed Size*/
	pkg_detail_info->installed_size = pkg_detail_info->app_size + pkg_detail_info->data_size;

	/* Installed Time*/
	snprintf(buff, BUFFSIZE-1, "db/app-info/%s/installed-time", pkgid);
	ret = vconf_get_int(buff, (int *)&install_time);
	if (ret) {
		_LOGE("vconf_get_int(%s) failed.", buff);
		pkg_detail_info->installed_time = 0;
	}
	else
		pkg_detail_info->installed_time = install_time;

	return LIBRPM_SUCCESS;
}

int pkg_plugin_get_app_detail_info_from_package(const char *pkg_path, package_manager_pkg_detail_info_t *pkg_detail_info)
{
	if (pkg_path == NULL || pkg_detail_info == NULL) {
		_LOGE("pkg_path or pkg_detail_info is NULL.");
		return LIBRPM_ERROR;
	}

	_LOGD("pkg_plugin_get_app_detail_info_from_package(%s) is called.", pkg_path);

	int ret = 0;
	long long data_size = 0;
	char *str = NULL;
	char dirname[BUFFSIZE] = {'\0'};
	char buff[BUFFSIZE] = {'\0'};
	time_t install_time = 0;

	if (__is_core_tpk_app(pkg_path, pkg_detail_info) == 1) {
		return LIBRPM_SUCCESS;
	}

	/* populate pkg type */
	str = strrchr(pkg_path, 46);	/* 46 is ASCII for . */
	strncpy(pkg_detail_info->pkg_type, (str + 1), strlen(str + 1));

	/* populate rpm header specific info (name, version, description, size)*/
	ret = _librpm_get_package_header_info(pkg_path, pkg_detail_info);
	if (ret) {
		return LIBRPM_ERROR;
	}

	/*get data_size. If pkg is not installed it will be 0*/
	snprintf(dirname, BUFFSIZE-1, "/opt/usr/apps/%s/data",
				pkg_detail_info->pkgid);

        data_size = _librpm_calculate_dir_size(dirname);
        if (data_size < 0) {
                _LOGE(
                                "Calculate dir size failed\n");
                pkg_detail_info->data_size = 0 ;
        }
        else {
		data_size += BLOCK_SIZE; /* the function does not adds 4096
                                        bytes for the directory size itself*/

                pkg_detail_info->data_size = data_size/1024 ;
        }

	/* Min Platform Version */
	pkg_detail_info->min_platform_version[0] = '\0';

	/* Optional ID*/
	pkg_detail_info->optional_id[0] = '\0';

	/* Total Installed Size*/
	pkg_detail_info->installed_size = pkg_detail_info->app_size +
									pkg_detail_info->data_size;

	/* Installed Time */
	snprintf(buff, 256, "db/app-info/%s/installed-time", pkg_detail_info->pkgid);
	ret = vconf_get_int(buff, (int *)&install_time);
	if (ret) {
		_LOGE("get installed time failed\n");
		pkg_detail_info->installed_time = 0;
	}
	else
		pkg_detail_info->installed_time = install_time;


	return LIBRPM_SUCCESS;
}

API int pkg_plugin_on_load(pkg_plugin_set *set)
{
	if (set == NULL) {
		_LOGE("set is NULL.");
		return LIBRPM_ERROR;
	}

	_LOGD("pkg_plugin_on_load() is called.");

	static int initialized = 0;
	rpmRC rc;
	memset(set, 0x00, sizeof(pkg_plugin_set));

	if (!initialized) {
		rc = rpmReadConfigFiles(NULL, NULL);
		if (rc == RPMRC_OK) {
			initialized = 1;
			_LOGD("rpmReadConfigFiles() is ok.");
		}
		else {
			_LOGE("rpmReadConfigFiles() failed.");
			initialized = 0;
			return LIBRPM_ERROR;
		}
	}

	set->plugin_on_unload = pkg_native_plugin_on_unload;
	set->pkg_is_installed = pkg_plugin_app_is_installed;
	set->get_installed_pkg_list = pkg_plugin_get_installed_apps_list;
	set->get_pkg_detail_info = pkg_plugin_get_app_detail_info;
	set->get_pkg_detail_info_from_package = pkg_plugin_get_app_detail_info_from_package;

	return LIBRPM_SUCCESS;
}
