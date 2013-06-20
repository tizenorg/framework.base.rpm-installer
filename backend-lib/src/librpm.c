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

#include "librpminternals.h"

#define BASEDIR						"/opt/share"
#define BUFFSIZE						256

void pkg_native_plugin_on_unload(void)
{
	return;
}

int pkg_plugin_app_is_installed(const char *pkgid)
{
	_librpm_print(DEBUG_INFO,
		      "pkg_plugin_app_is_installed() is called\n");
	/* Check for valid arguments */
	if (pkgid == NULL) {
		_librpm_print(DEBUG_ERR,
			      "[pkg_plugin_get_app_detail_info_from_package] "
			      "args supplied is NULL\n");
		return LIBRPM_ERROR;
	}
	int ret = -1;
	ret = _librpm_app_is_installed(pkgid);
	if (ret == -1) {
		_librpm_print(DEBUG_ERR, "_librpm_app_is_installed() failed\n");
		return LIBRPM_ERROR;
	}
	/*1 for installed, 0 for not installed*/
	if (ret == 1)
		return LIBRPM_SUCCESS;
	else
		return LIBRPM_ERROR;
}

int pkg_plugin_get_installed_apps_list(const char *category,
				       const char *option,
				       package_manager_pkg_info_t **list,
				       int *count)
{
	return LIBRPM_SUCCESS;
}

int pkg_plugin_get_app_detail_info(const char *pkgid,
				   package_manager_pkg_detail_info_t
				   *pkg_detail_info)
{
	_librpm_print(DEBUG_INFO,
		      "pkg_plugin_get_app_detail_info() is called\n");
	/* Check for valid arguments */
	if (pkgid == NULL || pkg_detail_info == NULL) {
		_librpm_print(DEBUG_ERR,
			      "[pkg_plugin_get_app_detail_info_from_package] "
			      "args supplied is NULL\n");
		return LIBRPM_ERROR;
	}
	char dirname[BUFFSIZE] = { '\0' };
	int ret = 0;
	long long data_size = 0;
	char buff[256] = {'\0'};
	time_t install_time = 0;

	/* pkgtype is by default rpm */
	strncpy(pkg_detail_info->pkg_type, "rpm", sizeof(pkg_detail_info->pkg_type));

	/* Get the installed package info from rpm db */
	ret = _librpm_get_installed_package_info(pkgid, pkg_detail_info);
	if (ret) {
		return LIBRPM_ERROR;
	}

	/*get data_size*/
	snprintf(dirname, BUFFSIZE-1, "/opt/usr/apps/%s/data", pkgid);
	data_size = _librpm_calculate_dir_size(dirname);
	if (data_size < 0) {
		_librpm_print(DEBUG_ERR,
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
	/* Installed Time*/
	snprintf(buff, 256, "db/app-info/%s/installed-time", pkgid);
	ret = vconf_get_int(buff, (int *)&install_time);
	if (ret) {
		_librpm_print(DEBUG_ERR, "get installed time failed\n");
		pkg_detail_info->installed_time = 0;
	}
	else
		pkg_detail_info->installed_time = install_time;


	return LIBRPM_SUCCESS;
}

int pkg_plugin_get_app_detail_info_from_package(const char *pkg_path,
					package_manager_pkg_detail_info_t
					*pkg_detail_info)
{
	_librpm_print(DEBUG_INFO,
		      "pkg_plugin_get_app_detail_info_from_package() is called\n");

	/* Check for valid arguments */
	if (pkg_path == NULL || pkg_detail_info == NULL) {
		_librpm_print(DEBUG_ERR,
			      "[pkg_plugin_get_app_detail_info_from_package]"
			      "args supplied is NULL\n");
		return LIBRPM_ERROR;
	}

	int ret = 0;
	long long data_size = 0;
	char *str = NULL;
	char dirname[BUFFSIZE] = { '\0' };
	char buff[256] = {'\0'};
	time_t install_time = 0;

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
                _librpm_print(DEBUG_ERR,
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
		_librpm_print(DEBUG_ERR, "get installed time failed\n");
		pkg_detail_info->installed_time = 0;
	}
	else
		pkg_detail_info->installed_time = install_time;


	return LIBRPM_SUCCESS;
}

API int pkg_plugin_on_load(pkg_plugin_set *set)
{
	_librpm_print(DEBUG_ERR, "pkg_plugin_on_load() is called\n");
	static int initialized = 0;
	rpmRC rc;
	if (set == NULL) {
		return LIBRPM_ERROR;
	}

	memset(set, 0x00, sizeof(pkg_plugin_set));
	if (!initialized) {
		rc = rpmReadConfigFiles(NULL, NULL);
		if (rc == RPMRC_OK) {
			initialized = 1;
			_librpm_print(DEBUG_ERR, "Successfully read RPM configuration.\n");
		}
		else {
			_librpm_print(DEBUG_ERR, "Unable to read RPM configuration.\n");
			initialized = 0;
	                return LIBRPM_ERROR;
		}
	}

	set->plugin_on_unload = pkg_native_plugin_on_unload;
	set->pkg_is_installed = pkg_plugin_app_is_installed;
	set->get_installed_pkg_list = pkg_plugin_get_installed_apps_list;
	set->get_pkg_detail_info = pkg_plugin_get_app_detail_info;
	set->get_pkg_detail_info_from_package =
	    pkg_plugin_get_app_detail_info_from_package;

	return LIBRPM_SUCCESS;
}
