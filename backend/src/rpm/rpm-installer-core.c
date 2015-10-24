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

/* System Include files */
#include <stdbool.h>
#include <string.h>
#include <stdlib.h>
#include <sys/wait.h>
#include <sys/types.h>
#include <unistd.h>
#include <stdarg.h>
#include <stdio.h>
#include <sys/stat.h>
#include <unistd.h>
#include <wait.h>
#include <regex.h>
#include <pthread.h>
#include <dirent.h>
#include <fcntl.h>
#include <errno.h>

/* SLP include files */
#include <pkgmgr-info.h>
#include <pkgmgr_parser.h>
#include "rpm-installer.h"
#include "installer-util.h"
#include "installer-type.h"
#include "db-util.h"
#include "rpm-frontend.h"

extern char *gpkgname;
extern int do_upgrade;

char *_rpm_load_directory(char *directory, char *pkgfile)
{
	DIR *dir;
	struct dirent entry, *result;
	int ret;
	char *buf = NULL;
	char *pkgname = NULL;
	char xml_file[BUF_SIZE] = { 0 };

	buf = malloc(BUF_SIZE);
	if (buf == NULL) {
		_LOGE("malloc failed.\n");
		return NULL;
	}

	dir = opendir(directory);
	if (!dir) {
		if (strerror_r(errno, buf, BUF_SIZE) == 0)
			_LOGE("Can not access to the [%s] because %s.\n", directory, buf);
		free(buf);
		return NULL;
	}

	_LOGD("Loading manifest files from %s\n", directory);

	for (ret = readdir_r(dir, &entry, &result);
		ret == 0 && result != NULL;
		ret = readdir_r(dir, &entry, &result)) {
		char *manifest = NULL;

		if (!strcmp(entry.d_name, ".") || !strcmp(entry.d_name, "..")) {
			continue;
		}

		manifest = _manifest_to_package(entry.d_name);
		if (!manifest) {
			_LOGE("Failed to convert file to xml[%s].\n", entry.d_name);
			continue;
		}

		memset(xml_file, '\0', BUF_SIZE);
		snprintf(xml_file, BUF_SIZE - 1, "%s/%s", directory, manifest);
		_LOGD("manifest is [%s] and its full path is [%s]", manifest, xml_file);
		ret = _get_package_name_from_xml(xml_file, &pkgname);
		if (ret != PMINFO_R_OK || pkgname == NULL) {
			_LOGE("Unable To read [%s] manifest file", xml_file);
			FREE_AND_NULL(manifest);
			continue;
		}

		else {
			snprintf(buf, BUF_SIZE, "%s/%s", directory, manifest);
			_LOGD("Manifest file is %s\n", manifest);
			FREE_AND_NULL(manifest);
			break;
		}
	}

	closedir(dir);

	FREE_AND_NULL(pkgname);

	return buf;
}

pkginfo *_rpm_installer_get_pkgfile_info(char *pkgfile)
{
	pkginfo *info = NULL;
	manifest_x *mfx = NULL;
	int ret = 0;
	int m_exist = 0;
	char cwd[BUF_SIZE] = { '\0' };
	char buff[BUF_SIZE] = { '\0' };
	char manifest[BUF_SIZE] = { '\0' };
	char *temp = NULL;
	char buf[BUF_SIZE] = { 0, };

	temp = getcwd(cwd, BUF_SIZE);
	if ((temp == NULL) || (cwd[0] == '\0')) {
		_LOGE("getcwd() failed.\n");
		return NULL;
	}

	ret = mkdir(TEMP_DIR, 0644);
	if (ret < 0) {
		if (access(TEMP_DIR, F_OK) == 0) {
			_installer_util_delete_dir(TEMP_DIR);
			ret = mkdir(TEMP_DIR, 0644);
			if (ret < 0) {
				_LOGE("mkdir() failed.\n");
				return NULL;
			}
		} else {
			_LOGE("mkdir() failed.\n");
			return NULL;
		}
	}

	ret = chdir(TEMP_DIR);
	if (ret != 0) {
		if (strerror_r(errno, buf, BUF_SIZE) == 0)
			_LOGE("chdir(%s) failed [%s].\n", TEMP_DIR, buf);
		goto err;
	}

	_LOGD("switched to %s\n", TEMP_DIR);

	const char *cpio_argv[] = { CPIO_SCRIPT, pkgfile, NULL };
	ret = _ri_xsystem(cpio_argv);
	if (ret != 0) {
		_LOGE("cpio failed for [%s], returns[%d].", pkgfile, ret);
	}

	snprintf(manifest, BUF_SIZE, "%s%s", TEMP_DIR, OPT_SHARE_PACKAGES);
	char *manifestpath = _rpm_load_directory(manifest, pkgfile);
	if (manifestpath != NULL) {
		strncpy(buff, manifestpath, sizeof(buff) - 1);
		free(manifestpath);
	}

	if (buff[0] == '\0') {
		snprintf(manifest, BUF_SIZE, "%s%s", TEMP_DIR, USR_SHARE_PACKAGES);
		manifestpath = _rpm_load_directory(manifest, pkgfile);
		if (manifestpath != NULL) {
			strncpy(buff, manifestpath, sizeof(buff) - 1);
			free(manifestpath);
		}

		if (buff[0] == '\0') {
			goto err;
		} else {
			m_exist = 1;
		}
	} else {
		m_exist = 1;
	}

	_LOGD("Manifest file is [%s]", buff);

	if (m_exist) {

		_LOGD("The path of manifest.xml is %s.\n", buff);

		/*get package name from xml */
		mfx = pkgmgr_parser_process_manifest_xml(buff);
		if (mfx != NULL) {

			info = calloc(1, sizeof(pkginfo));
			if (info == NULL) {
				_LOGE("calloc failed.\n");
				goto err;
			}

			strncpy(info->package_name, mfx->package, sizeof(info->package_name) - 1);
			strncpy(info->version, mfx->version, sizeof(info->version) - 1);
			_LOGD("_rpm_installer_get_pkgfile_info, pkgname: (%s), version(%s)\n", info->package_name, info->version);
		}
	}

err:
	_installer_util_delete_dir(TEMP_DIR);

	ret = chdir(cwd);
	if (ret != 0) {
		if (strerror_r(errno, buf, BUF_SIZE) == 0)
			_LOGE("chdir(%s) failed [%s].\n", cwd, buf);
	}

	if (mfx != NULL) {
		pkgmgr_parser_free_manifest_xml(mfx);
	}

	return info;
}

pkginfo *_rpm_installer_get_pkgname_info(const char *pkgid)
{
	pkginfo *info = NULL;
	int ret = 0;
	char *packageid = NULL;
	char *version = NULL;
	pkgmgrinfo_pkginfo_h handle = NULL;

	if (pkgid == NULL) {
		_LOGE("pkgid is NULL.\n");
		return NULL;
	}

	info = malloc(sizeof(pkginfo));
	if (info == NULL) {
		_LOGE("malloc failed.\n");
		return NULL;
	}

	ret = pkgmgrinfo_pkginfo_get_pkginfo(pkgid, &handle);
	if (ret != PMINFO_R_OK || handle == NULL) {
		_LOGE("fisrt installation, pkgid=[%s]", pkgid);
		free(info);
		return NULL;
	}

	ret = pkgmgrinfo_pkginfo_get_pkgid(handle, &packageid);
	if (ret != PMINFO_R_OK) {
		_LOGE("failed to get the pkgid.\n");
		goto err;
	}
	strncpy(info->package_name, packageid, sizeof(info->package_name) - 1);

	ret = pkgmgrinfo_pkginfo_get_version(handle, &version);
	if (ret != PMINFO_R_OK) {
		_LOGE("failed to get the version.\n");
		goto err;
	}
	strncpy(info->version, version, sizeof(info->version) - 1);

	pkgmgrinfo_pkginfo_destroy_pkginfo(handle);

	_LOGD("pkgid=[%s], version=[%s]", info->package_name, info->version);

	return info;

err:
	if (info) {
		free(info);
		info = NULL;
	}
	pkgmgrinfo_pkginfo_destroy_pkginfo(handle);
	return NULL;
}

int _rpm_installer_corexml_install(const char *pkgfilepath)
{
	/* Get package ID from filepath <pkgid.xml> */
	char *p = NULL;
	char *q = NULL;
	char *temp = NULL;
	int ret = 0;
	int idx = 0;
	temp = strdup(pkgfilepath);
	if (temp == NULL)
		return RPM_INSTALLER_ERR_NOT_ENOUGH_MEMORY;
	p = strrchr(temp, '/');
	if (p) {
		p++;
	} else {
		free(temp);
		return RPM_INSTALLER_ERR_INTERNAL;
	}
	/*p now points to pkgid.xml */
	q = strrchr(p, '.');
	if (q == NULL) {
		_LOGE("Failed to extract pkgid from xml name\n");
		free(temp);
		return RPM_INSTALLER_ERR_INTERNAL;
	}
	idx = strlen(p) - strlen(q);
	p[idx] = '\0';
	_LOGD("package id is [%s]", p);
	ret = _rpm_install_corexml(pkgfilepath, p);
	free(temp);
	return ret;
}

int _rpm_installer_package_install(char *pkgfilepath, bool forceinstall, char *installoptions, char *clientid)
{
	int err = 0;
	char *p = NULL;
	if (forceinstall == true && installoptions == NULL)
		return RPM_INSTALLER_ERR_WRONG_PARAM;

	/* Check for core xml installation */
	p = strrchr(pkgfilepath, '.');
	if (p) {
		if (strncmp(p + 1, "xml", 3) == 0) {
			err = _rpm_installer_corexml_install(pkgfilepath);
			if (err) {
				_LOGE("_rpm_installer_corexml_install() failed\n");
			} else {
				_LOGE("_rpm_installer_corexml_install() success\n");
			}
			return err;
		}
	} else {
		_LOGE("pkgfilepath does not have an extension\n");
		return RPM_INSTALLER_ERR_INTERNAL;
	}

	/* rpm installation */
	pkginfo *info = NULL;
	pkginfo *tmpinfo = NULL;
	/*Check to see if the package is already installed or not
	   If it is installed, compare the versions. If the current version
	   is higher than the installed version, upgrade it automatically
	   else ask for user confirmation before downgrading */

	info = _rpm_installer_get_pkgfile_info(pkgfilepath);
	if (info == NULL) {
		/* failed to get pkg info */
		return RPM_INSTALLER_ERR_INTERNAL;
	}

	_ri_set_backend_state_info(GOT_PACKAGE_INFO_SUCCESSFULLY);
	_ri_save_last_input_info(pkgfilepath, INSTALL_CMD, 0);
	if (gpkgname) {
		free(gpkgname);
		gpkgname = NULL;
	}
	gpkgname = strdup(info->package_name);
	if (gpkgname == NULL) {
		_LOGE("Malloc failed!!");
		if (info) {
			free(info);
			info = NULL;
		}
		return RPM_INSTALLER_ERR_INTERNAL;
	}

	tmpinfo = _rpm_installer_get_pkgname_info(info->package_name);
	if (tmpinfo == NULL) {
		_LOGD("tmpinfo is null.\n");

		/* package is not installed. Go for installation. */
		if (info) {
			free(info);
			info = NULL;
		}

		err = _rpm_install_pkg_with_dbpath(pkgfilepath, gpkgname, clientid);
		if (err != 0) {
			_LOGE("install complete with error(%d)\n", err);
			return err;
		} else {
			_ri_set_backend_state_info(REQUEST_COMPLETED);
			return RPM_INSTALLER_SUCCESS;
		}
	} else if (strcmp(info->version, tmpinfo->version) > 0) {
		/*upgrade */
		_LOGD("[upgrade] %s, %s\n", info->version, tmpinfo->version);

		err = _rpm_upgrade_pkg_with_dbpath(pkgfilepath, gpkgname);
		if (err != 0) {
			_LOGE("upgrade complete with error(%d)\n", err);
			if (info) {
				free(info);
				info = NULL;
			}
			if (tmpinfo) {
				free(tmpinfo);
				tmpinfo = NULL;
			}
			return err;
		} else {
			_ri_set_backend_state_info(REQUEST_COMPLETED);
			if (info) {
				free(info);
				info = NULL;
			}
			if (tmpinfo) {
				free(tmpinfo);
				tmpinfo = NULL;
			}
			return RPM_INSTALLER_SUCCESS;
		}
	} else if (strcmp(info->version, tmpinfo->version) < 0) {
		_LOGD("[down grade] %s, %s\n", info->version, tmpinfo->version);

		err = _rpm_upgrade_pkg_with_dbpath(pkgfilepath, gpkgname);
		if (err != 0) {
			_LOGE("upgrade complete with error(%d)\n", err);
			if (info) {
				free(info);
				info = NULL;
			}
			if (tmpinfo) {
				free(tmpinfo);
				tmpinfo = NULL;
			}
			return err;
		} else {
			_ri_set_backend_state_info(REQUEST_COMPLETED);
			if (info) {
				free(info);
				info = NULL;
			}
			if (tmpinfo) {
				free(tmpinfo);
				tmpinfo = NULL;
			}
			return RPM_INSTALLER_SUCCESS;
		}
	} else {
		/*same package. Reinstall it. Manifest should be parsed again */
		_LOGD("[same pkg] %s, %s\n", info->package_name, info->version);

		err = _rpm_upgrade_pkg_with_dbpath(pkgfilepath, gpkgname);
		if (err != 0) {
			_LOGE("upgrade complete with error(%d)\n", err);
			if (info) {
				free(info);
				info = NULL;
			}
			if (tmpinfo) {
				free(tmpinfo);
				tmpinfo = NULL;
			}
			return err;
		} else {
			_ri_set_backend_state_info(REQUEST_COMPLETED);
			if (info) {
				free(info);
				info = NULL;
			}
			if (tmpinfo) {
				free(tmpinfo);
				tmpinfo = NULL;
			}
			return RPM_INSTALLER_SUCCESS;
		}
	}

	return RPM_INSTALLER_SUCCESS;
}

int _rpm_installer_package_install_with_dbpath(char *pkgfilepath, char *clientid)
{
	int ret = 0;
	pkginfo *info = NULL;
	pkginfo *tmpinfo = NULL;

	/*Check to see if the package is already installed or not
	   If it is installed, compare the versions. If the current version
	   is higher than the installed version, upgrade it automatically
	   else ask for user confirmation before downgrading */

	_LOGD("[##]start : _rpm_installer_package_install_with_dbpath\n");

	info = _rpm_installer_get_pkgfile_info(pkgfilepath);
	if (info == NULL) {
		_LOGE("@Failed to get pkg info.\n");
		/* failed to get pkg info */
		return RPM_INSTALLER_ERR_INTERNAL;
	}

	_ri_set_backend_state_info(GOT_PACKAGE_INFO_SUCCESSFULLY);
	_ri_save_last_input_info(info->package_name, EFLWGT_INSTALL_CMD, 0);
	if (gpkgname) {
		free(gpkgname);
		gpkgname = NULL;
	}
	gpkgname = strdup(info->package_name);
	if (gpkgname == NULL) {
		_LOGE("Malloc failed!!");
		if (info) {
			free(info);
			info = NULL;
		}
		return RPM_INSTALLER_ERR_INTERNAL;
	}

	tmpinfo = _rpm_installer_get_pkgname_info(info->package_name);
	if (tmpinfo == NULL) {
		/* package is not installed. Go for installation. */
		_LOGD("#package is not installed. Go for installation\n");
		ret = _rpm_install_pkg_with_dbpath(pkgfilepath, info->package_name, clientid);

	} else if (strcmp(info->version, tmpinfo->version) > 0) {
		/*upgrade */
		_LOGD("#package is installed. Go for upgrade\n");
		ret = _rpm_upgrade_pkg_with_dbpath(pkgfilepath, info->package_name);
	} else if (strcmp(info->version, tmpinfo->version) < 0) {
		/*downgrade */
		_LOGD("#package is installed. Go for upgrade\n");
		ret = _rpm_upgrade_pkg_with_dbpath(pkgfilepath, info->package_name);

	} else {
		/*same package. Reinstall it. Manifest should be parsed again */
		_LOGD("#package is same. Go for reinstall(upgrade)\n");
		ret = _rpm_upgrade_pkg_with_dbpath(pkgfilepath, info->package_name);
	}

	if (info) {
		free(info);
		info = NULL;
	}
	if (tmpinfo) {
		free(tmpinfo);
		tmpinfo = NULL;
	}

	if (ret != 0) {
		_LOGE("[@@]end : _rpm_installer_package_install_with_dbpath(%d)\n", ret);
	} else {
		_LOGD("[##]end : _rpm_installer_package_install_with_dbpath \n");
	}

	return ret;
}

int _rpm_installer_package_uninstall_with_dbpath(const char *pkgid)
{
	return _rpm_uninstall_pkg_with_dbpath(pkgid, 0);
}

int _rpm_installer_package_uninstall(char *pkgid)
{
	int ret = 0;

	_LOGD("start : _rpm_installer_package_uninstall\n");

	pkginfo *tmppkginfo = _rpm_installer_get_pkgname_info(pkgid);
	if (tmppkginfo == NULL) {
		_LOGE("tmppkginfo is NULL.\n");
		return RPM_INSTALLER_ERR_PACKAGE_NOT_INSTALLED;
	}
	if (tmppkginfo) {
		free(tmppkginfo);
		tmppkginfo = NULL;
	}
#ifndef SEND_PKGPATH
	if (gpkgname) {
		free(gpkgname);
		gpkgname = NULL;
	}

	gpkgname = strdup(pkgid);
	/* _ri_broadcast_status_notification(pkgid, "command", "Uninstall"); */
#endif
	_ri_set_backend_state_info(GOT_PACKAGE_INFO_SUCCESSFULLY);
	_ri_save_last_input_info(pkgid, DELETE_CMD, 0);
	ret = _rpm_uninstall_pkg(pkgid);

	_ri_set_backend_state_info(REQUEST_COMPLETED);

	_LOGD("end : _rpm_installer_package_uninstall(%d)\n", ret);

	return ret;
}

int _rpm_installer_clear_private_data(char *pkgid)
{
	if (pkgid == NULL)
		return RPM_INSTALLER_ERR_WRONG_PARAM;
	char dir_path[BUF_SIZE] = { '\0' };
	int ret = -1;
	snprintf(dir_path, BUF_SIZE-1, "%s/%s/data/", OPT_USR_APPS, pkgid);
	ret = _ri_recursive_delete_dir(dir_path);
	return ret;
}
