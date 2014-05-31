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
#include "rpm-installer-type.h"
#include "rpm-installer-util.h"
#include "db-util.h"

#define QUERY_PACKAGE		"/usr/bin/query_rpm_package.sh"
#define RPM_PKG_INFO			"/var/rpmpkg.info"

extern char *gpkgname;
extern int do_upgrade;
static int __ri_recursive_delete_dir(char *dirname);

static int __ri_recursive_delete_dir(char *dirname)
{
	int ret=0;
	DIR *dp;
	struct dirent *ep;
	char abs_filename[FILENAME_MAX];
	struct stat stFileInfo;
	dp = opendir(dirname);
	if (dp != NULL) {
		while ((ep = readdir(dp))) {
			snprintf(abs_filename, FILENAME_MAX, "%s/%s", dirname,
				 ep->d_name);
			if (lstat(abs_filename, &stFileInfo) < 0)
				perror(abs_filename);
			if (S_ISDIR(stFileInfo.st_mode)) {
				if (strcmp(ep->d_name, ".") &&
				    strcmp(ep->d_name, "..")) {
					ret=__ri_recursive_delete_dir(abs_filename);
					if(ret < 0)
						_d_msg(DEBUG_ERR, "__ri_recursive_delete_dir fail\n");

					ret=remove(abs_filename);
					if(ret < 0)
						_d_msg(DEBUG_ERR, "remove fail\n");
				}
			} else {
				ret = remove(abs_filename);
				if(ret < 0)
					_d_msg(DEBUG_ERR, "Couldn't remove abs_filename\n");
			}
		}
		(void)closedir(dp);
	} else {
		_d_msg(DEBUG_ERR, "Couldn't open the directory\n");
		if (errno == ENOENT)
			return RPM_INSTALLER_SUCCESS;
		else
			return RPM_INSTALLER_ERR_CLEAR_DATA_FAILED;
	}

	return RPM_INSTALLER_SUCCESS;
}

int __rpm_xsystem(const char *argv[])
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

char* _manifest_to_package(const char* manifest)
{
	char *package;

	if(manifest == NULL) {
		_d_msg(DEBUG_ERR, "manifest is NULL.\n");
		return NULL;
	}

	package = strdup(manifest);
	if(package == NULL) {
		_d_msg(DEBUG_ERR, "strdup failed.\n");
		return NULL;
	}

	if (!strstr(package, ".xml")) {
		_d_msg(DEBUG_ERR, "%s is not a manifest file\n", manifest);
		free(package);
		return NULL;
	}

	return package;
}

char* _rpm_load_directory(char *directory)
{
	DIR *dir;
	struct dirent entry, *result;
	int ret;
	char *buf = NULL;

	buf = malloc(BUF_SIZE);
	if (buf == NULL) {
		_d_msg(DEBUG_ERR, "malloc failed.\n");
		return NULL;
	}

	dir = opendir(directory);
	if (!dir) {
		if (strerror_r(errno, buf, BUF_SIZE) == 0)
		_d_msg(DEBUG_ERR, "Can not access to the [%s] because %s.\n", directory, buf);
		free(buf);
		return NULL;
	}

	_d_msg(DEBUG_INFO, "Loading manifest files from %s\n", directory);

	for (ret = readdir_r(dir, &entry, &result);
			ret == 0 && result != NULL;
			ret = readdir_r(dir, &entry, &result)) {
		char *manifest;

		if (!strcmp(entry.d_name, ".") ||
			!strcmp(entry.d_name, "..")) {
			continue;
		}

		manifest = _manifest_to_package(entry.d_name);
		if (!manifest) {
			_d_msg(DEBUG_ERR, "Failed to convert file to xml[%s].\n", entry.d_name);
			continue;
		}

		snprintf(buf, BUF_SIZE, "%s/%s", directory, manifest);
		free(manifest);
	}

	closedir(dir);

	return buf;
}

int __rpm_delete_dir(char *dirname)
{
	int ret = 0;
	DIR *dp;
	struct dirent *ep;
	char abs_filename[FILENAME_MAX];
	struct stat stFileInfo;
	dp = opendir(dirname);
	if (dp != NULL) {
		while ((ep = readdir(dp))) {
			snprintf(abs_filename, FILENAME_MAX, "%s/%s", dirname, ep->d_name);
			if (lstat(abs_filename, &stFileInfo) < 0) {
				perror(abs_filename);
			}
			if (S_ISDIR(stFileInfo.st_mode)) {
				if (strcmp(ep->d_name, ".") && strcmp(ep->d_name, "..")) {
					__rpm_delete_dir(abs_filename);
					(void)remove(abs_filename);
				}
			} else {
				(void)remove(abs_filename);
			}
		}
		(void)closedir(dp);
	} else {
		_d_msg(DEBUG_ERR, "Couldn't open the directory\n");
		return -1;
	}
	ret = remove(dirname);
	if (ret < 0) {
		_d_msg(DEBUG_ERR, "remove fail dirname[%s]\n", dirname);
	}

	return 0;
}

pkginfo *_rpm_installer_get_pkgfile_info(char *pkgfile)
{
	pkginfo *info = NULL;
	manifest_x *mfx = NULL;
	int ret = 0;
	int m_exist = 0;
	char cwd[BUF_SIZE] = {'\0'};
	char buff[BUF_SIZE] = {'\0'};
	char manifest[BUF_SIZE] = { '\0'};

	getcwd(cwd, BUF_SIZE);
	if (cwd[0] == '\0') {
		_d_msg(DEBUG_ERR, "getcwd() failed.\n");
		return NULL;
	}

	ret = mkdir(TEMP_DIR, 0644);
	if (ret < 0) {
		if (access(TEMP_DIR, F_OK) == 0) {
			__rpm_delete_dir(TEMP_DIR);
			ret = mkdir(TEMP_DIR, 0644);
			if (ret < 0) {
				_d_msg(DEBUG_ERR, "mkdir() failed.\n");
				return NULL;
			}
		} else {
			_d_msg(DEBUG_ERR, "mkdir() failed.\n");
			return NULL;
		}
	}

	ret = chdir(TEMP_DIR);
	if (ret != 0) {
		_d_msg(DEBUG_ERR, "chdir(%s) failed [%s].\n", TEMP_DIR, strerror(errno));
		goto err;
	}

	_d_msg(DEBUG_INFO, "switched to %s\n", TEMP_DIR);

	const char *cpio_argv[] = { CPIO_SCRIPT, pkgfile, NULL };
	ret = __rpm_xsystem(cpio_argv);

	snprintf(manifest, BUF_SIZE, "%s/opt/share/packages", TEMP_DIR);
	char* manifestpath = _rpm_load_directory(manifest);
	if (manifestpath != NULL) {
		strncpy(buff, manifestpath, sizeof(buff) - 1);
		free(manifestpath);
	}

	if (buff[0] == '\0') {
		snprintf(manifest, BUF_SIZE, "%s/usr/share/packages", TEMP_DIR);
		manifestpath = _rpm_load_directory(manifest);
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

	if (m_exist) {

		_d_msg(DEBUG_INFO, "The path of manifest.xml is %s.\n", buff);

		info = malloc(sizeof(pkginfo));
		if (info == NULL) {
			_d_msg(DEBUG_ERR, "malloc failed.\n");
			goto err;
		}

		/*get package name from xml*/
		mfx = pkgmgr_parser_process_manifest_xml(buff);
		if (mfx) {
			strncpy(info->package_name, mfx->package, sizeof(info->package_name) - 1);
			strncpy(info->version, mfx->version, sizeof(info->version) - 1);
			_d_msg(DEBUG_INFO, "_rpm_installer_get_pkgfile_info, pkgname: (%s), version(%s)\n", info->package_name, info->version);
		}
		pkgmgr_parser_free_manifest_xml(mfx);
	}

err:
	__rpm_delete_dir(TEMP_DIR);

	ret = chdir(cwd);
	if (ret != 0) {
		_d_msg(DEBUG_ERR, "chdir(%s) failed [%s].\n", cwd, strerror(errno));
	}

	return info;
}

pkginfo *_rpm_installer_get_pkgname_info(char *pkgid)
{
	pkginfo *info = NULL;
	int ret = 0;
	char *packageid = NULL;
	char *version = NULL;
	pkgmgrinfo_pkginfo_h handle = NULL;

	if (pkgid == NULL) {
		_d_msg(DEBUG_ERR, "pkgid is NULL.\n");
		return NULL;
	}

	info = malloc(sizeof(pkginfo));
	if (info == NULL) {
		_d_msg(DEBUG_ERR, "malloc failed.\n");
		return NULL;
	}

	ret = pkgmgrinfo_pkginfo_get_pkginfo(pkgid, &handle);
	if (ret != PMINFO_R_OK || &handle == NULL) {
		_d_msg(DEBUG_ERR, "There is no old version for %s.\n", pkgid);
		free(info);
		return NULL;
	}

	ret = pkgmgrinfo_pkginfo_get_pkgid(handle, &packageid);
	if (ret != PMINFO_R_OK) {
		_d_msg(DEBUG_ERR, "Failed to get the pkgid.\n");
		goto err;
	}
	strncpy(info->package_name, packageid, sizeof(info->package_name) - 1);

	ret = pkgmgrinfo_pkginfo_get_version(handle, &version);
	if (ret != PMINFO_R_OK) {
		_d_msg(DEBUG_ERR, "Failed to get the version.\n");
		goto err;
	}
	strncpy(info->version, version, sizeof(info->version) - 1);

	pkgmgrinfo_pkginfo_destroy_pkginfo(handle);

	_d_msg(DEBUG_INFO, "_rpm_installer_get_pkgname_info, pkgname: (%s), version(%s)\n", info->package_name, info->version);

	return info;

err:
	free(info);
	pkgmgrinfo_pkginfo_destroy_pkginfo(handle);
	return NULL;
}

int _rpm_installer_corexml_install(char *pkgfilepath)
{
	/* Get package ID from filepath <pkgid.xml>*/
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
	/*p now points to pkgid.xml*/
	q = strrchr(p, '.');
	if (q == NULL) {
		_d_msg(DEBUG_ERR, "Failed to extract pkgid from xml name\n");
		free(temp);
		return RPM_INSTALLER_ERR_INTERNAL;
	}
	idx = strlen(p) - strlen(q);
	p[idx] = '\0';
	_d_msg(DEBUG_INFO, "Package ID is %s\n", p);
	ret = _rpm_install_corexml(pkgfilepath, p);
	free(temp);
	return ret;
}

int _rpm_installer_package_install(char *pkgfilepath, bool forceinstall,
				   char *installoptions)
{
	int err = 0;
	char *p = NULL;
	if (forceinstall == true && installoptions == NULL)
		return RPM_INSTALLER_ERR_WRONG_PARAM;

	/* Check for core xml installation */
	p = strrchr(pkgfilepath, '.');
	if (p) {
		if (strncmp(p+1, "xml", 3) == 0) {
			err = _rpm_installer_corexml_install(pkgfilepath);
			if (err) {
				_d_msg(DEBUG_ERR, "_rpm_installer_corexml_install() failed\n");
			} else {
				_d_msg(DEBUG_ERR, "_rpm_installer_corexml_install() success\n");
			}
			return err;
		}
	} else {
		_d_msg(DEBUG_ERR, "pkgfilepath does not have an extension\n");
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
	if (gpkgname) {
		free(gpkgname);
		gpkgname = NULL;
	}
	gpkgname = strdup(info->package_name);

	tmpinfo = _rpm_installer_get_pkgname_info(info->package_name);
	if (tmpinfo == NULL) {
		_d_msg(DEBUG_INFO, "tmpinfo is null.\n");

		/* package is not installed. Go for installation. */
		if (info) {
			free(info);
			info = NULL;
		}
		_ri_broadcast_status_notification(info->package_name, "start", "install");

		err = _rpm_install_pkg(pkgfilepath, installoptions);
		if (err != 0) {
			_d_msg(DEBUG_ERR,
			       "install complete with error(%d)\n", err);
			return err;
		} else {
			_ri_set_backend_state_info(REQUEST_COMPLETED);
			return RPM_INSTALLER_SUCCESS;
		}
	} else if (strcmp(info->version, tmpinfo->version) > 0) {
		/*upgrade */

		_d_msg(DEBUG_INFO, "[upgrade] %s, %s\n", info->version, tmpinfo->version);

		_ri_broadcast_status_notification(info->package_name, "start", "update");

		err = _rpm_upgrade_pkg(pkgfilepath, "--force");
		if (err != 0) {
			_d_msg(DEBUG_ERR,
			       "upgrade complete with error(%d)\n", err);
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
		/*show popup and confirm from user */

		_d_msg(DEBUG_INFO, "[down grade] %s, %s\n", info->version, tmpinfo->version);

		switch (do_upgrade) {
		case -1:
			_ri_set_backend_state_info(REQUEST_PENDING);
			if (info) {
				free(info);
				info = NULL;
			}
			if (tmpinfo) {
				free(tmpinfo);
				tmpinfo = NULL;
			}
			return RPM_INSTALLER_ERR_NEED_USER_CONFIRMATION;
		case 0:
			/*return */
			if (info) {
				free(info);
				info = NULL;
			}
			if (tmpinfo) {
				free(tmpinfo);
				tmpinfo = NULL;
			}
			_ri_set_backend_state_info(REQUEST_COMPLETED);
			return RPM_INSTALLER_ERR_PACKAGE_NOT_UPGRADED;
		case 1:
			/*continue with downgrade */
			_ri_set_backend_state_info
			    (GOT_PACKAGE_INFO_SUCCESSFULLY);

			_ri_broadcast_status_notification(info->package_name, "start", "update");

			err = _rpm_upgrade_pkg(pkgfilepath, "--force");
			if (err != 0) {
				_d_msg(DEBUG_ERR,
				       "upgrade complete with error(%d)\n",
				       err);
				if (info) {
					free(info);
					info = NULL;
				}
				if (tmpinfo) {
					free(tmpinfo);
					tmpinfo = NULL;
				}
				return err;
			}
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

		_d_msg(DEBUG_INFO, "[same pkg] %s, %s\n", info->package_name, info->version);

		_ri_broadcast_status_notification(info->package_name, "start", "update");

		err = _rpm_upgrade_pkg(pkgfilepath, "--force");
		if (err != 0) {
			_d_msg(DEBUG_ERR,
			       "upgrade complete with error(%d)\n", err);
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

int _rpm_installer_package_install_with_dbpath(char *pkgfilepath)
{
	int ret = 0;
	pkginfo *info = NULL;
	pkginfo *tmpinfo = NULL;

	/*Check to see if the package is already installed or not
	   If it is installed, compare the versions. If the current version
	   is higher than the installed version, upgrade it automatically
	   else ask for user confirmation before downgrading */

	_d_msg(DEBUG_INFO, "[##]start : _rpm_installer_package_install_with_dbpath\n");

	info = _rpm_installer_get_pkgfile_info(pkgfilepath);
	if (info == NULL) {
		_d_msg(DEBUG_ERR, "@Failed to get pkg info.\n");
		/* failed to get pkg info */
		return RPM_INSTALLER_ERR_INTERNAL;
	}

	_ri_set_backend_state_info(GOT_PACKAGE_INFO_SUCCESSFULLY);

	tmpinfo = _rpm_installer_get_pkgname_info(info->package_name);
	if (tmpinfo == NULL) {
		/* package is not installed. Go for installation. */
		_d_msg(DEBUG_INFO, "#package is not installed. Go for installation\n");
		ret = _rpm_install_pkg_with_dbpath(pkgfilepath, info->package_name);

	} else if (strcmp(info->version, tmpinfo->version) > 0) {
		/*upgrade */
		_d_msg(DEBUG_INFO, "#package is installed. Go for upgrade\n");
		ret = _rpm_upgrade_pkg_with_dbpath(pkgfilepath, info->package_name);

	} else {
		/*same package. Reinstall it. Manifest should be parsed again */
		_d_msg(DEBUG_INFO, "#package is same. Go for reinstall(upgrade)\n");
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
		_d_msg(DEBUG_ERR, "[@@]end : _rpm_installer_package_install_with_dbpath(%d)\n", ret);
	} else {
		_d_msg(DEBUG_INFO, "[##]end : _rpm_installer_package_install_with_dbpath \n");
	}

	return ret;
}

int _rpm_installer_package_uninstall_with_dbpath(char *pkgid)
{
	return _rpm_uninstall_pkg_with_dbpath(pkgid, 0);
}

int _rpm_installer_package_uninstall(char *pkgid)
{
	int ret = 0;

	_d_msg(DEBUG_INFO, "start : _rpm_installer_package_uninstall\n");

	pkginfo *tmppkginfo = _rpm_installer_get_pkgname_info(pkgid);
	if (tmppkginfo == NULL) {
		_d_msg(DEBUG_ERR, "tmppkginfo is NULL.\n");
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
//	_ri_broadcast_status_notification(pkgid, "command", "Uninstall");
#endif
	_ri_set_backend_state_info(GOT_PACKAGE_INFO_SUCCESSFULLY);
	ret = _rpm_uninstall_pkg(pkgid);

	_ri_set_backend_state_info(REQUEST_COMPLETED);

	_d_msg(DEBUG_INFO, "end : _rpm_installer_package_uninstall(%d)\n", ret);

	return ret;
}

int _rpm_installer_clear_private_data(char *pkgid)
{
	if (pkgid == NULL)
		return RPM_INSTALLER_ERR_WRONG_PARAM;
	char dir_path[BUF_SIZE] = { '\0' };
	int ret = -1;
	snprintf(dir_path, 255, "/opt/usr/apps/%s/data/", pkgid);
	ret = __ri_recursive_delete_dir(dir_path);
	return ret;
}
