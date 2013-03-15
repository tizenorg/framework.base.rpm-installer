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

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#define __USE_GNU
#include <sys/wait.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <wait.h>
#include <stdio.h>
#include <signal.h>
#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <glib.h>
#include <ctype.h>		/* for isspace () */
#include <pkgmgr-info.h>
#include <pkgmgr_parser.h>
#include <package-manager.h>

#include "rpm-installer-util.h"
#include "rpm-installer.h"
#include "rpm-frontend.h"

#define PRE_CHECK_FOR_MANIFEST
#define INSTALL_SCRIPT		"/usr/bin/install_rpm_package.sh"
#define UNINSTALL_SCRIPT	"/usr/bin/uninstall_rpm_package.sh"
#define UPGRADE_SCRIPT	"/usr/bin/upgrade_rpm_package.sh"
#define RPM2CPIO	"/usr/bin/rpm2cpio"

enum rpm_request_type {
	INSTALL_REQ,
	UNINSTALL_REQ,
	UPGRADE_REQ,
};

#define APP2EXT_ENABLE
#ifdef APP2EXT_ENABLE
#include <app2ext_interface.h>
#endif

typedef enum rpm_request_type rpm_request_type;
extern char *gpkgname;

static int __rpm_xsystem(const char *argv[]);
static void __rpm_process_line(char *line);
static void __rpm_perform_read(int fd);
static void __rpm_clear_dir_list(GList* dir_list);
static GList * __rpm_populate_dir_list();

static void __rpm_process_line(char *line)
{
	char *tok = NULL;
	tok = strtok(line, " ");
	if (tok) {
		if (!strncmp(tok, "%%", 2)) {
			tok = strtok(NULL, " ");
			if (tok) {
				_d_msg(DEBUG_INFO, "Install percentage is %s\n",
				       tok);
				_ri_broadcast_status_notification(gpkgname,
								  "install_percent",
								  tok);
				_ri_stat_cb(gpkgname, "install_percent", tok);
			}
			return;
		}
	}
	return;
}

static void __rpm_perform_read(int fd)
{
	char *buf_ptr = NULL;
	char *tmp_ptr = NULL;
	int size = 0;
	static char buffer[1024] = { 0, };
	static int buffer_position;

	size = read(fd, &buffer[buffer_position],
		    sizeof(buffer) - buffer_position);
	buffer_position += size;
	if (size <= 0)
		return;

	/* Process each line of the recieved buffer */
	buf_ptr = tmp_ptr = buffer;
	while ((tmp_ptr = (char *)memchr(buf_ptr, '\n',
					 buffer + buffer_position - buf_ptr)) !=
	       NULL) {
		*tmp_ptr = 0;
		__rpm_process_line(buf_ptr);
		/* move to next line and continue */
		buf_ptr = tmp_ptr + 1;
	}

	/*move the remaining bits at the start of the buffer
	   and update the buffer position */
	buf_ptr = (char *)memrchr(buffer, 0, buffer_position);
	if (buf_ptr == NULL)
		return;

	/* we have processed till the last \n which has now become
	   0x0. So we increase the pointer to next position */
	buf_ptr++;

	memmove(buffer, buf_ptr, buf_ptr - buffer);
	buffer_position = buffer + buffer_position - buf_ptr;
}

static int __rpm_xsystem(const char *argv[])
{
	int err = 0;
	int status = 0;
	pid_t pid;
	int pipefd[2];

	if (pipe(pipefd) == -1) {
		_d_msg(DEBUG_ERR, "pipe creation failed\n");
		return -1;
	}
	/*Read progress info via pipe */
	pid = fork();

	switch (pid) {
	case -1:
		_d_msg(DEBUG_ERR, "fork failed\n");
		return -1;
	case 0:
		/* child */
		{
			close(pipefd[0]);
			close(1);
			close(2);
			dup(pipefd[1]);
			dup(pipefd[1]);
			if (execvp(argv[0], (char *const *)argv) == -1) {
				_d_msg(DEBUG_ERR, "execvp failed\n");
			}
			_exit(100);
		}
	default:
		/* parent */
		break;
	}

	close(pipefd[1]);

	while ((err = waitpid(pid, &status, WNOHANG)) != pid) {
		if (err < 0) {
			if (errno == EINTR)
				continue;
			_d_msg(DEBUG_ERR, "waitpid failed\n");
			close(pipefd[0]);
			return -1;
		}

		int select_ret;
		fd_set rfds;
		struct timespec tv;
		FD_ZERO(&rfds);
		FD_SET(pipefd[0], &rfds);
		tv.tv_sec = 1;
		tv.tv_nsec = 0;
		select_ret =
		    pselect(pipefd[0] + 1, &rfds, NULL, NULL, &tv, NULL);
		if (select_ret == 0)
			continue;

		else if (select_ret < 0 && errno == EINTR)
			continue;
		else if (select_ret < 0) {
			_d_msg(DEBUG_ERR, "select() returned error\n");
			continue;
		}
		if (FD_ISSET(pipefd[0], &rfds))
			__rpm_perform_read(pipefd[0]);
	}

	close(pipefd[0]);
	/* Check for an error code. */
	if (WIFEXITED(status) == 0 || WEXITSTATUS(status) != 0) {

		if (WIFSIGNALED(status) != 0 && WTERMSIG(status) == SIGSEGV) {
			printf
			    ("Sub-process %s received a segmentation fault. \n",
			     argv[0]);
		} else if (WIFEXITED(status) != 0) {
			printf("Sub-process %s returned an error code (%u)\n",
			       argv[0], WEXITSTATUS(status));
		} else {
			printf("Sub-process %s exited unexpectedly\n", argv[0]);
		}
	}
	return WEXITSTATUS(status);
}

static void __rpm_clear_dir_list(GList* dir_list)
{
	GList *list = NULL;
	app2ext_dir_details* dir_detail = NULL;
	if (dir_list) {
		list = g_list_first(dir_list);
		while (list) {
			dir_detail = (app2ext_dir_details *)list->data;
			if (dir_detail && dir_detail->name) {
				free(dir_detail->name);
			}
			list = g_list_next(list);
		}
		g_list_free(dir_list);
	}
}

static GList * __rpm_populate_dir_list()
{
	GList *dir_list = NULL;
	GList *list = NULL;
	app2ext_dir_details* dir_detail = NULL;
	int i;
	char pkg_ro_content_rpm[3][5] = { "bin", "res", "lib" };


	for (i=0; i<3; i++) {
		dir_detail = (app2ext_dir_details*) calloc(1, sizeof(app2ext_dir_details));
		if (dir_detail == NULL) {
			printf("\nMemory allocation failed\n");
			goto FINISH_OFF;
		}
		dir_detail->name = (char*) calloc(1, sizeof(char)*(strlen(pkg_ro_content_rpm[i])+2));
		if (dir_detail->name == NULL) {
			printf("\nMemory allocation failed\n");
			free(dir_detail);
			goto FINISH_OFF;
		}
		snprintf(dir_detail->name, (strlen(pkg_ro_content_rpm[i])+1), "%s", pkg_ro_content_rpm[i]);
		dir_detail->type = APP2EXT_DIR_RO;
		dir_list = g_list_append(dir_list, dir_detail);
	}
	if (dir_list) {
		list = g_list_first(dir_list);
		while (list) {
			dir_detail = (app2ext_dir_details *)list->data;
			list = g_list_next(list);
		}
	}
	return dir_list;
FINISH_OFF:
	if (dir_list) {
		list = g_list_first(dir_list);
		while (list) {
			dir_detail = (app2ext_dir_details *)list->data;
			if (dir_detail && dir_detail->name) {
				free(dir_detail->name);
			}
			list = g_list_next(list);
		}
		g_list_free(dir_list);
	}
	return NULL;
}

static GList * __rpm_move_dir_list()
{
	GList *dir_list = NULL;
	GList *list = NULL;
	app2ext_dir_details* dir_detail = NULL;
	int i;
	char pkg_ro_content_rpm[3][5] = { "bin", "res", };


	for (i=0; i<3; i++) {
		dir_detail = (app2ext_dir_details*) calloc(1, sizeof(app2ext_dir_details));
		if (dir_detail == NULL) {
			printf("\nMemory allocation failed\n");
			goto FINISH_OFF;
		}
		dir_detail->name = (char*) calloc(1, sizeof(char)*(strlen(pkg_ro_content_rpm[i])+2));
		if (dir_detail->name == NULL) {
			printf("\nMemory allocation failed\n");
			free(dir_detail);
			goto FINISH_OFF;
		}
		snprintf(dir_detail->name, (strlen(pkg_ro_content_rpm[i])+1), "%s", pkg_ro_content_rpm[i]);
		dir_detail->type = APP2EXT_DIR_RO;
		dir_list = g_list_append(dir_list, dir_detail);
	}
	if (dir_list) {
		list = g_list_first(dir_list);
		while (list) {
			dir_detail = (app2ext_dir_details *)list->data;
			list = g_list_next(list);
		}
	}
	return dir_list;
FINISH_OFF:
	if (dir_list) {
		list = g_list_first(dir_list);
		while (list) {
			dir_detail = (app2ext_dir_details *)list->data;
			if (dir_detail && dir_detail->name) {
				free(dir_detail->name);
			}
			list = g_list_next(list);
		}
		g_list_free(dir_list);
	}
	return NULL;
}

int _rpm_uninstall_pkg(char *pkgid)
{
	int ret = 0;
	int err = 0;
	char buff[256] = {'\0'};
	pkgmgr_install_location location = 1;
	int size = -1;
#ifdef APP2EXT_ENABLE
	app2ext_handle *handle = NULL;
#endif
	char *manifest = NULL;
	pkgmgr_pkginfo_h pkghandle;
	const char *argv[] = { UNINSTALL_SCRIPT, pkgid, NULL };

#ifdef APP2EXT_ENABLE
	ret = pkgmgr_pkginfo_get_pkginfo(pkgid, &pkghandle);
	if (ret < 0) {
		_d_msg(DEBUG_ERR, "Failed to get pkginfo handle\n");
//		return RPM_INSTALLER_ERR_INTERNAL;
	} else {
		ret = pkgmgr_pkginfo_get_install_location(pkghandle, &location);
		if (ret < 0) {
			_d_msg(DEBUG_ERR, "Failed to get install location\n");
			pkgmgr_pkginfo_destroy_pkginfo(pkghandle);
			return RPM_INSTALLER_ERR_INTERNAL;
		}
		pkgmgr_pkginfo_destroy_pkginfo(pkghandle);
		if (location == PM_INSTALL_LOCATION_PREFER_EXTERNAL) {
			handle = app2ext_init(APP2EXT_SD_CARD);
			if (handle == NULL) {
				_d_msg(DEBUG_ERR, "app2ext init failed\n");
				return RPM_INSTALLER_ERR_INTERNAL;
			}
			if ((&(handle->interface) != NULL) && (handle->interface.pre_uninstall != NULL) && (handle->interface.post_uninstall != NULL)){
				ret = app2ext_get_app_location(pkgid);
				if (ret == APP2EXT_INTERNAL_MEM){
						_d_msg(DEBUG_ERR, "app2xt APP is not in MMC, go internal (%d)\n", ret);
				}
				else {
					ret = handle->interface.pre_uninstall(pkgid);
					if (ret == APP2EXT_ERROR_MMC_STATUS || ret == APP2EXT_SUCCESS ) {
						_d_msg(DEBUG_ERR, "app2xt MMC is not here, go internal (%d)\n", ret);
					}
					else {
						_d_msg(DEBUG_ERR, "app2xt pre uninstall API failed (%d)\n", ret);
						handle->interface.post_uninstall(pkgid);
						return RPM_INSTALLER_ERR_INTERNAL;
					}
				}
			}
		}
	}
#endif

#ifdef PRE_CHECK_FOR_MANIFEST
	/*Manifest info should be removed first because after installation manifest
	file is uninstalled. If uninstallation fails, we need to re-insert manifest info for consistency*/
	manifest = pkgmgr_parser_get_manifest_file(pkgid);
	if (manifest == NULL) {
		_d_msg(DEBUG_ERR, "manifest name is NULL\n");
		return RPM_INSTALLER_ERR_INTERNAL;
	}
	_d_msg(DEBUG_INFO, "manifest name is %s\n", manifest);
	pkgmgr_parser_parse_manifest_for_uninstallation(manifest, NULL);
#endif

	ret = __rpm_xsystem(argv);
	if (ret != 0) {
		_d_msg(DEBUG_ERR, "uninstall failed with error(%d)\n", ret);
		#ifdef PRE_CHECK_FOR_MANIFEST
		err = pkgmgr_parser_parse_manifest_for_installation(manifest, NULL);
		if (err < 0) {
			_d_msg(DEBUG_ERR, "Parsing Manifest Failed\n");
		}
		if (manifest) {
			free(manifest);
			manifest = NULL;
		}
		#endif
		#ifdef APP2EXT_ENABLE
		if ((handle != NULL) && (handle->interface.post_uninstall != NULL)){
			handle->interface.post_uninstall(pkgid);
		}
		#endif
		return ret;
	}

#ifdef APP2EXT_ENABLE
	if ((handle != NULL) && (handle->interface.post_uninstall != NULL)){
		handle->interface.post_uninstall(pkgid);
		app2ext_deinit(handle);
	}
#endif

#ifdef PRE_CHECK_FOR_MANIFEST
	if (manifest) {
		free(manifest);
		manifest = NULL;
	}
#endif
	/* Uninstallation Success. Remove the installation time key from vconf*/
	snprintf(buff, 256, "db/app-info/%s/installed-time", pkgid);
	err = vconf_unset(buff);
	if (err) {
		_d_msg(DEBUG_ERR, "unset installation time failed\n");
	}
	return ret;
}

int _rpm_install_pkg(char *pkgfilepath, char *installoptions)
{
	int err = 0;
	int ret = 0;
	time_t cur_time;
	char buff[256] = {'\0'};
	char manifest[1024] = { '\0'};
	char *mfst = NULL;
	pkgmgrinfo_install_location location = 1;
	int size = -1;
#ifdef APP2EXT_ENABLE
	app2ext_handle *handle = NULL;
	GList *dir_list = NULL;
#endif
	pkgmgr_pkginfo_h pkghandle;
	const char *argv[] = {
		INSTALL_SCRIPT, pkgfilepath, installoptions, NULL
	};

#ifdef PRE_CHECK_FOR_MANIFEST
	char cwd[1024] = {'\0'};
	char query[1024] = {'\0'};
	int m_exist = 0;
	getcwd(cwd, 1024);
	if (cwd[0] == '\0') {
		_d_msg(DEBUG_ERR, "getcwd() Failed\n");
		return RPM_INSTALLER_ERR_INTERNAL;
	}
	_d_msg(DEBUG_ERR, "Current working directory is %s\n", cwd);
	err = chdir("/tmp");
	if (err != 0) {
		_d_msg(DEBUG_ERR, "chdir() failed\n");
		return RPM_INSTALLER_ERR_INTERNAL;
	}
	_d_msg(DEBUG_ERR, "Switched to /tmp\n");
	snprintf(query, 1024, "/usr/bin/rpm2cpio %s | cpio -idmv", pkgfilepath);
	_d_msg(DEBUG_INFO, "query= %s\n", query);
	system(query);
	snprintf(manifest, 1024, "/tmp/opt/share/packages/%s.xml", gpkgname);
	_d_msg(DEBUG_ERR, "Manifest name is %s\n", manifest);
	if (access(manifest, F_OK)) {
		_d_msg(DEBUG_ERR, "No rw Manifest File Found\n");

		snprintf(manifest, 1024, "/tmp/usr/share/packages/%s.xml", gpkgname);
		_d_msg(DEBUG_ERR, "Manifest ro name is %s\n", manifest);

		if (access(manifest, F_OK)) {
			_d_msg(DEBUG_ERR, "No ro Manifest File Found\n");
//			unlink(manifest);
//			return RPM_INSTALLER_ERR_NO_MANIFEST;
		} else
			m_exist = 1;
	} else
		m_exist = 1;

	_d_msg(DEBUG_ERR, "Manifest exists\n");

	err = chdir(cwd);
	if (err != 0) {
		_d_msg(DEBUG_ERR, "chdir() failed\n");
//		unlink(manifest);
//		return RPM_INSTALLER_ERR_INTERNAL;
	}

	if (m_exist) {
		err = pkgmgr_parser_check_manifest_validation(manifest);
		if(err < 0) {
			_d_msg(DEBUG_ERR, "Invalid manifest\n");
			unlink(manifest);
			return RPM_INSTALLER_ERR_INVALID_MANIFEST;
		}
	}
#endif

#ifdef APP2EXT_ENABLE
	ret = pkgmgrinfo_pkginfo_get_location_from_xml(manifest, &location);

	if (ret < 0) {
		_d_msg(DEBUG_ERR, "Failed to get install location\n");
		return RPM_INSTALLER_ERR_INTERNAL;
	} else {
		if (location == PMINFO_INSTALL_LOCATION_PREFER_EXTERNAL) {
			ret = pkgmgrinfo_pkginfo_get_size_from_xml(manifest, &size);
			if (ret < 0) {
				_d_msg(DEBUG_ERR, "Failed to get package size\n");
				return RPM_INSTALLER_ERR_INTERNAL;
			}
		}
	}

	if ((location == PMINFO_INSTALL_LOCATION_PREFER_EXTERNAL) && size > 0) {
		handle = app2ext_init(APP2EXT_SD_CARD);
		if (handle == NULL) {
			_d_msg(DEBUG_ERR, "app2ext init failed\n");
			return RPM_INSTALLER_ERR_INTERNAL;
		}
		if ((&(handle->interface) != NULL) && (handle->interface.pre_install != NULL) && (handle->interface.post_install != NULL)){
			dir_list = __rpm_populate_dir_list();
			if (dir_list == NULL) {
				_d_msg(DEBUG_ERR, "\nError in populating the directory list\n");
				app2ext_deinit(handle);
				return RPM_INSTALLER_ERR_RPM_SCRIPT_WRONG_ARGS;
			}
			ret = handle->interface.pre_install(gpkgname, dir_list, size);
			if (ret == APP2EXT_ERROR_MMC_STATUS) {
				_d_msg(DEBUG_ERR, "app2xt MMC is not here, go internal\n");
			} else if (ret == APP2EXT_SUCCESS){
				_d_msg(DEBUG_ERR, "pre_install done, go internal\n");
			}
			else {
				_d_msg(DEBUG_ERR, "app2xt pre install API failed (%d)\n", ret);
				__rpm_clear_dir_list(dir_list);
				handle->interface.post_install(gpkgname, APP2EXT_STATUS_FAILED);
				app2ext_deinit(handle);
				return RPM_INSTALLER_ERR_INTERNAL;
			}
		}
	}
#endif

	err = __rpm_xsystem(argv);

	if (err != 0) {
		_d_msg(DEBUG_ERR, "install complete with error(%d)\n", err);

		#ifdef APP2EXT_ENABLE
		if ((handle != NULL) && (handle->interface.post_install != NULL)){
			__rpm_clear_dir_list(dir_list);
			handle->interface.post_install(gpkgname, APP2EXT_STATUS_FAILED);
		}
		#endif

		return err;
	}

#ifdef APP2EXT_ENABLE
	if ((handle != NULL) && (handle->interface.post_install != NULL)){
		__rpm_clear_dir_list(dir_list);
		handle->interface.post_install(gpkgname, APP2EXT_STATUS_SUCCESS);
		app2ext_deinit(handle);
	}
#endif

	/*Parse the manifest to get install location and size. If installation fails, remove manifest info from DB*/
	err = pkgmgr_parser_parse_manifest_for_installation(manifest, NULL);
	if (err < 0) {
		_d_msg(DEBUG_ERR, "Parsing Manifest Failed\n");
//		unlink(manifest);
//		return RPM_INSTALLER_ERR_INTERNAL;
	} else {
		_d_msg(DEBUG_ERR, "Parsing Manifest Success\n");
		return err;
	}

#ifndef PRE_CHECK_FOR_MANIFEST
	mfst = pkgmgr_parser_get_manifest_file(gpkgname);
	if (mfst == NULL) {
		_d_msg(DEBUG_ERR, "manifest name is NULL\n");
		unlink(manifest);
		return RPM_INSTALLER_ERR_INTERNAL;
	}
	pkgmgr_parser_parse_manifest_for_installation(mfst, NULL);
	if (mfst) {
		free(mfst);
		mfst = NULL;
	}
#endif
	/* Install Success. Store the installation time*/
	cur_time = time(NULL);
	snprintf(buff, 256, "db/app-info/%s/installed-time", gpkgname);
	/* The time is stored in time_t format. It can be converted to
	local time or GMT time as per the need by the apps*/
	ret = vconf_set_int(buff, cur_time);
	if(ret) {
		_d_msg(DEBUG_ERR, "setting installation time failed\n");
		vconf_unset(buff);
	}
	unlink(manifest);
	return err;
}

int _rpm_upgrade_pkg(char *pkgfilepath, char *installoptions)
{
	int err = 0;
	int ret = 0;
	time_t cur_time;
	char buff[256] = {'\0'};
	char manifest[1024] = { '\0'};
	char *mfst = NULL;
	pkgmgr_install_location location = 1;
	int size = -1;
#ifdef APP2EXT_ENABLE
	app2ext_handle *handle = NULL;
	GList *dir_list = NULL;
#endif
	pkgmgr_pkginfo_h pkghandle;
	const char *argv[] = {
		UPGRADE_SCRIPT, pkgfilepath, installoptions, NULL
	};

#ifdef PRE_CHECK_FOR_MANIFEST
	char cwd[1024] = {'\0'};
	char query[1024] = {'\0'};
	int m_exist = 0;
	getcwd(cwd, 1024);
	if (cwd[0] == '\0') {
		_d_msg(DEBUG_ERR, "getcwd() Failed\n");
		return RPM_INSTALLER_ERR_INTERNAL;
	}
	_d_msg(DEBUG_ERR, "Current working directory is %s\n", cwd);
	err = chdir("/tmp");
	if (err != 0) {
		_d_msg(DEBUG_ERR, "chdir() failed\n");
		return RPM_INSTALLER_ERR_INTERNAL;
	}
	_d_msg(DEBUG_ERR, "Switched to /tmp\n");
	snprintf(query, 1024, "/usr/bin/rpm2cpio %s | cpio -idmv", pkgfilepath);
	_d_msg(DEBUG_INFO, "query= %s\n", query);
	system(query);
	snprintf(manifest, 1024, "/tmp/opt/share/packages/%s.xml", gpkgname);
	_d_msg(DEBUG_ERR, "Manifest name is %s\n", manifest);
	if (access(manifest, F_OK)) {
		_d_msg(DEBUG_ERR, "No rw Manifest File Found\n");

		snprintf(manifest, 1024, "/tmp/usr/share/packages/%s.xml", gpkgname);
		_d_msg(DEBUG_ERR, "Manifest ro name is %s\n", manifest);

		if (access(manifest, F_OK)) {
			_d_msg(DEBUG_ERR, "No ro Manifest File Found\n");
//			unlink(manifest);
//			return RPM_INSTALLER_ERR_NO_MANIFEST;
		} else
			m_exist = 1;
	} else
		m_exist = 1;

	_d_msg(DEBUG_ERR, "Manifest exists\n");

	err = chdir(cwd);
	if (err != 0) {
		_d_msg(DEBUG_ERR, "chdir() failed\n");
//		unlink(manifest);
//		return RPM_INSTALLER_ERR_INTERNAL;
	}

	if (m_exist) {
		err = pkgmgr_parser_check_manifest_validation(manifest);
		if(err < 0) {
			_d_msg(DEBUG_ERR, "Invalid manifest\n");
			unlink(manifest);
			return RPM_INSTALLER_ERR_INVALID_MANIFEST;
		}
	}
	/*Parse the manifest to get install location and size. If upgradation fails, remove manifest info from DB*/
	err = pkgmgr_parser_parse_manifest_for_upgrade(manifest, NULL);
	if (err < 0) {
		_d_msg(DEBUG_ERR, "Parsing Manifest Failed\n");
//		unlink(manifest);
//		return RPM_INSTALLER_ERR_INTERNAL;
	} else {
		_d_msg(DEBUG_ERR, "Parsing Manifest Success\n");
	}
#endif

#ifdef APP2EXT_ENABLE
	ret = pkgmgr_pkginfo_get_pkginfo(gpkgname, &pkghandle);
	if (ret < 0) {
		_d_msg(DEBUG_ERR, "Failed to get pkginfo handle\n");
//		unlink(manifest);
//		return RPM_INSTALLER_ERR_INTERNAL;
	} else {
		ret = pkgmgr_pkginfo_get_install_location(pkghandle, &location);
		if (ret < 0) {
			_d_msg(DEBUG_ERR, "Failed to get install location\n");
			pkgmgr_pkginfo_destroy_pkginfo(pkghandle);
			unlink(manifest);
			return RPM_INSTALLER_ERR_INTERNAL;
		} else {
			if (location == PM_INSTALL_LOCATION_PREFER_EXTERNAL) {
				ret = pkgmgr_pkginfo_get_package_size(pkghandle, &size);
				if (ret < 0) {
					_d_msg(DEBUG_ERR, "Failed to get package size\n");
					pkgmgr_pkginfo_destroy_pkginfo(pkghandle);
					unlink(manifest);
					return RPM_INSTALLER_ERR_INTERNAL;
				}
			}
		}
		pkgmgr_pkginfo_destroy_pkginfo(pkghandle);
		if ((location == PM_INSTALL_LOCATION_PREFER_EXTERNAL) && size > 0) {
			handle = app2ext_init(APP2EXT_SD_CARD);
			if (handle == NULL) {
				_d_msg(DEBUG_ERR, "app2ext init failed\n");
				unlink(manifest);
				return RPM_INSTALLER_ERR_INTERNAL;
			}
			if ((&(handle->interface) != NULL) && (handle->interface.pre_upgrade != NULL) && (handle->interface.post_upgrade != NULL)){
				dir_list = __rpm_populate_dir_list();
				if (dir_list == NULL) {
					_d_msg(DEBUG_ERR, "\nError in populating the directory list\n");
					return RPM_INSTALLER_ERR_RPM_SCRIPT_WRONG_ARGS;
				}
				ret = handle->interface.pre_upgrade(gpkgname, dir_list, size);
				if (ret == APP2EXT_ERROR_MMC_STATUS || ret == APP2EXT_SUCCESS ) {
					_d_msg(DEBUG_ERR, "app2xt MMC is not here, go internal (%d)\n", ret);
				}
				else {
					_d_msg(DEBUG_ERR, "app2xt pre upgrade API failed (%d)\n", ret);
					__rpm_clear_dir_list(dir_list);
					handle->interface.post_upgrade(gpkgname, APP2EXT_STATUS_FAILED);
					unlink(manifest);
					return RPM_INSTALLER_ERR_INTERNAL;
				}
			}
		}
	}
#endif

	err = __rpm_xsystem(argv);
	if (err != 0) {
		_d_msg(DEBUG_ERR, "upgrade complete with error(%d)\n", err);
		/*remove manifest info*/
		#ifdef PRE_CHECK_FOR_MANIFEST
		pkgmgr_parser_parse_manifest_for_uninstallation(manifest, NULL);
		#endif
		#ifdef APP2EXT_ENABLE
		if ((handle != NULL) && (handle->interface.post_upgrade != NULL)){
			__rpm_clear_dir_list(dir_list);
			handle->interface.post_upgrade(gpkgname, APP2EXT_STATUS_FAILED);
		}
		#endif
		unlink(manifest);
		return err;
	}
#ifdef APP2EXT_ENABLE
	if ((handle != NULL) && (handle->interface.post_upgrade != NULL)){
		__rpm_clear_dir_list(dir_list);
		handle->interface.post_upgrade(gpkgname, APP2EXT_STATUS_SUCCESS);
		app2ext_deinit(handle);
	}
#endif
#ifndef PRE_CHECK_FOR_MANIFEST
	mfst = pkgmgr_parser_get_manifest_file(gpkgname);
	if (mfst == NULL) {
		_d_msg(DEBUG_ERR, "manifest name is NULL\n");
		unlink(manifest);
		return RPM_INSTALLER_ERR_INTERNAL;
	}
	pkgmgr_parser_parse_manifest_for_upgrade(mfst, NULL);
	if (mfst) {
		free(mfst);
		mfst = NULL;
	}
#endif
	unlink(manifest);
	return err;
}

int _rpm_move_pkg(char *pkgid, int move_type)
{
	app2ext_handle *hdl = NULL;
	int ret = 0;
	int movetype = -1;
	GList *dir_list = NULL;

	if (move_type == PM_MOVE_TO_INTERNAL)
		movetype = APP2EXT_MOVE_TO_PHONE;
	else if (move_type == PM_MOVE_TO_SDCARD)
		movetype = APP2EXT_MOVE_TO_EXT;
	else
		return RPM_INSTALLER_ERR_WRONG_PARAM;

	hdl = app2ext_init(APP2EXT_SD_CARD);
	if ((hdl != NULL) && (hdl->interface.move != NULL)){
		dir_list = __rpm_move_dir_list();
		if (dir_list == NULL) {
			_d_msg(DEBUG_ERR, "\nError in populating the directory list\n");
			return RPM_INSTALLER_ERR_RPM_SCRIPT_WRONG_ARGS;
		}
		ret = hdl->interface.move(pkgid, dir_list, movetype);
		__rpm_clear_dir_list(dir_list);
		if (ret != 0) {
			_d_msg(DEBUG_ERR, "Failed to move app\n");
			return RPM_INSTALLER_ERR_INTERNAL;
		}
		app2ext_deinit(hdl);
		return RPM_INSTALLER_SUCCESS;
	} else {
		_d_msg(DEBUG_ERR,"Failed to get app2ext handle\n");
		return RPM_INSTALLER_ERR_INTERNAL;
	}
}

