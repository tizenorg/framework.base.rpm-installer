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

#ifndef __RPM_INSTALLER_H_
#define __RPM_INSTALLER_H_

#ifdef __cplusplus
extern "C" {
#endif				/* __cplusplus */

#include "rpm-installer-util.h"
#include <stdbool.h>

#define PM_UNLIKELY(expr) __builtin_expect((expr), 0)
#define PM_LIKELY(expr) __builtin_expect((expr), 1)

	enum backend_state {
		REQUEST_ACCEPTED = 1,
		GOT_PACKAGE_INFO_SUCCESSFULLY,
		REQUEST_PENDING,
		REQUEST_COMPLETED
	};
	typedef enum backend_state backend_state;
	struct pkginfo_t {
		char package_name[128];
		char version[11];
	};

	typedef struct pkginfo_t pkginfo;

/**
 * Install the package
 * @in :pkgfilepath : Package file path
 * @in :force_install: Whether we need to forceful overwrite.
 *	   If package already installed then reinstall the application
 * @in :install_options: install options
 */
	int _rpm_installer_package_install(char *pkgfilepath,
					   bool force_install,
					   char *install_options);

/**
 * Install the package manifest
 * @in :pkgfilepath : Package manifest file path
 */
	int _rpm_installer_corexml_install(char *pkgfilepath);
/**
 * get the package information from package name
 * return the package information
 * @in :pkgid : package id for which information is requested
 */
	pkginfo *_rpm_installer_get_pkgname_info(char *pkgid);

/**
 * get the package information from package file
 * return the package information
 * @in :pkgfile : package file for which information is requested
 */
	pkginfo *_rpm_installer_get_pkgfile_info(char *pkgfile);

/**
 * Uninstall the Application
 * @in :pkgid : package id to be uninstalled
 */
	int _rpm_installer_package_uninstall(char *pkgid);

/* Dbus related prototype */
	void _ri_broadcast_status_notification(char *pkgid, char *key,
					       char *val);
	int _rpm_backend_interface(char *keyid, char *pkgid,
				   char *reqcommand);

/* RPM operations prototype */
	int _rpm_uninstall_pkg(char *pkgid);
	int _rpm_install_pkg(char *pkgfilepath, char *installoptions);
	int _rpm_upgrade_pkg(char *pkgfilepath, char *installoptions);
	int _rpm_install_corexml(char *pkgfilepath, char *pkgid);
	int _ri_set_backend_state(int state);
	int _ri_get_backend_state();
	int _ri_get_backend_state_info();
	int _ri_set_backend_state_info(int state);
	int _ri_get_last_input_info(char **pkgid, int *preqcommand,
				    int *poptions);
	void _ri_save_last_input_info(char *pkgid, int reqcommand,
				      int options);
	void _ri_package_downgrade_information(const char *message);
	int _rpm_installer_clear_private_data(char *pkgid);
	int _rpm_move_pkg(char *pkgid, int move_type);

/* libprivilege-control specific operations prototype*/
	int _ri_privilege_register_package(const char *pkgid);
	int _ri_privilege_unregister_package(const char *pkgid);
	int _ri_privilege_revoke_permissions(const char *pkgid);
	int _ri_privilege_enable_permissions(const char *pkgid, int apptype,
						const char **perms, int persistent);
	int _ri_privilege_setup_path(const char *pkgid, const char *dirpath,
						int apppathtype, const char *groupid);
	int _ri_privilege_add_friend(const char *pkgid1, const char *pkgid2);
	int _ri_privilege_change_smack_label(const char *path, const char *label,
						int label_type);
	int _ri_verify_sig_and_cert(const char *sigfile);
	void _ri_unregister_cert(const char *pkgid);
	void _ri_register_cert(const char *pkgid);
	void _ri_apply_smack(char *pkgname, int flag);


#ifdef __cplusplus
}
#endif				/* __cplusplus */
#endif				/* __RPM_INSTALLER_H_ */
