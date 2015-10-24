/*
 * coretpk-installer-internal
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

#ifndef __CORETPK_INSTALLER_INTERNAL_H_
#define __CORETPK_INSTALLER_INTERNAL_H_

#ifdef __cplusplus
extern "C" {
#endif				/* __cplusplus */

/*use pkginfo*/
#include "coretpk-installer.h"
#include "installer-type.h"


#ifdef _APPFW_FEATURE_MOUNT_INSTALL
#define TZIP_BUS_NAME "org.tizen.system.deviced"
#define TZIP_OBJECT_PATH "/Org/Tizen/System/DeviceD/Tzip"
#define TZIP_INTERFACE_NAME "org.tizen.system.deviced.Tzip"
#define TZIP_MOUNT_METHOD "Mount"
#define TZIP_UNMOUNT_METHOD "Unmount"
#define TZIP_IS_MOUNTED_METHOD "IsMounted"

#define TZIP_MOUNT_MAXIMUM_RETRY_CNT 15
#endif

int _coretpk_installer_package_reinstall(const char *dirpath, const char *clientid);

pkginfo *_coretpk_installer_get_pkgfile_info(const char *pkgfile, int cmd);

int _coretpk_installer_change_mode(const char* path, int mode);
int _coretpk_installer_change_file_owner(const char* path, int ownerid, int groupid);
int _coretpk_installer_change_directory_owner(const char* dirpath, int ownerid, int groupid);
int _coretpk_installer_make_directory_for_ext(const char *pkgid);
int _coretpk_installer_make_directory(const char *pkgid, bool preload);
int _coretpk_installer_apply_smack(const char *pkgname, int flag);
int _coretpk_installer_apply_privilege(const char *pkgid, const char *pkgPath, int apiVisibility);
void _coretpk_installer_search_ui_gadget(const char *pkgid);
int _coretpk_installer_set_smack_label_access(const char *path, const char *label);
int _coretpk_installer_get_smack_label_access(const char *path, char **label);
int _coretpk_installer_set_smack_label_transmute(const char *path, const char *flag);
int _coretpk_installer_remove_db_info(const char *pkgid);

int __coretpk_patch_trimmed_api_version(const char *api_version, char **trim_api_version);
int __coretpk_patch_padded_api_version(const char *api_version, char **pad_api_version);

int __coretpk_installer_csc_install(const char *path_str, const char *remove_str, const char *csc_script);
int __coretpk_installer_csc_uninstall(const char *pkgid);

#ifdef _APPFW_FEATURE_MOUNT_INSTALL
int _coretpk_dbus_mount_file(char *mnt_path[], const char *pkgid);
int _coretpk_dbus_unmount_file(char *mnt_path);
int _coretpk_dbus_is_mount_done(const char *mnt_path);
int _coretpk_dbus_wait_for_tep_mount(const char *tep_path);
#endif

#ifdef __cplusplus
}
#endif				/* __cplusplus */
#endif				/* __CORETPK_INSTALLER_INTERNAL_H_ */
