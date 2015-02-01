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
#include "rpm-installer-util.h"
#include "coretpk-installer.h"
#include "coretpk-installer-type.h"

int _coretpk_installer_directory_install(char* dirpath, char *clientid);

int _coretpk_installer_package_install(char *pkgfile, char *pkgid, char *clientid);
int _coretpk_installer_package_uninstall(const char *pkgid);
int _coretpk_installer_package_reinstall(char *dirpath, char *clientid);
int _coretpk_installer_package_upgrade(char *pkgfile, char *pkgid, char *clientid);

int _coretpk_installer_csc_install(char *path_str, char *remove_str);

pkginfo *_coretpk_installer_get_pkgfile_info(char *pkgfile);
char* _coretpk_installer_load_directory(char *directory,char* pkgfile);
int _coretpk_installer_convert_manifest(char *manifestfilepath, char *pkgid, char *clientid);
int _coretpk_installer_get_configuration_value(char *value);

int _coretpk_installer_change_mode(char* path, int mode);
int _coretpk_installer_change_file_owner(char* path, int ownerid, int groupid);
int _coretpk_installer_change_directory_owner(char* dirpath, int ownerid, int groupid);
int _coretpk_installer_make_directory_for_ext(char *pkgid);
int _coretpk_installer_make_directory(char *pkgid);
int _coretpk_installer_apply_smack(char *pkgname, int flag);
int _coretpk_installer_apply_privilege(char *pkgid, char *pkgPath, int apiVisibility);
void _coretpk_installer_search_ui_gadget(const char *pkgid);
int _coretpk_installer_set_smack_label_access(const char *path, const char *label);
int _coretpk_installer_get_smack_label_access(const char *path, char **label);
int _coretpk_installer_set_smack_label_transmute(const char *path, const char *flag);
int _coretpk_installer_remove_db_info(const char *pkgid);

#ifdef __cplusplus
}
#endif				/* __cplusplus */
#endif				/* __CORETPK_INSTALLER_INTERNAL_H_ */
