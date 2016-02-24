/*
 * coretpk-installer
 *
 * Copyright (c) 2000 - 2011 Samsung Electronics Co., Ltd. All rights reserved.
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

#ifndef __CORETPK_INSTALLER_H_
#define __CORETPK_INSTALLER_H_

#ifdef __cplusplus
extern "C" {
#endif

#include "installer-type.h"
#include "rpm-frontend.h"

int _coretpk_backend_interface(const char *reqcommand, const ri_frontend_cmdline_arg *data);
int _coretpk_installer_prepare_package_install(const char *pkgid, const char *clientid, bool preload, const cmdinfo* cmd_info);
int _coretpk_installer_prepare_package_install_with_debug(const char *pkgid, const char *clientid, bool preload, const cmdinfo* cmd_info);
int _coretpk_installer_prepare_package_uninstall(const char *pkgid);
int _coretpk_installer_prepare_preload_install(const char* dirpath, const char *clientid, const cmdinfo* cmd_info);
int _coretpk_installer_prepare_preload_uninstall(const char* pkgid);
int _coretpk_installer_package_move(const char* pkgid, int movetype);
int _coretpk_installer_request_hybrid(int hybridOperation, const char* pPkgPath, int apiVisibility);

int _coretpk_parser_convert_manifest(const char *tizen_manifest, const char *pkgid, const char *clientid, bool hybrid, int api_visibility, const bundle *optional_data);
bool _coretpk_parser_is_widget(const char *tizen_manifest);
pkginfo *_coretpk_parser_get_manifest_info(const char *tizen_manifest);
int _coretpk_parser_update_manifest(const char *tizen_manifest, const char *label);
#ifdef _APPFW_FEATURE_DELTA_UPDATE
delta_info* _coretpk_parser_get_delta_info(char* delta_info_file, char *manifest_file);
int _coretpk_installer_prepare_delta_install(const char* dirpath, const char* clientid);
#endif

#ifdef _APPFW_FEATURE_MOUNT_INSTALL
int _coretpk_installer_prepare_mount_install(const char *pkg_file, const char *client_id, bool preload, const cmdinfo * cmd_info);
#endif

#ifdef __cplusplus
}
#endif
#endif /* __CORETPK_INSTALLER_H_ */
