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
#endif				/* __cplusplus */

/*use ri_frontend_cmdline_arg*/
#include "rpm-frontend.h"

int _coretpk_backend_interface(const char *reqcommand, const ri_frontend_cmdline_arg *data);
int _coretpk_installer_prepare_package_install(char *pkgid, char *clientid);
int _coretpk_installer_prepare_package_uninstall(const char *pkgid);
int _coretpk_installer_prepare_directory_install(char* dirpath, char *clientid);
int _coretpk_installer_package_move(char* pkgid, int movetype);
int _coretpk_installer_request_hybrid(int hybridOperation, char* pPkgPath, int apiVisibility);
int _coretpk_parser_convert_manifest(const char *tizen_manifest, const char *pkgid, const char *clientid, bool hybrid, int api_visibility, const bundle *optional_data);
bool _coretpk_parser_is_widget(const char *tizen_manifest);
#ifdef __cplusplus
}
#endif				/* __cplusplus */
#endif				/* __CORETPK_INSTALLER_H_ */
