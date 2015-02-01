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

#ifndef __RPM_INSTALLER_PRIVILEGE_H_
#define __RPM_INSTALLER_PRIVILEGE_H_

#ifdef __cplusplus
extern "C" {
#endif				/* __cplusplus */

int _ri_privilege_register_package(const char *pkgid);
int _ri_privilege_unregister_package(const char *pkgid);
int _ri_privilege_revoke_permissions(const char *pkgid);
int _ri_privilege_enable_permissions(const char *pkgid, int apptype, const char **perms, int persistent);
int _ri_privilege_setup_path(const char *pkgid, const char *dirpath, int apppathtype, const char *groupid);
int _ri_privilege_add_friend(const char *pkgid1, const char *pkgid2);
int _ri_privilege_change_smack_label(const char *path, const char *label,	int label_type);

#ifdef __cplusplus
}
#endif				/* __cplusplus */
#endif				/* __RPM_INSTALLER_PRIVILEGE_H_ */
