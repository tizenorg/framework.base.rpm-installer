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
#include <unistd.h>
#include <stdio.h>
#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <privilege-control.h>

#include "rpm-installer.h"



static int __ri_privilege_perm_begin(void)
{
	int ret = 0;

	ret = perm_begin();
	_d_msg(DEBUG_INFO, "[smack] perm_begin, result = [%d]",ret);

	return ret;
}

static int __ri_privilege_perm_end(void)
{
	int ret = 0;

	ret = perm_end();
	_d_msg(DEBUG_INFO, "[smack] perm_end, result = [%d]",ret);

	return ret;
}

int _ri_privilege_register_package(const char *pkgid)
{
	int ret = 0;

	ret = perm_app_install(pkgid);
	_d_msg(DEBUG_INFO, "[smack] app_install(%s), result = [%d]", pkgid, ret);

	return ret;
}

int _ri_privilege_unregister_package(const char *pkgid)
{
	int ret = 0;

	ret = perm_app_uninstall(pkgid);
	_d_msg(DEBUG_INFO, "[smack] app_uninstall(%s), result = [%d]", pkgid, ret);

	return ret;
}

int _ri_privilege_revoke_permissions(const char *pkgid)
{
	int ret = 0;

	ret = perm_app_revoke_permissions(pkgid);
	_d_msg(DEBUG_INFO, "[smack] app_revoke_permissions(%s), result = [%d]", pkgid, ret);

	return ret;
}

int _ri_privilege_enable_permissions(const char *pkgid, int apptype,
						const char **perms, int persistent)
{
	int ret = 0;

	__ri_privilege_perm_begin();

	ret = perm_app_enable_permissions(pkgid, apptype, perms, persistent);
	_d_msg(DEBUG_INFO, "[smack] app_enable_permissions(%s, %d), result = [%d]", pkgid, apptype, ret);

	__ri_privilege_perm_end();

	return ret;
}

int _ri_privilege_setup_path(const char *pkgid, const char *dirpath,
						int apppathtype, const char *groupid)
{
	int ret = 0;

	if (groupid == NULL) {
		ret = perm_app_setup_path(pkgid, dirpath, apppathtype);
		_d_msg(DEBUG_INFO, "[smack] app_setup_path(%s), result = [%d]", dirpath,ret);
	} else {
		ret = perm_app_setup_path(pkgid, dirpath, apppathtype, groupid);
		_d_msg(DEBUG_INFO, "[smack] app_setup_path(%s), result = [%d]", dirpath, ret);
	}

	return ret;
}

int _ri_privilege_add_friend(const char *pkgid1, const char *pkgid2)
{
	int ret = 0;

	ret = perm_app_add_friend(pkgid1, pkgid2);
	_d_msg(DEBUG_INFO, "[smack] app_add_friend(%s, %s), result = [%d]", pkgid1, pkgid2, ret);

	return ret;
}

int _ri_privilege_change_smack_label(const char *path, const char *label,
						int label_type)
{
	if (path == NULL || label == NULL)
		return -1;
	int ret = 0;

	ret = smack_lsetlabel(path, label, label_type);
	_d_msg(DEBUG_INFO, "[smack] smack_lsetlabel(%s, %s, %d), result = [%d]", path, label, label_type, ret);

	return ret;
}
