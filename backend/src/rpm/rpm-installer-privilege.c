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
#include <stdbool.h>
#include <dlfcn.h>

#include "rpm-installer.h"

#define LIB_PRIVILEGE_CONTROL		"libprivilege-control.so.0"
#define LIB_SMACK					"libsmack.so.1"

int _ri_privilege_register_package(const char *pkgid)
{
	int ret = 0;
	void *handle = NULL;
	char *errmsg = NULL;
	int (*app_install)(const char*) = NULL;

	if (pkgid == NULL)
		return -1;

	handle = dlopen(LIB_PRIVILEGE_CONTROL, RTLD_LAZY | RTLD_GLOBAL);
	if (!handle) {
		_d_msg(DEBUG_ERR, "register package: dlopen() failed. [%s]", dlerror());
		return -1;
	}

	app_install = dlsym(handle, "app_install");
	errmsg = dlerror();
	if ((errmsg != NULL) || (app_install == NULL)) {
		_d_msg(DEBUG_ERR, "register package: dlsym() failed. [%s]", errmsg);
		dlclose(handle);
		return -1;
	}

	_d_msg(DEBUG_INFO, "[smack] app_install(%s)", pkgid);
	ret = app_install(pkgid);
	_d_msg(DEBUG_INFO, "[smack] app_install(%s), result = [%d]", pkgid, ret);

	dlclose(handle);
	return ret;
}

int _ri_privilege_unregister_package(const char *pkgid)
{
	int ret = 0;
	void *handle = NULL;
	char *errmsg = NULL;
	int (*app_uninstall)(const char*) = NULL;

	if (pkgid == NULL)
		return -1;

	handle = dlopen(LIB_PRIVILEGE_CONTROL, RTLD_LAZY | RTLD_GLOBAL);
	if (!handle) {
		_d_msg(DEBUG_ERR, "unregister package: dlopen() failed. [%s]", dlerror());
		return -1;
	}

	app_uninstall = dlsym(handle, "app_uninstall");
	errmsg = dlerror();
	if ((errmsg != NULL) || (app_uninstall == NULL)) {
		_d_msg(DEBUG_ERR, "unregister package: dlsym() failed. [%s]", errmsg);
		dlclose(handle);
		return -1;
	}

	_d_msg(DEBUG_INFO, "[smack] app_uninstall(%s)", pkgid);
	ret = app_uninstall(pkgid);
	_d_msg(DEBUG_INFO, "[smack] app_uninstall(%s), result = [%d]", pkgid, ret);

	dlclose(handle);
	return ret;
}

int _ri_privilege_revoke_permissions(const char *pkgid)
{
	int ret = 0;
	void *handle = NULL;
	char *errmsg = NULL;
	int (*app_revoke_permissions)(const char*) = NULL;

	if (pkgid == NULL)
		return -1;

	handle = dlopen(LIB_PRIVILEGE_CONTROL, RTLD_LAZY | RTLD_GLOBAL);
	if (!handle) {
		_d_msg(DEBUG_ERR, "revoke permissions: dlopen() failed. [%s][%s]", pkgid, dlerror());
		return -1;
	}

	app_revoke_permissions = dlsym(handle, "app_revoke_permissions");
	errmsg = dlerror();
	if ((errmsg != NULL) || (app_revoke_permissions == NULL)) {
		_d_msg(DEBUG_ERR, "revoke permissions(): dlsym() failed. [%s][%s]", pkgid, errmsg);
		dlclose(handle);
		return -1;
	}

	_d_msg(DEBUG_INFO, "[smack] app_revoke_permissions(%s)", pkgid);
	ret = app_revoke_permissions(pkgid);
	_d_msg(DEBUG_INFO, "[smack] app_revoke_permissions(%s), result = [%d]", pkgid, ret);

	dlclose(handle);
	return ret;
}

int _ri_privilege_enable_permissions(const char *pkgid, int apptype,
						const char **perms, int persistent)
{
	int ret = 0;
	void *handle = NULL;
	char *errmsg = NULL;
	int (*app_enable_permissions)(const char*, int, const char**, bool) = NULL;

	if (pkgid == NULL)
		return -1;

	handle = dlopen(LIB_PRIVILEGE_CONTROL, RTLD_LAZY | RTLD_GLOBAL);
	if (!handle) {
		_d_msg(DEBUG_ERR, "enable permissions(): dlopen() failed. [%s]", dlerror());
		return -1;
	}

	app_enable_permissions = dlsym(handle, "app_enable_permissions");
	errmsg = dlerror();
	if ((errmsg != NULL) || (app_enable_permissions == NULL)) {
		_d_msg(DEBUG_ERR, "enable permissions(): dlsym() failed. [%s]", errmsg);
		dlclose(handle);
		return -1;
	}

	_d_msg(DEBUG_INFO, "[smack] app_enable_permissions(%s, %d)", pkgid, apptype);
	ret = app_enable_permissions(pkgid, apptype, perms, persistent);
	_d_msg(DEBUG_INFO, "[smack] app_enable_permissions(%s, %d), result = [%d]", pkgid, apptype, ret);

	dlclose(handle);
	return ret;
}

int _ri_privilege_setup_path(const char *pkgid, const char *dirpath,
						int apppathtype, const char *groupid)
{
	int ret = 0;
	void *handle = NULL;
	char *errmsg = NULL;
	int (*app_setup_path)(const char*, const char*, int, ...) = NULL;

	if (pkgid == NULL || dirpath == NULL)
		return -1;

	handle = dlopen(LIB_PRIVILEGE_CONTROL, RTLD_LAZY | RTLD_GLOBAL);
	if (!handle) {
		_d_msg(DEBUG_ERR, "setup path: dlopen() failed. [%s]", dlerror());
		return -1;
	}

	app_setup_path = dlsym(handle, "app_setup_path");
	errmsg = dlerror();
	if ((errmsg != NULL) || (app_setup_path == NULL)) {
		_d_msg(DEBUG_ERR, "setup path: dlsym() failed. [%s]", errmsg);
		dlclose(handle);
		return -1;
	}

	if (groupid == NULL) {
		_d_msg(DEBUG_INFO, "[smack] app_setup_path(%s, %s, %d)", pkgid, dirpath, apppathtype);
		ret = app_setup_path(pkgid, dirpath, apppathtype);
		_d_msg(DEBUG_INFO, "[smack] app_setup_path(), result = [%d]", ret);
	} else {
		_d_msg(DEBUG_INFO, "[smack] app_setup_path(%s, %s, %d, %s)", pkgid, dirpath, apppathtype, groupid);
		ret = app_setup_path(pkgid, dirpath, apppathtype, groupid);
		_d_msg(DEBUG_INFO, "[smack] app_setup_path(), result = [%d]", ret);
	}

	dlclose(handle);
	return ret;
}

int _ri_privilege_add_friend(const char *pkgid1, const char *pkgid2)
{
	int ret = 0;
	void *handle = NULL;
	char *errmsg = NULL;
	int (*app_add_friend)(const char*, const char*) = NULL;

	if (pkgid1 == NULL || pkgid2 == NULL)
		return -1;

	handle = dlopen(LIB_PRIVILEGE_CONTROL, RTLD_LAZY | RTLD_GLOBAL);
	if (!handle) {
		_d_msg(DEBUG_ERR, "add friend: dlopen() failed. [%s]", dlerror());
		return -1;
	}

	app_add_friend = dlsym(handle, "app_add_friend");
	errmsg = dlerror();
	if ((errmsg != NULL) || (app_add_friend == NULL)) {
		_d_msg(DEBUG_ERR, "add friend: dlsym() failed. [%s]", errmsg);
		dlclose(handle);
		return -1;
	}

	_d_msg(DEBUG_INFO, "[smack] app_add_friend(%s, %s)", pkgid1, pkgid2);
	ret = app_add_friend(pkgid1, pkgid2);
	_d_msg(DEBUG_INFO, "[smack] app_add_friend(%s, %s), result = [%d]", pkgid1, pkgid2, ret);

	dlclose(handle);
	return ret;
}

int _ri_privilege_change_smack_label(const char *path, const char *label,
						int label_type)
{
	if (path == NULL || label == NULL)
		return -1;
	int ret = 0;
	void *handle = NULL;
	char *errmsg = NULL;
	int (*smack_lsetlabel)(const char*, const char*, int) = NULL;

	handle = dlopen(LIB_SMACK, RTLD_LAZY | RTLD_GLOBAL);
	if (!handle) {
		_d_msg(DEBUG_ERR, "change smack label: dlopen() failed. [%s]", dlerror());
		return -1;
	}

	smack_lsetlabel = dlsym(handle, "smack_lsetlabel");
	errmsg = dlerror();
	if ((errmsg != NULL) || (smack_lsetlabel == NULL)) {
		_d_msg(DEBUG_ERR, "change smack label: dlsym() failed. [%s]", errmsg);
		dlclose(handle);
		return -1;
	}

	_d_msg(DEBUG_INFO, "[smack] smack_lsetlabel(%s, %s, %d)", path, label, label_type);
	ret = smack_lsetlabel(path, label, label_type);
	_d_msg(DEBUG_INFO, "[smack] smack_lsetlabel(%s, %s, %d), result = [%d]", path, label, label_type, ret);

	dlclose(handle);
	return ret;
}
