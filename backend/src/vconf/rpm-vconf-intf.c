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

#include <pkgmgr_installer.h>
#include <vconf.h>
#include <errno.h>

#include "rpm-installer-util.h"
#include "rpm-installer.h"

#define VCONF_LOCATION			"db"
#define VCONF_RPM_INSTALLER		VCONF_LOCATION"/private/rpm-installer"

#define VCONF_RPM_INSTALLER_BACKEND_STATE \
	VCONF_RPM_INSTALLER"/state"
#define VCONF_RPM_INSTALLER_BACKEND_STATEINFO \
	VCONF_RPM_INSTALLER"/stateinfo"

#define VCONF_RPM_INSTALLER_LAST_REQUESTINFO_COMMAND \
	VCONF_RPM_INSTALLER"/requestinfo/command"
#define VCONF_RPM_INSTALLER_LAST_REQUESTINFO_PKGNAME \
	VCONF_RPM_INSTALLER"/requestinfo/pkgname"
#define VCONF_RPM_INSTALLER_LAST_REQUESTINFO_OPTIONS \
	VCONF_RPM_INSTALLER"/requestinfo/options"

#define ERR_RETURN_LEN			256

extern pkgmgr_installer *pi;
extern char *gpkgname;
extern int broadcast_disable;

int _ri_get_backend_state()
{
	int ret = -1;
	int state = -1;

//	_LOGD("_ri_get_backend_state\n");
	ret = vconf_get_int(VCONF_RPM_INSTALLER_BACKEND_STATE, &state);
	if (ret == -1) {
		_LOGE(
		       "_ri_get_backend_state: vconf_get_int FAIL\n");
	} else {
		ret = state;
	}
	return ret;
}

int _ri_set_backend_state(int state)
{
	int ret = -1;

	if (state == 0) {
		vconf_unset_recursive(VCONF_RPM_INSTALLER);
	}

//	_LOGD("_ri_set_backend_state\n");
	ret = vconf_set_int(VCONF_RPM_INSTALLER_BACKEND_STATE, state);
	if (ret == -1) {
		_LOGE(
		       "_ri_set_backend_state: vconf_set_int FAIL\n");
	}

	return ret;
}

int _ri_get_backend_state_info()
{
	int ret = -1;
	int state = -1;
	ret = vconf_get_int(VCONF_RPM_INSTALLER_BACKEND_STATEINFO, &state);
	if (ret == -1) {
		_LOGE(
		       "_ri_get_backend_state_info: vconf_get_int FAIL\n");
	} else {
		ret = state;
	/*	_LOGD("_ri_get_backend_state_info state[%d]\n", state);*/
	}
	return ret;
}

int _ri_set_backend_state_info(int state)
{
	int ret = -1;
//	_LOGD("_ri_set_backend_state_info %d\n", state);
	ret = vconf_set_int(VCONF_RPM_INSTALLER_BACKEND_STATEINFO, state);
	if (ret == -1)
		_LOGE(
		       "_ri_set_backend_state_info: vconf_set_int FAIL\n");

	return ret;
}

int _ri_get_last_input_info(char **pkgid, int *preqcommand, int *poptions)
{
	int ret = -1;
	if (!pkgid || !preqcommand || !poptions)
		return -1;
	ret = vconf_get_int(VCONF_RPM_INSTALLER_LAST_REQUESTINFO_COMMAND,
			    preqcommand);
	if (ret == -1)
		_LOGE(
		       "_ri_get_last_input_info: VCONF_RPM_INSTALLER_LAST_REQUESTINFO_COMMAND: vconf_get_int FAIL\n");

	ret = vconf_get_int(VCONF_RPM_INSTALLER_LAST_REQUESTINFO_OPTIONS,
			    poptions);
	if (ret == -1)
		_LOGE(
		       "_ri_get_last_input_info: VCONF_RPM_INSTALLER_LAST_REQUESTINFO_OPTIONS: vconf_get_int FAIL\n");

	*pkgid = vconf_get_str(VCONF_RPM_INSTALLER_LAST_REQUESTINFO_PKGNAME);
	return 0;
}

void _ri_save_last_input_info(char *pkgid, int reqcommand, int options)
{
	keylist_t *kl = NULL;
	kl = vconf_keylist_new();
	int ret = -1;

	ret = vconf_keylist_add_int(kl,
			    VCONF_RPM_INSTALLER_LAST_REQUESTINFO_COMMAND,
			    reqcommand);
	if (ret == -1)
		_LOGE("vconf_keylist_add_int FAIL\n");
	ret = vconf_keylist_add_str(kl,
			    VCONF_RPM_INSTALLER_LAST_REQUESTINFO_PKGNAME,
			    pkgid);
	if (ret == -1)
		_LOGE("vconf_keylist_add_str FAIL\n");
	ret = vconf_keylist_add_int(kl,
			    VCONF_RPM_INSTALLER_LAST_REQUESTINFO_OPTIONS,
			    options);
	if (ret == -1)
		_LOGE("vconf_keylist_add_int FAIL\n");

	if (vconf_set(kl))
		_LOGE(
		       "_ri_save_last_input_info: Failure in writing vconf\n");

	ret = vconf_keylist_free(kl);
	if (ret == -1)
		_LOGE("vconf_keylist_free FAIL\n");
}

void _ri_broadcast_privilege_notification(const char *pkgid, const char *pkgtype, const char *key, const char *val)
{
	int ret_val = 0;

	if (broadcast_disable || pi == NULL || val == NULL)
		return;

	_LOGE("pkgid=[%s], key[%s], val=[%s]", pkgid, key, val);
	pkgmgr_installer_send_signal(pi, pkgtype, pkgid, key, val);
}

void _ri_broadcast_status_notification(const char *pkgid, char *pkg_type, char *key, char *val)
{
	const char *pkgid_tmp = pkgid;
	char buf[ERR_RETURN_LEN] = {'\0'};
	int ret_val = 0;

	if (broadcast_disable)
		return;

#if 0
	if (gpkgname != NULL)
		pkgid_tmp = gpkgname;
	else
		pkgid_tmp = pkgid;
#endif

	if (pi == NULL) {
		_LOGE("Failure in sending broadcast message\n");
		return;
	}

	if (strcmp(key,PKGMGR_INSTALLER_INSTALL_PERCENT_KEY_STR) == 0) {
		ret_val = atoi(val);

		_LOGD("pkgid=[%s], key=[%s], val=[%s]\n", pkgid_tmp, key, val);

		snprintf(buf, ERR_RETURN_LEN - 1, "%d", ret_val);
		pkgmgr_installer_send_signal(pi, pkg_type, pkgid_tmp, key, buf);
		return;
	} else {
		ret_val = _ri_string_to_error_no(val);

		_LOGD( "pkgid=[%s], key=[%s], val=[%s]\n", pkgid_tmp, key, val);

		if (ret_val == RPM_INSTALLER_ERR_UNKNOWN){
			pkgmgr_installer_send_signal(pi, pkg_type, pkgid_tmp, key, val);
		}
		else{
			snprintf(buf, ERR_RETURN_LEN - 1, "%d:%s", ret_val, val);
			pkgmgr_installer_send_signal(pi, pkg_type, pkgid_tmp, key, buf);
		}
	}
}
