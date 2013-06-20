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

#define ERR_RETURN_LEN			10

extern pkgmgr_installer *pi;
extern char *gpkgname;

int _ri_get_backend_state()
{
	int ret = -1;
	int state = -1;

	_d_msg(DEBUG_INFO,"_ri_get_backend_state\n");
	ret = vconf_get_int(VCONF_RPM_INSTALLER_BACKEND_STATE, &state);
	if (ret == -1) {
		_d_msg(DEBUG_ERR,
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

	_d_msg(DEBUG_INFO,"_ri_set_backend_state\n");
	ret = vconf_set_int(VCONF_RPM_INSTALLER_BACKEND_STATE, state);
	if (ret == -1) {
		_d_msg(DEBUG_ERR,
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
		_d_msg(DEBUG_ERR,
		       "_ri_get_backend_state_info: vconf_get_int FAIL\n");
	} else {
		ret = state;
	/*	_d_msg(DEBUG_INFO,"_ri_get_backend_state_info state[%d]\n", state);*/
	}
	return ret;
}

int _ri_set_backend_state_info(int state)
{
	int ret = -1;
	_d_msg(DEBUG_INFO,"_ri_set_backend_state_info %d\n", state);
	ret = vconf_set_int(VCONF_RPM_INSTALLER_BACKEND_STATEINFO, state);
	if (ret == -1)
		_d_msg(DEBUG_ERR,
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
		_d_msg(DEBUG_ERR,
		       "_ri_get_last_input_info: VCONF_RPM_INSTALLER_LAST_REQUESTINFO_COMMAND: vconf_get_int FAIL\n");

	ret = vconf_get_int(VCONF_RPM_INSTALLER_LAST_REQUESTINFO_OPTIONS,
			    poptions);
	if (ret == -1)
		_d_msg(DEBUG_ERR,
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
		_d_msg(DEBUG_ERR, "vconf_keylist_add_int FAIL\n");
	ret = vconf_keylist_add_str(kl,
			    VCONF_RPM_INSTALLER_LAST_REQUESTINFO_PKGNAME,
			    pkgid);
	if (ret == -1)
		_d_msg(DEBUG_ERR, "vconf_keylist_add_str FAIL\n");
	ret = vconf_keylist_add_int(kl,
			    VCONF_RPM_INSTALLER_LAST_REQUESTINFO_OPTIONS,
			    options);
	if (ret == -1)
		_d_msg(DEBUG_ERR, "vconf_keylist_add_int FAIL\n");

	if (vconf_set(kl))
		_d_msg(DEBUG_ERR,
		       "_ri_save_last_input_info: Failure in writing vconf\n");

	ret = vconf_keylist_free(kl);
	if (ret == -1)
		_d_msg(DEBUG_ERR, "vconf_keylist_free FAIL\n");
}

void _ri_broadcast_status_notification(char *pkgid, char *key, char *val)
{
	char *pkgid_tmp = NULL;
	char buf[ERR_RETURN_LEN] = {'\0'};
	int ret_val = 0;

	if (gpkgname != NULL)
		pkgid_tmp = gpkgname;
	else
		pkgid_tmp = pkgid;

	ret_val = _ri_string_to_error_no(val);
	_d_msg(DEBUG_INFO, "pkgid = %s, key = %s, val = %s, ret_val = %d\n", pkgid_tmp, key, val, ret_val);

	if (ret_val == RPM_INSTALLER_ERR_UNKNOWN){
		if (pi != NULL)
			pkgmgr_installer_send_signal(pi, PKGTYPE, pkgid_tmp, key, val);
		else
			_d_msg(DEBUG_ERR, "Failure in sending broadcast message\n");
	}
	else{
		snprintf(buf, ERR_RETURN_LEN - 1, "%d", ret_val);
		pkgmgr_installer_send_signal(pi, PKGTYPE, pkgid_tmp, key, buf);
	}
}
