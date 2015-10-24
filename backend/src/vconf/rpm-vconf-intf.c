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

#include "installer-type.h"
#include "installer-util.h"
#include "rpm-installer.h"

int state;
int state_info;
int request_info_command;
int request_info_options;
char request_info_pkgname[1024];
extern pkgmgr_installer *pi;

int _ri_get_backend_state()
{
	_LOGD("state=[%d]", state);
	return state;
}

int _ri_set_backend_state(int value)
{
	_LOGD("set state=[%d]", value);
	state = value;

	if (value == 0) {
		// unset
		state_info = 0;
		request_info_command = 0;
		request_info_options = 0;
		memset(request_info_pkgname, 0x00, sizeof(request_info_pkgname));
	}

	return 0;
}

int _ri_get_backend_state_info()
{
	_LOGD("state_info=[%d]", state_info);
	return state_info;
}

int _ri_set_backend_state_info(int value)
{
	_LOGD("set state_info=[%d]", value);
	state_info = value;

	return 0;
}

int _ri_get_last_input_info(char **pkgid, int *preqcommand, int *poptions)
{
	if (!pkgid || !preqcommand || !poptions)
		return -1;

	*preqcommand = request_info_command;
	*poptions = request_info_options;
	*pkgid = strdup(request_info_pkgname);

	_LOGD("reqcommand=[%d], options=[%d], pkgid=[%s]", *preqcommand, *poptions, *pkgid);

	return 0;
}

void _ri_save_last_input_info(char *pkgid, int reqcommand, int options)
{
	request_info_command = reqcommand;
	request_info_options = options;
	snprintf(request_info_pkgname, 1024 - 1, "%s", pkgid);

	_LOGD("reqcommand=[%d], options=[%d], pkgid=[%s]", request_info_command, request_info_options, request_info_pkgname);
}

void _ri_broadcast_privilege_notification(const char *pkgid, const char *pkgtype, const char *key, const char *val)
{
	if (pi == NULL)
		return;

	if (val == NULL)
		return;

	_LOGD("pkgid=[%s], key=[%s], val=[%s]", pkgid, key, val);
	pkgmgr_installer_send_signal(pi, pkgtype, pkgid, key, val);
}

void _ri_broadcast_app_uninstall_notification(const char *pkgid, const char *pkgtype, const char *val)
{
	pkgmgr_installer_send_app_uninstall_signal(pi, pkgtype, pkgid, val);
}

void _ri_broadcast_status_notification(const char *pkgid, const char *pkgtype, const char *key, const char *val)
{
	char buf[BUF_SIZE] = {'\0'};
	int ret_val = 0;

	if (pi == NULL) {
		return;
	}
	if (val == NULL) {
		return;
	}

	_LOGD("pkgid=[%s], key=[%s], val=[%s]", pkgid, key, val);

	if (strcmp(key, PKGMGR_INSTALLER_INSTALL_PERCENT_KEY_STR) == 0) {
		ret_val = atoi(val);
		snprintf(buf, BUF_SIZE - 1, "%d", ret_val);
		pkgmgr_installer_send_signal(pi, pkgtype, pkgid, key, buf);
	} else {
		ret_val = _ri_string_to_error_no(val);
		if (ret_val == RPM_INSTALLER_ERR_UNKNOWN){
			pkgmgr_installer_send_signal(pi, pkgtype, pkgid, key, val);
		} else {
			snprintf(buf, BUF_SIZE - 1, "%d:%s", ret_val, val);
			pkgmgr_installer_send_signal(pi, pkgtype, pkgid, key, buf);
		}
	}
}

