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

#include <stdio.h>
#include <stdlib.h>
#include <getopt.h>
#include <pthread.h>
#include <stdio.h>
#include <appcore-efl.h>
#include <pkgmgr_installer.h>
#include <security-server.h>
#include "rpm-frontend.h"
#include "rpm-installer-util.h"
#include "rpm-installer.h"
#include "rpm-homeview.h"

#define _FIX_POP_UP_
extern struct appdata ad;
extern int ret_val;
extern pkgmgr_installer *pi;
ri_frontend_data front_data;
char scrolllabel[256];
int move_type;

static void __ri_show_usage(char **arg);
static int __ri_process_request(ri_frontend_cmdline_arg *fdata);

static void __ri_show_usage(char **arg)
{

	int i = 0;
	char buffer[256];
	char buff[256] = "";
	while (arg[i] != NULL) {
		snprintf(buffer, 256, "%s %s", buff, arg[i]);
		strncpy(buff, buffer, 255);
		i++;
	}

	_d_msg(DEBUG_INFO, "%s\n", buffer);
	_d_msg(DEBUG_INFO,
	       "\nrpm-backend usage\n   rpm-backend -k <keyid>  <command> <pkgid | pkg_path> [-q] \n\n");
	_d_msg(DEBUG_INFO, "<Commands> \n");
	_d_msg(DEBUG_INFO,
	       "\t -i <package file path>	  : install package file \n");
	_d_msg(DEBUG_INFO,
	       "\t -k <keyid>			: key id file \n");
	_d_msg(DEBUG_INFO,
	       "\t -r : (recover). Must ignore specific package name or path \n");
	_d_msg(DEBUG_INFO,
	       "\t -d <package name>		: delete a package with package name \n");
	_d_msg(DEBUG_INFO,
	       "\t -q : (quiet) run in background without any user interaction \n");
}

int _ri_parse_cmdline(int argc, char **argv, ri_frontend_cmdline_arg *data)
{
	int req_cmd = INVALID_CMD;
	const char *pkgid = NULL;
	int quiet = 0;
	const char *pkeyid = NULL;
	int ret = 0;
	int move_type = -1;
	pi = pkgmgr_installer_new();
	if (!pi) {
		_d_msg(DEBUG_ERR,
		       "Failure in creating the pkgmgr_installer object \n");
		return RPM_INSTALLER_ERR_WRONG_PARAM;
	}
	ret = pkgmgr_installer_receive_request(pi, argc, argv);
	if (ret) {
		_d_msg(DEBUG_ERR, "pkgmgr_installer_receive_request failed \n");
		return RPM_INSTALLER_ERR_WRONG_PARAM;
	}
	ret = pkgmgr_installer_get_request_type(pi);
	switch (ret) {
	case PKGMGR_REQ_INSTALL:
		req_cmd = INSTALL_CMD;
		break;
	case PKGMGR_REQ_UNINSTALL:
		req_cmd = DELETE_CMD;
		break;
	case PKGMGR_REQ_RECOVER:
		req_cmd = RECOVER_CMD;
		break;
	case PKGMGR_REQ_CLEAR:
		req_cmd = CLEARDATA_CMD;
		break;
	case PKGMGR_REQ_MOVE:
		req_cmd = MOVE_CMD;
		break;
	case PKGMGR_REQ_PERM:
		goto PARSEERROR;
	case PKGMGR_REQ_INVALID:
		req_cmd = INVALID_CMD;
		goto PARSEERROR;
	default:
		goto PARSEERROR;
	}
	if (req_cmd != RECOVER_CMD) {
		pkgid = pkgmgr_installer_get_request_info(pi);
		if (!pkgid) {
			_d_msg(DEBUG_ERR,
			       "pkgmgr_installer_get_request_info failed \n");
			return RPM_INSTALLER_ERR_WRONG_PARAM;
		}
		pkeyid = pkgmgr_installer_get_session_id(pi);
		if (!pkeyid) {
			_d_msg(DEBUG_ERR, "pkgmgr_installer_get_session_id failed \n");
			return RPM_INSTALLER_ERR_WRONG_PARAM;
		}

		quiet = pkgmgr_installer_is_quiet(pi);
		if (quiet != 0 && quiet != 1) {
			_d_msg(DEBUG_ERR, "pkgmgr_installer_is_quiet failed \n");
			return RPM_INSTALLER_ERR_WRONG_PARAM;
		}

		move_type = pkgmgr_installer_get_move_type(pi);
	}
	if ((req_cmd < INSTALL_CMD) ||(req_cmd > MOVE_CMD)) {
		_d_msg(DEBUG_ERR, "invalid command \n");
		goto PARSEERROR;
	}

	data->req_cmd = req_cmd;
	data->pkgid = (char *)pkgid;
	data->quiet = quiet;
	data->keyid = (char *)pkeyid;
	data->move_type = move_type;
	return RPM_INSTALLER_SUCCESS;

 PARSEERROR:
	_d_msg(DEBUG_ERR, "Error in parsing input parameter\n");
	__ri_show_usage(argv);
	return RPM_INSTALLER_ERR_WRONG_PARAM;

}

static int __ri_process_request(ri_frontend_cmdline_arg *data)
{
	int ret = 0;
	if (!data)
		return RPM_INSTALLER_ERR_WRONG_PARAM;
	char *pkgid = NULL;
	char *keyid = NULL;
	if (data->req_cmd != RECOVER_CMD) {
		pkgid = strdup(data->pkgid);
                if (PM_UNLIKELY(pkgid == NULL)) {
                        _d_msg(DEBUG_ERR, "strdup failed\n");
                        return RPM_INSTALLER_ERR_WRONG_PARAM;
                }
                keyid = strdup(data->keyid);
                if (PM_UNLIKELY(keyid == NULL)) {
                        _d_msg(DEBUG_ERR, "strdup failed\n");
                        free(pkgid);
                        return RPM_INSTALLER_ERR_WRONG_PARAM;
                }
	}
	switch (data->req_cmd) {
	case INSTALL_CMD:
		_d_msg(DEBUG_INFO, "rpm-backend -i %s\n", pkgid);
		ret = _rpm_backend_interface(keyid, pkgid, "install");
		break;
	case DELETE_CMD:
		_d_msg(DEBUG_INFO, "rpm-backend -d %s\n", pkgid);
		ret = _rpm_backend_interface(keyid, pkgid, "remove");
		break;
	case CLEARDATA_CMD:
		_d_msg(DEBUG_INFO, "rpm-backend -c %s\n", pkgid);
		ret = _rpm_backend_interface(keyid, pkgid, "cleardata");
		break;
	case MOVE_CMD:
		_d_msg(DEBUG_INFO, "rpm-backend -m %s -t %d\n", pkgid, data->move_type);
		move_type = data->move_type;
		ret = _rpm_backend_interface(keyid, pkgid, "move");
		break;
	case RECOVER_CMD:
		_d_msg(DEBUG_INFO, "rpm-backend -r \n");
		ret = _rpm_backend_interface(keyid, pkgid, "recover");
		break;
	default:
		_d_msg(DEBUG_ERR,
		       "Error Never Come Here as Error is already checked\n");

	}
	if (keyid) {
		free(keyid);
		keyid = NULL;
	}
	if (pkgid) {
		free(pkgid);
		pkgid = NULL;
	}

	return ret;
}

void _ri_stat_cb(const char *pkgid, const char *key, const char *val)
{

	if (NULL == pkgid || NULL == key || NULL == val) {
		_d_msg(DEBUG_ERR, "Either pkgid/key/val is NULL\n");
		return;		/*TODO: handle error. */
	}

	char *pkgid_modified = NULL;
	char delims[] = "/";
	char *result = NULL;
	char *pkgid_tmp = NULL;
	char *saveptr = NULL;

	pkgid_modified = (char *)malloc(strlen(pkgid) + 1);
	if (pkgid_modified == NULL) {
		_d_msg(DEBUG_ERR, "pkgid_modified is NULL. Malloc failed\n");
		return;
	}
	memset(pkgid_modified, '\0', strlen(pkgid) + 1);
	memcpy(pkgid_modified, pkgid, strlen(pkgid));

	result = strtok_r(pkgid_modified, delims, &saveptr);
	while (result != NULL) {
		pkgid_tmp = result;
		result = strtok_r(NULL, delims, &saveptr);
	}

	if (strcmp(key, "install_percent") == 0) {
		return;
	} else if (strcmp(key, "error") == 0) {
		/* Store the error to be display to the user */
		front_data.error = strdup(val);
	} else if (strcmp(key, "end") == 0) {

		char requesttype[32];
		switch (front_data.args->req_cmd) {
		case INSTALL_CMD:
			snprintf(requesttype, sizeof(requesttype),
				_("Installation"));
			break;
		case DELETE_CMD:
			snprintf(requesttype, sizeof(requesttype), _("Deletion"));
			break;
		case CLEARDATA_CMD:
			snprintf(requesttype, sizeof(requesttype),
				 _("Clear Data"));
			break;
		case MOVE_CMD:
			snprintf(requesttype, sizeof(requesttype),
				 _("Move"));
			break;
		default:
			snprintf(requesttype, sizeof(requesttype), _("Recovery"));
			break;
		}

		if (front_data.error) {
			/* Error Happened */
			snprintf(scrolllabel, sizeof(scrolllabel),
				 "%s :: %s:: %s:: %s", requesttype, pkgid_tmp,
				 dgettext("sys_string", "IDS_COM_POP_ERROR"),
				 front_data.error);
			_d_msg(DEBUG_ERR, "%s\n", scrolllabel);
			ret_val = _ri_string_to_error_no(front_data.error);
			_d_msg(DEBUG_ERR, "%d\n", ret_val);

		} else {
			snprintf(scrolllabel, sizeof(scrolllabel),
				 " %s :: %s :: %s", requesttype, pkgid_tmp,
				 dgettext("sys_string", "IDS_COM_POP_SUCCESS"));
			_d_msg(DEBUG_INFO, "%s\n", scrolllabel);
			ret_val = 0;
		}
	}
}

int _ri_cmdline_process(ri_frontend_data *data)
{
	int ret = 0;
	ri_frontend_cmdline_arg *fdata = data->args;
	/*rpm-installer is invoked by pkgmgr-server hence server should do cookie validation*/
	ret = __ri_process_request(fdata);
	if (ret != RPM_INSTALLER_SUCCESS) {
		_d_msg(DEBUG_ERR, "__ri_process_request: Error\n");
		return ret;
	}
	return RPM_INSTALLER_SUCCESS;
}

int _ri_cmdline_destroy(ri_frontend_data *data)
{
	if (data == NULL)
		return 0;

	if (data->security_cookie)
		free(data->security_cookie);

	return 0;

}
