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
#include <pkgmgr_installer.h>
#include <security-server.h>
#include "rpm-frontend.h"
#include "rpm-installer-util.h"
#include "rpm-installer.h"
#include "coretpk-installer.h"

#define _FIX_POP_UP_
extern struct appdata ad;
extern int ret_val;
extern pkgmgr_installer *pi;
ri_frontend_data front_data;
char scrolllabel[256];
int move_type;
#define BUF_SIZE 1024
#define OTP_USR_APPS "/opt/usr/apps"

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

	_LOGD("%s\n", buffer);
	_LOGD(
	       "\nrpm-backend usage\n   rpm-backend -k <keyid>  <command> <pkgid | pkg_path> [-q] \n\n");
	_LOGD("<Commands> \n");
	_LOGD(
	       "\t -i <package file path>	  : install package file \n");
	_LOGD(
	       "\t -k <keyid>			: key id file \n");
	_LOGD(
	       "\t -r : (recover). Must ignore specific package name or path \n");
	_LOGD(
	       "\t -d <package name>		: delete a package with package name \n");
	_LOGD(
	       "\t -q : (quiet) run in background without any user interaction \n");
	_LOGD(
	       "\t -s : (smack) apply smack rule and set smack label\n");
}

int _ri_parse_hybrid(int argc, char **argv)
{
	int i = 0;

	if (argv[1] != NULL) {
		if (!strcmp(argv[1], "-iv")) {
			_LOGE("Hybrid Installation start\n");

			for (i = 0; i < argc; i++) {
				const char* arg_str = argv[i];
				if (arg_str)
					_LOGE("argv[%d] = [%s]\n", i, arg_str);
			}

			if (_coretpk_installer_request_hybrid(argv[1][1], argv[2], atoi(argv[4])) == 0) {
				return RPM_INSTALLER_SUCCESS;
			} else {
				return RPM_INSTALLER_ERR_INTERNAL;
			}
		} else if (!strcmp(argv[1], "-uv")) {
			_LOGE("Hybrid Uninstallation start\n");
			return RPM_INSTALLER_SUCCESS;
		}
	}

	return RPM_INSTALLER_ERR_WRONG_PARAM;
}

int _ri_parse_cmdline(int argc, char **argv, ri_frontend_cmdline_arg *data)
{
	int req_cmd = INVALID_CMD;
	const char *pkgid = NULL;
	const char *pkeyid = NULL;
	int ret = 0;
	int move_type = -1;
	pi = pkgmgr_installer_new();
	if (!pi) {
		_LOGE(
		       "Failure in creating the pkgmgr_installer object \n");
		return RPM_INSTALLER_ERR_WRONG_PARAM;
	}
	ret = pkgmgr_installer_receive_request(pi, argc, argv);
	if (ret) {
		_LOGE("pkgmgr_installer_receive_request failed \n");
		return RPM_INSTALLER_ERR_WRONG_PARAM;
	}
	ret = pkgmgr_installer_get_request_type(pi);
	switch (ret) {
	case PKGMGR_REQ_INSTALL:
		req_cmd = INSTALL_CMD;
		break;
	case PKGMGR_REQ_REINSTALL:
		req_cmd = CORETPK_REINSTALL_CMD;
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
	case PKGMGR_REQ_SMACK:
		req_cmd = SMACK_CMD;
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
			_LOGE(
			       "pkgmgr_installer_get_request_info failed \n");
			return RPM_INSTALLER_ERR_WRONG_PARAM;
		}
		pkeyid = pkgmgr_installer_get_session_id(pi);
		if (!pkeyid) {
			_LOGE("pkgmgr_installer_get_session_id failed \n");
			return RPM_INSTALLER_ERR_WRONG_PARAM;
		}
		move_type = pkgmgr_installer_get_move_type(pi);
	}
//Logically dead code,the value of req_cmd never satisfies the condition
#if 0
	if ((req_cmd < INSTALL_CMD) ||(req_cmd > RPM_CMD_MAX)) {
		_LOGE("invalid command \n");
		goto PARSEERROR;
	}
#endif
	data->req_cmd = req_cmd;
	data->pkgid = (char *)pkgid;
	data->keyid = (char *)pkeyid;
	data->move_type = move_type;
	data->clientid = (char *)pkgmgr_installer_get_caller_pkgid(pi);

	return RPM_INSTALLER_SUCCESS;

 PARSEERROR:
	_LOGE("Error in parsing input parameter\n");
	__ri_show_usage(argv);
	return RPM_INSTALLER_ERR_WRONG_PARAM;

}

static int __ri_is_core_tpk_app(char *pkgid)
{
	char pkgpath[BUF_SIZE] = {'\0'};

	snprintf(pkgpath, BUF_SIZE, "%s/%s/tizen-manifest.xml", OTP_USR_APPS, pkgid);

	if (access(pkgpath, R_OK) == 0) {
		_LOGE("This is a core tpk app.");
		return 0;
	} else {
		_LOGE("This is not a core tpk app.");
		return -1;
	}
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
			_LOGE("strdup failed\n");
			return RPM_INSTALLER_ERR_WRONG_PARAM;
		}
		keyid = strdup(data->keyid);
		if (PM_UNLIKELY(keyid == NULL)) {
			_LOGE("strdup failed\n");
			free(pkgid);
			pkgid = NULL;
			return RPM_INSTALLER_ERR_WRONG_PARAM;
		}
	}

	if (pkgid == NULL) {
		_LOGE("pkgid is null\n");
		return -1;
	}

	switch (data->req_cmd) {
	case INSTALL_CMD:
		_LOGD("rpm-backend -i %s\n", pkgid);
		ret = _rpm_backend_interface(keyid, pkgid, "install", data->clientid);
		break;
	case DELETE_CMD:
		if (__ri_is_core_tpk_app(pkgid) == 0) {
			_LOGD("------------------------------------------------");
			_LOGD("uninstallation: tpk, pkgid=[%s]", pkgid);
			_LOGD("------------------------------------------------");
			ret = _coretpk_backend_interface("coretpk-uninstall", data);
		} else {
			_LOGD("uninstallation for rpm [%s]", pkgid);
			ret = _rpm_backend_interface(keyid, pkgid, "remove", NULL);
		}
		break;
	case CLEARDATA_CMD:
		_LOGD("rpm-backend -c %s\n", pkgid);
		ret = _rpm_backend_interface(keyid, pkgid, "cleardata", NULL);
		break;
	case MOVE_CMD:
		if (__ri_is_core_tpk_app(pkgid) == 0) {
			_LOGD("coretpk-move %s\n", pkgid);
			ret = _coretpk_backend_interface("coretpk-move", data);
		} else {
			_LOGD("rpm-backend -m %s -t %d\n", pkgid, data->move_type);
			move_type = data->move_type;
			ret = _rpm_backend_interface(keyid, pkgid, "move", NULL);
		}
		break;
	case RECOVER_CMD:
		_LOGD("rpm-backend -r \n");
		ret = _rpm_backend_interface(keyid, pkgid, "recover", NULL);
		break;
	case SMACK_CMD:
		_LOGD("rpm-backend -s %s", pkgid);
		ret = _rpm_backend_interface(keyid, pkgid, "smack", NULL);
		break;
	case EFLWGT_INSTALL_CMD:
		_LOGD("eflwgt-install %s\n", pkgid);
		ret = _rpm_backend_interface(keyid, pkgid, "eflwgt-install", data->clientid);
		break;
	case CORETPK_INSTALL_CMD:
		_LOGD("------------------------------------------------");
		_LOGD("installation: tpk, arg=[%s]", pkgid);
		_LOGD("------------------------------------------------");
		ret = _coretpk_backend_interface("coretpk-install", data);
		break;
	case CORETPK_REINSTALL_CMD:
		_LOGD("coretpk-reinstall %s\n", pkgid);
		ret = _coretpk_backend_interface("coretpk-reinstall", data);
		break;
	case CORETPK_DIRECTORY_INSTALL_CMD:
		_LOGD("coretpk-directory_install %s\n", pkgid);
		ret = _coretpk_backend_interface("coretpk-directory-install", data);
		break;
	case ENABLE_CMD:
		_LOGD("rpm enable %s\n", pkgid);
		ret = _rpm_backend_interface(keyid, pkgid, "rpm-enable", NULL);
		break;
	case DISABLE_CMD:
		_LOGD("rpm disable %s\n", pkgid);
		ret = _rpm_backend_interface(keyid, pkgid, "rpm-disable", NULL);
		break;
	default:
		_LOGE("Error Never Come Here as Error is already checked\n");
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
		_LOGE("Either pkgid/key/val is NULL\n");
		return;		/*TODO: handle error. */
	}

	char pkgid_modified[PATH_MAX] = {0};
	char delims[] = "/";
	char *result = NULL;
	char *pkgid_tmp = NULL;
	char *saveptr = NULL;

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
				"installation");
			break;
		case DELETE_CMD:
			snprintf(requesttype, sizeof(requesttype), "deletion");
			break;
		case CLEARDATA_CMD:
			snprintf(requesttype, sizeof(requesttype),
				 "clear data");
			break;
		case MOVE_CMD:
			snprintf(requesttype, sizeof(requesttype),
				 "move");
			break;
		default:
			snprintf(requesttype, sizeof(requesttype), "recovery");
			break;
		}

		if (front_data.error) {
			/* Error Happened */
			snprintf(scrolllabel, sizeof(scrolllabel),
				 "%s :: %s:: %s:: %s", requesttype, pkgid_tmp,
				 "error",
				 front_data.error);
			_LOGE("%s\n", scrolllabel);
			ret_val = _ri_string_to_error_no(front_data.error);
			_LOGE("%d\n", ret_val);

		} else {
			snprintf(scrolllabel, sizeof(scrolllabel),
				 " %s :: %s :: %s", requesttype, pkgid_tmp,
				"success");
			_LOGD("%s\n", scrolllabel);
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
		_LOGE("__ri_process_request: Error\n");
		return ret;
	}
	return RPM_INSTALLER_SUCCESS;
}

int _ri_cmdline_destroy(ri_frontend_data *data)
{
	if (data == NULL)
		return 0;

	if (data->security_cookie){
		free(data->security_cookie);
		data->security_cookie = NULL;
	}

	return 0;

}
