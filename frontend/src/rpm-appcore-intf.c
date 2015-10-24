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
#include <pthread.h>
#include <string.h>
#include <device/power.h>
#include <libxml/parser.h>
#include <unistd.h>

#include "rpm-frontend.h"
#include "installer-type.h"
#include "rpm-installer.h"
#include <pkgmgr_installer.h>
#ifdef _APPFW_FEATURE_EXPANSION_PKG_INSTALL
#include "installer-util.h"
#endif

static int __ri_start_processing(void *user_data);
static int __ri_is_signature_verification_enabled();

/*flag to check whether signature verification is on/off*/
int sig_enable = 0;
extern char scrolllabel[256];
extern ri_frontend_data front_data;
pkgmgr_installer *pi = NULL;


static int __ri_is_signature_verification_enabled()
{
	char buffer[1024] = {'\0'};
	char *p = NULL;
	FILE *fi = NULL;
	int len = 0;
	int ret = 0;
	fi = fopen(RPM_CONFIG_PATH, "r");
	if (fi == NULL) {
		_LOGE("Failed to open config file [%s]\n", RPM_CONFIG_PATH);
		return 0;
	}
	while (fgets(buffer, 1024, fi) != NULL) {
		/* buffer will be like signature=off\n\0*/
		if (strncmp(buffer, "signature", strlen("signature")) == 0) {
			len = strlen(buffer);
			/*remove newline character*/
			buffer[len - 1] = '\0';
			p = strchr(buffer, '=');
			if (p) {
				p++;
				if (strcmp(p, "on") == 0)
					ret = 1;
				else
					ret = 0;
			}
		} else {
			continue;
		}
	}
	fclose(fi);
	return ret;
}


static int __ri_start_processing(void *user_data)
{
	int ret = 0;
	if (user_data == NULL) {
		_LOGE("arg supplied is NULL \n");
		return -1;
	}
	ri_frontend_data *data = (ri_frontend_data *) user_data;
	ret = _ri_cmdline_process(data);
	_ri_cmdline_destroy(data);

	return ret;
}

int main(int argc, char *argv[])
{
	int i = 0;
	int ret = 0;
	ri_frontend_cmdline_arg *data = NULL;

	_LOGD("------------------------------------------------");
	_LOGD(" [START] rpm-installer: version=[%s]", INSTALLER_VERSION);
	_LOGD("------------------------------------------------");

	__ri_privilege_perm_begin();

	for (i = 0; i < argc; i++)
	{
		const char* pStr = argv[i];
		if (pStr)
		{
			_LOGD("argv[%d] = [%s]", i, pStr);
		}
	}

	// hybrid, preload, csc, fota
	ret = _ri_parse_command_arg(argc, argv);
	if (ret != RPM_INSTALLER_ERR_WRONG_PARAM) {
		_LOGE("[END] _ri_parse_command_arg() finished. ret=[%d]", ret);
		__ri_privilege_perm_end();
		return ret;
	}

	// power_lock
	ret = device_power_request_lock(POWER_LOCK_CPU, 0);
	_LOGD("device_power_lock_state(POWER_LOCK_CPU, 0), ret = [%d]", ret);

	/* Initialize the xml parser */
	xmlInitParser();
	// _LOGD("xml parser initialized");

	/*get signature verification config*/
	sig_enable = __ri_is_signature_verification_enabled();
	//_LOGD("signature verification mode is [%s]", sig_enable?"on":"off");

	data = (ri_frontend_cmdline_arg *) calloc(1,
						  sizeof
						  (ri_frontend_cmdline_arg));
	if (data == NULL) {
		_LOGE("Not Enough Memory\n");
		ret = RPM_INSTALLER_ERR_NOT_ENOUGH_MEMORY;
		goto ERROR;
	}
	data->keyid = NULL;
	data->pkgid = NULL;
	data->pkg_chksum = NULL;
#ifdef _APPFW_FEATURE_EXPANSION_PKG_INSTALL
	data->tep_path = NULL;
#endif
	data->req_cmd = INVALID_CMD;
	data->move_type = -1;
#ifdef _APPFW_FEATURE_SUPPORT_DEBUGMODE_FOR_SDK
	data->debug_mode = false;
#endif

	/* We need to use pkgmgr_installer_receive request()
	   to parse the arguments */
	if ((ret =
	     _ri_parse_cmdline(argc, argv, data)) != RPM_INSTALLER_SUCCESS) {
		_LOGE("_ri_parse_cmdline failed \n");
		goto ERROR;
	}

#ifdef _APPFW_FEATURE_EXPANSION_PKG_INSTALL
	_LOGD("_ri_parse_cmdline success \n");
	_LOGD("Received command is %d\n", data->req_cmd);
#endif

	if(data->req_cmd == INSTALL_CMD){
		/*directory installation for coretpk*/
		if (strstr(data->keyid, "coretpk") != NULL) {
			_LOGD("[%s] is directory for tpk.\n", data->pkgid);
			data->req_cmd = CORETPK_DIRECTORY_INSTALL_CMD;
			goto process_request;
		}

		// installation for watch-app
		if (strstr(data->keyid, "watch-install") != NULL) {
			_LOGD("[%s] is installation for watch.", data->pkgid);
			data->req_cmd = CORETPK_WATCH_INSTALL_CMD;
			goto process_request;
		}

		/*installation for coretpk*/
		if ((strstr(data->keyid, ".tpk") != NULL)
			|| (strstr(data->pkgid,".wgt") != NULL)
			|| (__is_dir(data->pkgid))) {
			_LOGE("[%s] is tpk package.\n", data->pkgid);
			data->req_cmd = CORETPK_INSTALL_CMD;
			goto process_request;
		}

#ifdef _APPFW_FEATURE_DELTA_UPDATE
		/*installation for delta package*/
		if (strstr(data->keyid, DELTA_EXTENSION) != NULL) {
			_LOGE("[%s] is delta tpk package.\n", data->pkgid);
			data->req_cmd = CORETPK_DELTA_INSTALL_CMD;
			goto process_request;
		}
#endif
#ifdef _APPFW_FEATURE_EXPANSION_PKG_INSTALL
		if (data->tep_path){
			if (strstr(data->keyid, ".tep") != NULL){
				data->req_cmd = INSTALL_TEP_CMD;
				goto process_request;
			}
		}
	} else if(data->req_cmd == INSTALL_TEP_CMD){
		_LOGD("data->req_cmd [%d]", INSTALL_TEP_CMD);
		goto process_request;
#endif
#ifdef _APPFW_FEATURE_MOUNT_INSTALL
	} else if(data->req_cmd == CORETPK_MOUNT_INSTALL_CMD) {	/* Mount based installation */
		_LOGE("[%s] is mount install.\n", data->pkgid);
		goto process_request;
#endif

	}

process_request:

	front_data.args = data;
	front_data.security_cookie = NULL;
	front_data.error = NULL;

	ret = __ri_start_processing(&front_data);

#ifdef _APPFW_FEATURE_EXPANSION_PKG_INSTALL
	if ((data->keyid && (strstr(data->keyid, ".tpk") != NULL)) || (data->pkgid && (strstr(data->pkgid,".wgt") != NULL))) {
#else
	if ((strstr(data->keyid, ".tpk") != NULL) || (strstr(data->pkgid,".wgt") != NULL)) {
#endif
		if(!ret) {
			_LOGD("sync() start");
			sync();
			_LOGD("sync() end");
		}
	}


ERROR:
	device_power_release_lock(POWER_LOCK_CPU);

	if (pi) {
		pkgmgr_installer_free(pi);
		pi = NULL;
	}

	if (data) {
		free(data);
		data = NULL;
	}

	xmlCleanupParser();
	__ri_privilege_perm_end();

	_LOGD("------------------------------------------------");
	_LOGD(" [END] rpm-installer: result=[%d]", ret);
	_LOGD("------------------------------------------------");

	return ret;

}
