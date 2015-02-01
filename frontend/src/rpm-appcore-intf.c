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

#include "rpm-frontend.h"
#include "rpm-installer-util.h"
#include "rpm-installer.h"
#include <pkgmgr_installer.h>

#define CONFIG_PATH		"/usr/etc/rpm-installer-config.ini"
static void __ri_start_processing(void *user_data);
static int __ri_is_signature_verification_enabled();

int ret_val = -1;
/*flag to check whether signature verification is on/off*/
int sig_enable = 0;
int broadcast_disable = 0;
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
	fi = fopen(CONFIG_PATH, "r");
	if (fi == NULL) {
		_LOGE("Failed to open config file [%s]\n", CONFIG_PATH);
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


static void __ri_start_processing(void *user_data)
{
	int ret = 0;
	if (user_data == NULL) {
		_LOGE("arg supplied is NULL \n");
		return;
	}
	ri_frontend_data *data = (ri_frontend_data *) user_data;
	ret = _ri_cmdline_process(data);
	ret_val = ret;
	_ri_cmdline_destroy(data);

}

int main(int argc, char *argv[])
{
	int i = 0;
	int ret = 0;
	char *errstr = NULL;
	ri_frontend_cmdline_arg *data = NULL;
	struct stat st;

	_LOGD("------------------------------------------------");
	_LOGD(" [START] rpm-installer: version=[%s]", RPM_INSTALLER_VERSION);
	_LOGD("------------------------------------------------");

	// hybrid
	ret = _ri_parse_hybrid(argc, argv);
	if (ret == RPM_INSTALLER_SUCCESS) {
		_LOGD("------------------------------------------------");
		_LOGD(" [END] rpm-installer: _ri_parse_hybrid() succeed.");
		_LOGD("------------------------------------------------");
		fprintf(stdout, "%d", ret);
		return 0;
	}

	for (i = 0; i < argc; i++)
	{
		const char* pStr = argv[i];
		if (pStr)
		{
			_LOGD("argv[%d] = [%s]", i, pStr);
		}
	}

	// power_lock
	ret = device_power_request_lock(POWER_LOCK_CPU, 0);
	_LOGD("device_power_lock_state(POWER_LOCK_CPU, 0), ret = [%d]", ret);

	/* Initialize the xml parser */
	xmlInitParser();
	// _LOGD("xml parser initialized");

	/*get signature verification config*/
	sig_enable = __ri_is_signature_verification_enabled();
	_LOGD("signature verification mode is [%s]", sig_enable?"on":"off");

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
	data->req_cmd = INVALID_CMD;
	data->move_type = -1;

	/* We need to use pkgmgr_installer_receive request()
	   to parse the arguments */
	if ((ret =
	     _ri_parse_cmdline(argc, argv, data)) != RPM_INSTALLER_SUCCESS) {
		_LOGE("_ri_parse_cmdline failed \n");
		goto ERROR;
	}

#if 0
	/*
	Check for converted wgt package.
	*/
	if(strstr(data->pkgid,".wgt") != NULL){
		_LOGD("[%s] is eflwgt package.\n", data->pkgid);
		if(data->req_cmd == INSTALL_CMD){
			data->req_cmd = EFLWGT_INSTALL_CMD;
	       		ret = _ri_process_wgt_package(&data->pkgid);
			if(ret != RPM_INSTALLER_SUCCESS){
				_ri_error_no_to_string(ret, &errstr);
				_LOGE("ERROR:[%s]",errstr);
				goto ERROR;
			}
		}else{
			ret = RPM_INSTALLER_ERR_CMD_NOT_SUPPORTED;
			_ri_error_no_to_string(ret,&errstr);
			_LOGE("ERROR:[%s]",errstr);
			goto ERROR;
		}
	}
#endif

	if (strstr(data->keyid, "change-state") != NULL) {
		_LOGE("change-state for [%s]\n", data->pkgid);
		if (data->req_cmd == INSTALL_CMD) {
			data->req_cmd = ENABLE_CMD;
		} else if (data->req_cmd == DELETE_CMD) {
			data->req_cmd = DISABLE_CMD;
		} else {
			ret = RPM_INSTALLER_ERR_CMD_NOT_SUPPORTED;
			_ri_error_no_to_string(ret,&errstr);
			_LOGE("ERROR:[%s]",errstr);
			goto ERROR;
		}
	}

	/*installation for coretpk*/
	if ((strstr(argv[0], "coretpk") != NULL)
			&& (data->req_cmd == INSTALL_CMD)) {
		if (stat(data->pkgid, &st)) {
			ret = RPM_INSTALLER_ERR_UNKNOWN;
			_ri_error_no_to_string(ret, &errstr);
			_LOGE("ERROR:[%s]",errstr);
			goto ERROR;
		}

		if (S_ISDIR(st.st_mode)) {
			_LOGD("[%s] is directory for tpk.\n", data->pkgid);
			data->req_cmd = CORETPK_DIRECTORY_INSTALL_CMD;
		} else {
			_LOGD("[%s] is tpk package.\n", data->pkgid);
			data->req_cmd = CORETPK_INSTALL_CMD;
		}
	}

	front_data.args = data;
	front_data.security_cookie = NULL;
	front_data.error = NULL;

	__ri_start_processing(&front_data);

	ret = ret_val;
	if ((strstr(data->keyid, ".tpk") != NULL) || (strstr(data->pkgid,".wgt") != NULL)) {
		if(!ret_val) {
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
	_LOGD("------------------------------------------------");
	_LOGD(" [END] rpm-installer: result=[%d]", ret);
	_LOGD("------------------------------------------------");


	return ret;

}
