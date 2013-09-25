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

#include <Elementary.h>
#include <appcore-efl.h>
#include <string.h>
#include <glib-object.h>

#include "rpm-frontend.h"
#include "rpm-homeview.h"
#include "rpm-installer-util.h"
#include "rpm-installer.h"
#include <pkgmgr_installer.h>

#define CONFIG_PATH		"/usr/etc/rpm-installer-config.ini"
static void __ri_start_processing(void *user_data);
static int __ri_is_signature_verification_enabled();

int ret_val = -1;
/*flag to check whether signature verification is on/off*/
int sig_enable = 0;
struct appdata ad;
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
		_d_msg(DEBUG_ERR, "Failed to open config file [%s]\n", CONFIG_PATH);
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

/**< Called before main loop */
int app_create(void *user_data)
{

	int ret = 0;
	struct appdata *data = (struct appdata *)user_data;
	/*In case of downgrade, popup should be shown even if quiet mode*/
	ret = _ri_frontend_launch_main_view(data);
	return ret;
}

/**< Called after main loop */
int app_terminate(void *user_data)
{
	struct appdata *data = (struct appdata *)user_data;
	ri_frontend_cmdline_arg *fdata = front_data.args;
	if (fdata->quiet == 0) {
		_ri_destroy_home_view(data);
	}
	return 0;
}

/**< Called when every window goes back */
int app_pause(void *user_data)
{
	return 0;
}

/**< Called when any window comes on top */
int app_resume(void *user_data)
{
	return 0;
}

/**< Called at the first idler*/
int app_reset(bundle *b, void *user_data)
{
	return 0;
}

/**< Called at rotate device*/
int app_rotation(int mode, void *user_data)
{
	if (user_data == NULL) {
		_d_msg(DEBUG_ERR, "arg supplied is NULL \n");
		return -1;
	}
	struct appdata *data = (struct appdata *)user_data;
	int angle;
	switch (mode) {
	case APPCORE_RM_LANDSCAPE_NORMAL:
		angle = -90;
		break;

	case APPCORE_RM_LANDSCAPE_REVERSE:
		angle = 90;
		break;

	case APPCORE_RM_PORTRAIT_REVERSE:
		angle = 180;
		break;

	case APPCORE_RM_UNKNOWN:
	case APPCORE_RM_PORTRAIT_NORMAL:
	default:
		angle = 0;
		break;
	}
	elm_win_rotation_with_resize_set(data->win_main, angle);
	return 0;
}

Eina_Bool show_popup_cb(void *data)
{
	/*Avoid log printing as it is an idler function*/
	int state = -1;
	char message[256] = {'\0'};
	state = _ri_get_backend_state_info();
	switch (state) {
	case REQUEST_ACCEPTED:
		break;
	case GOT_PACKAGE_INFO_SUCCESSFULLY:
		break;
	case REQUEST_PENDING:
		strncpy(message, _("Continue Downgrade?"), 255);
		_ri_package_downgrade_information(message);
		/*request is not completed yet. We just got confirmation
		from user whether to downgrade or not*/
		_ri_set_backend_state_info(REQUEST_ACCEPTED);
		break;
	case REQUEST_COMPLETED:
	default:
		if (front_data.args->quiet == 0) {
			_ri_frontend_update_progress_info(&ad, scrolllabel);
			return 0;
		} else
			elm_exit();
		break;
	}

	return 1;
}

static void __ri_start_processing(void *user_data)
{
	int ret = 0;
	if (user_data == NULL) {
		_d_msg(DEBUG_ERR, "arg supplied is NULL \n");
		return;
	}
	ri_frontend_data *data = (ri_frontend_data *) user_data;
	g_type_init();
	ret = _ri_cmdline_process(data);
	ret_val = ret;
	_ri_cmdline_destroy(data);

}

int main(int argc, char *argv[])
{
	int ret = 0;
	ri_frontend_cmdline_arg *data = NULL;
	struct appcore_ops ops;
	ops.create = app_create;
	ops.terminate = app_terminate;
	ops.pause = app_pause;
	ops.resume = app_resume;
	ops.reset = app_reset;
	ops.data = &ad;
	ecore_init();
	appcore_set_i18n(PACKAGE, LOCALE_PATH);
	_d_msg_init("rpm-installer");
	/*get signature verification config*/
	sig_enable = __ri_is_signature_verification_enabled();
	_d_msg(DEBUG_INFO, "Signature Verification Mode is [%d]\n", sig_enable);
	data = (ri_frontend_cmdline_arg *) calloc(1,
						  sizeof
						  (ri_frontend_cmdline_arg));
	if (data == NULL) {
		_d_msg(DEBUG_ERR, "Not Enough Memory\n");
		ret = RPM_INSTALLER_ERR_NOT_ENOUGH_MEMORY;
		goto ERROR;
	}
	data->keyid = NULL;
	data->pkgid = NULL;
	data->quiet = 0;
	data->req_cmd = INVALID_CMD;
	data->move_type = -1;

	/* We need to use pkgmgr_installer_receive request()
	   to parse the arguments */
	if ((ret =
	     _ri_parse_cmdline(argc, argv, data)) != RPM_INSTALLER_SUCCESS) {
		_d_msg(DEBUG_ERR, "_ri_parse_cmdline failed \n");
		goto ERROR;
	}

	front_data.args = data;
	front_data.security_cookie = NULL;
	front_data.error = NULL;

	__ri_start_processing(&front_data);

	/*The installer has finished the installation/uninstallation.
	   Now, if it was a non quiet operation we need to show the popup. */
	if (data->req_cmd == SMACK_CMD) {
		goto ERROR;
	}

	ecore_idler_add(show_popup_cb, NULL);

	_d_msg(DEBUG_RESULT, "About to run EFL Main Loop");
	appcore_efl_main(PACKAGE, &argc, &argv, &ops);
	_d_msg(DEBUG_RESULT, "%d\n", ret_val);

	_d_msg_deinit();
	if (pi) {
		pkgmgr_installer_free(pi);
		pi = NULL;
	}

	if(!ret_val)
		sync();

	return ret_val;

 ERROR:
	if (data) {
		if (data->pkgid) {
			free(data->pkgid);
			data->pkgid = NULL;
		}
		if (data->keyid) {
			free(data->keyid);
			data->keyid = NULL;
		}
		free(data);
		data = NULL;
	}
	_d_msg(DEBUG_INFO, "%d\n", ret);
	_d_msg_deinit();
	return ret;

}
