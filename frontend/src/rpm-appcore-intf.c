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

static void __ri_start_processing(void *user_data);
static Eina_Bool __ri_elm_exit_cb(void *data);

int ret_val = -1;
struct appdata ad;
extern char scrolllabel[256];
extern ri_frontend_data front_data;
pkgmgr_installer *pi = NULL;

/**< Called before main loop */
int app_create(void *user_data)
{

	int ret = 0;
	struct appdata *data = (struct appdata *)user_data;
	ri_frontend_cmdline_arg *fdata = front_data.args;

	if (fdata->quiet == 0) {
		ret = _ri_frontend_launch_main_view(data);
		return ret;
	}

	return 0;
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
int app_rotation(enum appcore_rm mode, void *user_data)
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
	int state = -1;
	int ret = -1;
	const char message[256] = {'\0'};
	strncpy(message, _("Continue Downgrade?"), 255);
	state = _ri_get_backend_state_info();
	_d_msg(DEBUG_INFO, "_ri_get_backend_state_info: state[%d]\n", state);
	switch (state) {
	case REQUEST_ACCEPTED:
		break;
	case GOT_PACKAGE_INFO_SUCCESSFULLY:
		break;
	case REQUEST_PENDING:
		_ri_package_downgrade_information(message);
//		_ri_set_backend_state_info(REQUEST_ACCEPTED);
		_ri_set_backend_state_info(REQUEST_COMPLETED);
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
		return -1;
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
	Ecore_Idler *popup_handle = NULL;
	ops.create = app_create;
	ops.terminate = app_terminate;
	ops.pause = app_pause;
	ops.resume = app_resume;
	ops.reset = app_reset;
	ops.data = &ad;
	ecore_init();
	appcore_set_i18n(PACKAGE, LOCALE_PATH);
	_d_msg_init("rpm-installer");
	data = (ri_frontend_cmdline_arg *) calloc(1,
						  sizeof
						  (ri_frontend_cmdline_arg));
	if (data == NULL) {
		_d_msg(DEBUG_ERR, "Not Enough Memory\n");
		ret = RPM_INSTALLER_ERR_NOT_ENOUGH_MEMORY;
		goto ERROR;
	}
	data->keyid = NULL;
	data->pkg_name = NULL;
	data->quiet = 0;
	data->req_cmd = INVALID_CMD;

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
	popup_handle = ecore_idler_add(show_popup_cb, NULL);

	_d_msg(DEBUG_RESULT, "About to run EFL Main Loop");
	appcore_efl_main(PACKAGE, &argc, &argv, &ops);
	_d_msg(DEBUG_RESULT, "%d\n", ret_val);

	_d_msg_deinit();
	if (pi) {
		pkgmgr_installer_free(pi);
		pi = NULL;
	}
	return ret_val;

 ERROR:
	if (data) {
		if (data->pkg_name) {
			free(data->pkg_name);
			data->pkg_name = NULL;
		}
		if (data->keyid) {
			free(data->keyid);
			data->keyid = NULL;
		}
		free(data);
		data = NULL;
	}
	_d_msg(DEBUG_RESULT, "%d\n", ret);
	_d_msg_deinit();
	return ret;

}
