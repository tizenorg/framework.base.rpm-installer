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

#include <appcore-efl.h>
#include <Ecore_X.h>
#include <pthread.h>
#include "rpm-frontend.h"
#include "rpm-installer-util.h"
#include "rpm-homeview.h"
#include "rpm-installer.h"

#define DESKTOP_W   720.0

extern struct appdata ad;
int do_upgrade = -1;
extern ri_frontend_data front_data;
Evas_Object *popup_global;

static void __ri_response_cb1(void *data, Evas_Object *obj, void *event);
static void __ri_response_cb2(void *data, Evas_Object *obj, void *event);
static void __ri_win_del(void *data, Evas_Object *obj, void *event);
static Eina_Bool __ri_perform_downgrade(void *data);

void _ri_information_popup(Evas_Smart_Cb func, const char *output,
			   void *user_param)
{
	if (!ad.win_main)
		return;
	evas_object_show(ad.win_main);
	Evas_Object *popup = NULL;
	popup = elm_popup_add(ad.win_main);
	if (!popup)
		return;
	elm_object_part_text_set(popup, "Information", NULL);
	evas_object_size_hint_weight_set(popup, EVAS_HINT_EXPAND,
					 EVAS_HINT_EXPAND);
	elm_object_text_set(popup, output);
	Evas_Object *button = NULL;
	button = elm_button_add(popup);
	elm_object_text_set(button, "Ok");
	elm_object_part_content_set(popup, "button1", button);
	evas_object_smart_callback_add(button, "clicked", func, user_param);
	evas_object_show(popup);
}

void _ri_package_downgrade_popup(Evas_Smart_Cb func1,
				Evas_Smart_Cb func2,
				const char *output, void *user_param)
{
	if (!ad.win_main)
		return;
	evas_object_show(ad.win_main);
	Evas_Object *popup = NULL;
	popup = elm_popup_add(ad.win_main);
	if (!popup)
		return;
	elm_object_part_text_set(popup, "Information", NULL);
	evas_object_size_hint_weight_set(popup, EVAS_HINT_EXPAND,
				 EVAS_HINT_EXPAND);
	elm_object_text_set(popup, output);
	Evas_Object *button1 = NULL;
	Evas_Object *button2 = NULL;
	button1 = elm_button_add(popup);
	elm_object_text_set(button1, "Yes");
	elm_object_part_content_set(popup, "button1", button1);
	evas_object_smart_callback_add(button1, "clicked", func1, user_param);

	button2 = elm_button_add(popup);
	elm_object_text_set(button2, "No");
	elm_object_part_content_set(popup, "button2", button2);
	evas_object_smart_callback_add(button2, "clicked", func2, user_param);
	popup_global = popup;
	evas_object_show(popup);
}

static void __ri_win_del(void *data, Evas_Object *obj, void *event)
{
	elm_exit();
}

static Eina_Bool __ri_perform_downgrade(void *data)
{
	int ret = -1;
	ret = _rpm_installer_package_install(front_data.args->pkgid,
					     true, "--force");
	if (ret != 0) {
		char *errstr = NULL;
		_ri_error_no_to_string(ret, &errstr);
		_ri_broadcast_status_notification(front_data.args->pkgid,
						  "error", errstr);
		_ri_stat_cb(front_data.args->pkgid, "error", errstr);
		_ri_broadcast_status_notification(front_data.args->pkgid,
						  "end", "fail");
		_ri_stat_cb(front_data.args->pkgid, "end", "fail");
		_d_msg(DEBUG_ERR,
		       "install failed with err(%d) (%s)\n", ret, errstr);
	} else {
		_d_msg(DEBUG_INFO, "install success\n");
		_ri_broadcast_status_notification(front_data.args->pkgid,
						  "end", "ok");
		_ri_stat_cb(front_data.args->pkgid, "end", "ok");
	}
	_ri_set_backend_state_info(REQUEST_COMPLETED);
	_ri_set_backend_state(1);
	return 0;
}

static void __ri_response_cb1(void *data, Evas_Object *obj, void *event)
{
	printf("\nresponse callback=%d\n", (int)event);
	do_upgrade = 1;

	ecore_idler_add(__ri_perform_downgrade, NULL);
	_d_msg(DEBUG_INFO, "doUpgrade is %d\n", do_upgrade);
	evas_object_del(obj);
	evas_object_del(popup_global);
	obj = NULL;
}
static void __ri_response_cb2(void *data, Evas_Object *obj, void *event)
{
	printf("\nresponse callback=%d\n", (int)event);
	do_upgrade = 0;

	ecore_idler_add(__ri_perform_downgrade, NULL);
	evas_object_del(obj);
	evas_object_del(popup_global);
	_d_msg(DEBUG_INFO, "doUpgrade is %d\n", do_upgrade);
	obj = NULL;
}

Eina_Bool _ri_init_appdata(struct appdata *user_data)
{
	unsigned char *prop_data = NULL;
	int rotation = 0;
	int w;
	int h;
	int x;
	int y;
	int count = 0;
	user_data->win_main = elm_win_add(NULL, PACKAGE, ELM_WIN_DIALOG_BASIC);
	if (!user_data->win_main)
		return EINA_FALSE;

	elm_win_title_set(user_data->win_main, PACKAGE);
	elm_win_alpha_set(user_data->win_main, EINA_TRUE);
	elm_win_borderless_set(user_data->win_main, EINA_TRUE);
	elm_win_raise(user_data->win_main);
	ecore_x_window_geometry_get(ecore_x_window_root_get
				    (ecore_x_window_focus_get()), &x, &y, &w,
				    &h);
	int ret =
	    ecore_x_window_prop_property_get(ecore_x_window_root_get
				     (ecore_x_window_focus_get()),
				     ECORE_X_ATOM_E_ILLUME_ROTATE_ROOT_ANGLE,
				     ECORE_X_ATOM_CARDINAL, 32,
				     &prop_data, &count);
	if (ret && prop_data)
		memcpy(&rotation, prop_data, sizeof(int));
	if (prop_data)
		free(prop_data);
	evas_object_resize(user_data->win_main, w, h);
	evas_object_move(user_data->win_main, x, y);
	/*evas_object_show(user_data->win_main);
	evas_object_smart_callback_add(user_data->win_main, "delete,request",
				       __ri_win_del, NULL);
	elm_win_indicator_state_set(user_data->win_main, EINA_TRUE);*/

	if (elm_win_wm_rotation_supported_get(user_data->win_main)) {
		int rots[4] = { 0, 90, 180, 270 };
		elm_win_wm_rotation_available_rotations_set(user_data->win_main, &rots, 4);
	}

	double s;
	s = w / DESKTOP_W;
	elm_config_scale_set(s);
	user_data->evas = evas_object_evas_get(user_data->win_main);
	if (!user_data->evas)
		return EINA_FALSE;

	return EINA_TRUE;
}

Eina_Bool _ri_init_home_view(struct appdata *user_data)
{
	return EINA_TRUE;

}

void _ri_destroy_home_view(struct appdata *user_data)
{

	if (!user_data) {
		return;
	}
	evas_object_del(user_data->main_view);
}

int _ri_frontend_launch_main_view(struct appdata *data)
{
	/* create UI */
	if (!_ri_init_appdata(data)) {
		return 0;
	}
	if (!_ri_init_home_view(data)) {
		return 0;
	}
	return 0;
}

void _ri_frontend_update_progress_info(struct appdata *data, char *progressinfo)
{
	elm_object_text_set(data->scrollbar_label, progressinfo);
	_ri_information_popup(__ri_win_del, progressinfo, data);
}

void _ri_package_downgrade_information(const char *message)
{
	_ri_package_downgrade_popup(__ri_response_cb1, __ri_response_cb2, message, &ad);
}
