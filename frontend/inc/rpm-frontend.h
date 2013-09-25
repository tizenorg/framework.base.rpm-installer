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

#ifndef __RPM_FRONTEND_H_
#define __RPM_FRONTEND_H_

#include <Elementary.h>
#include <pkgmgr_installer.h>
#include <bundle.h>

#ifndef APP_DIR
#define APP_DIR	"/usr"
#endif				/* APP_DIR */

#ifndef LOCALE_PATH
#define LOCALE_PATH		APP_DIR"/share/locale"
#endif				/* LOCALE_PATH */

#ifndef PACKAGE
#define PACKAGE	"rpm-installer"
#endif				/* PACKAGE */

enum command {
	INVALID_CMD = -1,
	INSTALL_CMD = 1,
	DELETE_CMD = 2,
	UPDATE_CMD = 3,
	RECOVER_CMD = 4,
	CLEARDATA_CMD = 5,
	MOVE_CMD = 6,
	SMACK_CMD = 7,
	RPM_CMD_MAX = 8,
};

struct ri_frontend_cmdline_arg_t {
	int req_cmd;
	char *pkgid;
	char *keyid;
	int quiet;
	int move_type;
};
typedef struct ri_frontend_cmdline_arg_t ri_frontend_cmdline_arg;

struct ri_frontend_data_t {
	ri_frontend_cmdline_arg *args;
	char *security_cookie;
	char *error;
};
typedef struct ri_frontend_data_t ri_frontend_data;

struct appdata {
	Evas *evas;
	Evas_Object *win_main;
	Evas_Coord root_w;
	Evas_Coord root_h;
	Evas_Object *main_view;	/* for main view layout */
	Evas_Object *scrollbar_label;
};

int app_create(void *user_data);
int app_terminate(void *user_data);
int app_pause(void *user_data);
int app_resume(void *user_data);
int app_reset(bundle *b, void *user_data);
/*mode is actually an enum defined in appcore [enum appcore_rm]*/
int app_rotation(int mode, void *user_data);

int _ri_cmdline_destroy(ri_frontend_data *data);
int _ri_cmdline_process(ri_frontend_data *data);
int _ri_parse_cmdline(int argc, char **argv, ri_frontend_cmdline_arg *data);
void _ri_stat_cb(const char *pkgid, const char *key, const char *val);

#endif				/* __RPM_FRONTEND_H_ */
