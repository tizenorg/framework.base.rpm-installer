/*
 * coretpk-dbus
 *
 * Copyright (c) 2000 - 2011 Samsung Electronics Co., Ltd. All rights reserved.
 *
 * Contact: Vineet Mimrot <v.mimrot@samsung.com>
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

#ifdef _APPFW_FEATURE_MOUNT_INSTALL
#include <dbus/dbus.h>
#include <dbus/dbus-glib-lowlevel.h>
#include <unistd.h>
#include <stdio.h>

#include "coretpk-installer-internal.h"
#include "installer-type.h"
#include <stdlib.h>

int _coretpk_dbus_mount_file(char *mnt_path[], const char *pkgid)
{

	_LOGD("_coretpk_dbus_mount_file called");
	DBusMessage *msg;
	int func_ret = 0;
	int rv = 0;
	struct stat link_buf = {0,};
	DBusError err;

	DBusConnection *conn = dbus_bus_get(DBUS_BUS_SYSTEM, NULL);
	if(!conn){
		_LOGE("DBUS Connection Error");
		return -1;
	}

	rv = lstat(mnt_path[0], &link_buf);
	if (rv == 0) {
		rv = unlink(mnt_path[0]);
		if (rv)
			_LOGE("Unable to remove link file [%s]", mnt_path[0]);
	}

	msg = dbus_message_new_method_call(TZIP_BUS_NAME, TZIP_OBJECT_PATH, TZIP_INTERFACE_NAME, TZIP_MOUNT_METHOD);
	if(!msg) {
		_LOGE("dbus_message_new_method_call(%s:%s-%s)", TZIP_OBJECT_PATH, TZIP_INTERFACE_NAME, TZIP_MOUNT_METHOD);
		return -1;
	}

	if (!dbus_message_append_args(msg,
					DBUS_TYPE_STRING, &mnt_path[0],
					DBUS_TYPE_STRING, &mnt_path[1],
					DBUS_TYPE_STRING, &pkgid,
					DBUS_TYPE_INVALID))
	{
		_LOGE("Ran out of memory while constructing args\n");
		func_ret = -1;
		goto func_out;
	}

	if(dbus_connection_send(conn, msg, NULL) == FALSE) {
		_LOGE("dbus_connection_send error");
		func_ret = -1;
		goto func_out;
	}
func_out :
	dbus_message_unref(msg);
	_LOGE("__tpk_mount finished");
	return func_ret;
}


int _coretpk_dbus_unmount_file(char *mnt_path)
{
	DBusError err;
	_LOGD("__tpk_unmount called [%s]", mnt_path);

	DBusConnection *conn = dbus_bus_get(DBUS_BUS_SYSTEM, NULL);
	if(!conn){
		_LOGE("DBUS Connection Error");
		return -1;
	}

	DBusMessage *msg = NULL;
	msg = dbus_message_new_method_call(TZIP_BUS_NAME, TZIP_OBJECT_PATH, TZIP_INTERFACE_NAME, TZIP_UNMOUNT_METHOD);
	if(!msg) {
		_LOGE("dbus_message_new_method_call(%s:%s-%s)", TZIP_OBJECT_PATH, TZIP_INTERFACE_NAME, TZIP_UNMOUNT_METHOD);
		return -1;
	}

	if (!dbus_message_append_args(msg,
					DBUS_TYPE_STRING, &mnt_path,
					DBUS_TYPE_INVALID))
	{
		_LOGE("Ran out of memory while constructing args\n");
		dbus_message_unref(msg);
		return -1;
	}

	if(dbus_connection_send(conn, msg, NULL) == FALSE)
	{
		_LOGE("dbus send error");
		dbus_message_unref(msg);
		return -1;
	}
	dbus_message_unref(msg);
	_LOGE("__tpk_unmount finished");
	return 0;
}


int _coretpk_dbus_is_mount_done(const char *mnt_path)
{
	_LOGD("_coretpk_dbus_is_mount_done called [%s]", mnt_path);
	DBusMessage *msg;
	DBusMessage *reply;
	DBusError err;
	int ret = -1;
	int r = -1;

	DBusConnection *conn = dbus_bus_get(DBUS_BUS_SYSTEM, NULL);
	if(!conn){
		_LOGE("DBUS Connection Error");
		return -1;
	}

	msg = dbus_message_new_method_call(TZIP_BUS_NAME, TZIP_OBJECT_PATH, TZIP_INTERFACE_NAME, TZIP_IS_MOUNTED_METHOD);
	if(!msg) {
		_LOGE("dbus_message_new_method_call(%s:%s-%s)", TZIP_OBJECT_PATH, TZIP_INTERFACE_NAME, TZIP_IS_MOUNTED_METHOD);
		return ret;
	}

	if (!dbus_message_append_args(msg,
					DBUS_TYPE_STRING, &mnt_path,
					DBUS_TYPE_INVALID)) {
		_LOGE("Ran out of memory while constructing args\n");
		dbus_message_unref(msg);
		return ret;
	}

	dbus_error_init(&err);
	reply = dbus_connection_send_with_reply_and_block(conn, msg, 500, &err);
	if (!reply) {
		_LOGE("dbus_connection_send error(%s:%s)", err.name, err.message);
		goto func_out;
	}

	r = dbus_message_get_args(reply, &err, DBUS_TYPE_INT32, &ret, DBUS_TYPE_INVALID);
	if (!r) {
		_LOGE("no message : [%s:%s]", err.name, err.message);
		goto func_out;
	}

func_out :
	dbus_message_unref(msg);
	dbus_error_free(&err);
	return ret;
}

int _coretpk_dbus_wait_for_tep_mount(const char *mnt_path)
{
	_LOGD("_coretpk_dbus_wait_for_tep_mount called [%s]", mnt_path);
	if(mnt_path) {
		int rv = -1;
		int cnt = 0;
		while(cnt < TZIP_MOUNT_MAXIMUM_RETRY_CNT) {
			rv = _coretpk_dbus_is_mount_done(mnt_path);
			_LOGE("cnt:%d",cnt);
			if(rv == 1)
				break;
			sleep(1);
			cnt++;
		}
		/* incase after trying 15 sec, not getting mounted then quit */
		if( rv != 1) {
			_LOGE("Not able to mount within 15 sec");
			return -1;
		}
	}
	return 0;
}
#endif

