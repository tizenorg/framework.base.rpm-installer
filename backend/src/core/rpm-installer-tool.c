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

#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <getopt.h>
#include <fcntl.h>
#include <dirent.h>
#include <unistd.h>
#include <ctype.h>
#include <rpmlib.h>
#include <header.h>
#include <rpmts.h>
#include <rpmdb.h>
#include "rpm-installer.h"
#include "rpm-frontend.h"
#include <pkgmgr_installer.h>

#define RPM	"/usr/etc/package-manager/backend/rpm"
#define BUFF_SIZE			256

char *gpkgname = NULL;
extern char scrolllabel[256];
extern int move_type;
enum optionsflags {
	INVALID_OPTIONS = 0,
	FORCE_OVERWITE = 1,
	IGNORE_DEPENDS = 2,
};

struct ri_backend_data_t {
	int req_cmd;
	char *cmd_string;
	char *pkgid;
	int force_overwrite;
};

typedef struct ri_backend_data_t ri_backend_data;
static int __ri_native_recovery(int lastbackstate);
static int __ri_uninstall_package(char *pkgid);
static int __ri_clear_private_data(char *pkgid);
static int __ri_move_package(char *pkgid, int move_type);
static inline int __ri_read_proc(const char *path, char *buf, int size);
static inline int __ri_find_pid_by_cmdline(const char *dname,
					   const char *cmdline,
					   const char *priv);
static bool __ri_is_another_instance_running(const char *exepath);

static int __ri_uninstall_package(char *pkgid)
{

	if (pkgid == NULL)
		return RPM_INSTALLER_ERR_WRONG_PARAM;
	int ret = 0;
	ret = _rpm_installer_package_uninstall(pkgid);
	if (ret == RPM_INSTALLER_ERR_PACKAGE_NOT_INSTALLED) {
		_d_msg(DEBUG_ERR, "[__ri_uninstall_package]%s "
		       "not installed\n", pkgid);
	} else if (ret != 0) {
		_d_msg(DEBUG_ERR,
		       "[__ri_uninstall_package]%s uninstall failed(%d)\n",
		       pkgid, ret);
	} else {
		_d_msg(DEBUG_ERR,
		       "[__ri_uninstall_package]%s successfully uninstalled\n",
		       pkgid);
	}
	return ret;
}

static int __ri_clear_private_data(char *pkgid)
{
	if (pkgid == NULL)
		return RPM_INSTALLER_ERR_WRONG_PARAM;
	int ret = 0;
	ret = _rpm_installer_clear_private_data(pkgid);
	if (ret == RPM_INSTALLER_SUCCESS) {
		_d_msg(DEBUG_ERR,
		       "[__clear_private_data]%s clear data successful\n",
		       pkgid);
	} else {
		_d_msg(DEBUG_ERR,
		       "[__clear_private_data]%s clear data failed(%d)\n",
		       pkgid, ret);
	}
	return ret;
}

static int __ri_move_package(char *pkgid, int move_type)
{
	if (pkgid == NULL)
		return RPM_INSTALLER_ERR_WRONG_PARAM;
	int ret = 0;
	ret = _rpm_move_pkg(pkgid, move_type);
	if (ret == RPM_INSTALLER_SUCCESS) {
		_d_msg(DEBUG_ERR,
		       "[__ri_move_package]%s move successful\n",
		       pkgid);
	} else {
		_d_msg(DEBUG_ERR,
		       "[__ri_move_package]%s move failed(%d)\n",
		       pkgid, ret);
	}
	return ret;
}

static inline int __ri_read_proc(const char *path, char *buf, int size)
{
	int fd;
	int ret;

	if (buf == NULL || path == NULL)
		return -1;

	fd = open(path, O_RDONLY);
	if (fd < 0)
		return -1;

	ret = read(fd, buf, size - 1);
	if (ret <= 0) {
		close(fd);
		return -1;
	} else
		buf[ret] = 0;

	close(fd);

	return ret;
}

static inline int __ri_find_pid_by_cmdline(const char *dname,
					   const char *cmdline,
					   const char *priv)
{
	int pid = 0;
	if (strncmp(cmdline, priv, strlen(RPM)) == 0) {
		pid = atoi(dname);
		if (pid != getpgid(pid))
			pid = 0;
		if (pid == getpid())
			pid = 0;
	}

	return pid;
}

static bool __ri_is_another_instance_running(const char *exepath)
{
	DIR *dp;
	struct dirent *dentry;
	int pid;
	int ret;
	char buf[256] = { 0, };
	char buf1[256] = { 0, };
	dp = opendir("/proc");
	if (dp == NULL) {
		return 0;
	}
	while ((dentry = readdir(dp)) != NULL) {
		if (!isdigit(dentry->d_name[0]))
			continue;
		snprintf(buf, sizeof(buf), "/proc/%s/cmdline", dentry->d_name);
		ret = __ri_read_proc(buf, buf1, sizeof(buf));
		if (ret <= 0)
			continue;
		pid = __ri_find_pid_by_cmdline(dentry->d_name, buf1, exepath);
		if (pid > 0) {
			closedir(dp);
			return 1;
		}
	}

	closedir(dp);
	return 0;

}

static int __ri_native_recovery(int lastbackstate)
{
	char *pn = NULL;
	int lreq;
	int opt;
	int err = 0;

	_d_msg(DEBUG_INFO, "Rpm Installer Recovery Entry \n");

	/* which package it was installing and what was state at that time */
	_ri_get_last_input_info(&pn, &lreq, &opt);

	switch (lastbackstate) {
	case REQUEST_ACCEPTED:
	case GOT_PACKAGE_INFO_SUCCESSFULLY:
		/*
		 * restart the last operation
		 */
		_d_msg(DEBUG_INFO,
			      "Rpm Installer Recovery started. state=%d \n", lastbackstate);
		switch (lreq) {
		case INSTALL_CMD:
			err =
			    _rpm_installer_package_install(pn, true, "--force");
			if (err)
				goto RECOVERYERROR;
			break;

		case DELETE_CMD:
			err = _rpm_installer_package_uninstall(pn);
			if (err)
				goto RECOVERYERROR;
			break;

		case CLEARDATA_CMD:
		case MOVE_CMD:
		case RECOVER_CMD:
			/*TODO*/
			_d_msg(DEBUG_INFO,
					"Recovery of command(%d) is to be implemented\n", lreq);
			return 0;
		}
		_d_msg(DEBUG_INFO,
			      " Rpm Installer Recovery Ended \n");
		break;
	case REQUEST_COMPLETED:
		_d_msg(DEBUG_INFO,
			      " Rpm Installer Recovery. Nothing To Be Done\n");
		_ri_set_backend_state_info(REQUEST_COMPLETED);
		break;

	case REQUEST_PENDING:
		_d_msg(DEBUG_INFO,
				"Rpm Installer Recovery started. state=%d\n", lastbackstate);
		/*Only package downgradation can be the case*/
		err = _rpm_installer_package_install(pn, true, "--force");
		if (err != RPM_INSTALLER_SUCCESS &&
			err != RPM_INSTALLER_ERR_NEED_USER_CONFIRMATION) {
			goto RECOVERYERROR;
		}
		_d_msg(DEBUG_INFO,
			      " Rpm Installer Recovery ended \n");
		_ri_set_backend_state_info(REQUEST_COMPLETED);
		break;

	default:
		/*
		 * Unknown state
		 * No need to recover
		 */
		_d_msg(DEBUG_INFO,
			      " Rpm Installer Recovery Default state \n");
		break;

	}
	return 0;

 RECOVERYERROR:
	_d_msg(DEBUG_ERR, "Error in Recovery error number = (%d)\n",
		      err);
	return err;

}

static int __ri_check_root_path(const char *pkgid)
{
	char dirpath[BUFF_SIZE] = {'\0'};
	struct stat stFileInfo;

	snprintf(dirpath, BUFF_SIZE, "/usr/apps/%s", pkgid);

	(void)stat(dirpath, &stFileInfo);

	if (S_ISDIR(stFileInfo.st_mode)) {
		return 0;	//it menas "/usr/apps/pkgid"
	}
	return 1;		//it menas "/opt/usr/apps/pkgid"
}

static int __ri_process_smack(char *keyid, char *pkgid)
{
	int ret = 0;

	/*apply smack for ug*/
	if(strcmp(keyid,"ug-smack")==0) {
		_d_msg(DEBUG_INFO, "only apply smack for ug\n");
		char *perm[] = {"http://tizen.org/privilege/appsetting", NULL};
		_ri_apply_smack(pkgid,__ri_check_root_path(pkgid));
		_ri_privilege_enable_permissions(pkgid, 1, perm, 1);
	/*apply smack for rpm package*/
	} else if (strcmp(keyid,"rpm-smack")==0) {
		_d_msg(DEBUG_INFO, "apply smack for rpm\n");
		_ri_apply_smack(pkgid,__ri_check_root_path(pkgid));
	/*register xml to db, call pkgmgr parser*/
	} else if (strcmp(keyid,"core-xml")==0) {
		_d_msg(DEBUG_INFO, "install corexml\n");
		ret = _rpm_installer_corexml_install(pkgid);
		if (ret != 0) {
			_d_msg(DEBUG_ERR, "corexml_install failed with err(%d)\n", ret);
		} else {
			_d_msg(DEBUG_INFO, "corexml_install success\n");
		}
	/*apply privilege for rpm package*/
	} else if (strcmp(keyid,"rpm-perm")==0) {
		_d_msg(DEBUG_INFO, "apply permmissions for rpm\n");
		ret = _ri_apply_perm(pkgid);
		if (ret != 0) {
			_d_msg(DEBUG_ERR, "apply perm failed with err(%d)\n", ret);
		} else {
			_d_msg(DEBUG_INFO, "apply perm success\n");
		}
	/*check csc xml*/
	} else if (strcmp(keyid,"csc-xml")==0) {
		_d_msg(DEBUG_INFO, "csc xml for rpm\n");
		ret = _rpm_process_cscxml(pkgid);
		if (ret != 0) {
			_d_msg(DEBUG_ERR, "install csc xml failed with err(%d)\n", ret);
		} else {
			_d_msg(DEBUG_INFO, "install csc xml success\n");
		}
	/*check fota*/
	} else if (strcmp(keyid,"rpm-fota")==0) {
		_d_msg(DEBUG_INFO, "fota process for rpm\n");
		ret = _rpm_process_fota(pkgid);
		if (ret != 0) {
			_d_msg(DEBUG_ERR, "fota process failed with err(%d)\n", ret);
		} else {
			_d_msg(DEBUG_INFO, "fota process success\n");
		}
	/*check fota*/
	} else if (strcmp(keyid,"rpm-rw-fota")==0) {
		_d_msg(DEBUG_INFO, "rw fota process for rpm\n");
		ret = _rpm_process_fota_for_rw(pkgid);
		if (ret != 0) {
			_d_msg(DEBUG_ERR, "rw fota process failed with err(%d)\n", ret);
		} else {
			_d_msg(DEBUG_INFO, "rw fota process success\n");
		}
	} else {
		_d_msg(DEBUG_ERR, "smack cmd error\n");
		ret = -1;
	}

	return ret;
}

int _rpm_backend_interface(char *keyid, char *pkgid, char *reqcommand)
{
	int ret = -1;
	ri_backend_data data = { 0 };
	int backendstate;
	rpmRC rc;
	if (reqcommand == NULL) {
		_d_msg(DEBUG_ERR, "reqcommand is NULL\n");
		return RPM_INSTALLER_ERR_WRONG_PARAM;
	}
	if (keyid == NULL || pkgid == NULL) {
		if (strncmp(reqcommand, "recover", strlen("recover"))) {
			_d_msg(DEBUG_ERR, " Either keyid/pkgid is NULL\n");
			return RPM_INSTALLER_ERR_WRONG_PARAM;
		}
	}

	if (strncmp(reqcommand, "install", strlen("install")) == 0) {
		data.req_cmd = INSTALL_CMD;
		data.cmd_string = strdup("install");
		if (data.cmd_string == NULL) {
			_d_msg(DEBUG_ERR,
			       "strdup failed due to insufficient memory\n");
			return RPM_INSTALLER_ERR_NOT_ENOUGH_MEMORY;
		}
	} else if (strncmp(reqcommand, "remove", strlen("remove")) == 0) {
		data.req_cmd = DELETE_CMD;
		data.cmd_string = strdup("uninstall");
		if (data.cmd_string == NULL) {
			_d_msg(DEBUG_ERR,
			       "strdup failed due to insufficient memory\n");
			return RPM_INSTALLER_ERR_NOT_ENOUGH_MEMORY;
		}
	} else if (strncmp(reqcommand, "recover", strlen("recover")) == 0) {
		data.req_cmd = RECOVER_CMD;
		data.cmd_string = strdup("recover");
		if (data.cmd_string == NULL) {
			_d_msg(DEBUG_ERR,
			       "strdup failed due to insufficient memory\n");
			return RPM_INSTALLER_ERR_NOT_ENOUGH_MEMORY;
		}
	} else if (strncmp(reqcommand, "cleardata", strlen("cleardata")) == 0) {
		data.req_cmd = CLEARDATA_CMD;
		data.cmd_string = strdup("cleardata");
		if (data.cmd_string == NULL) {
			_d_msg(DEBUG_ERR,
			       "strdup failed due to insufficient memory\n");
			return RPM_INSTALLER_ERR_NOT_ENOUGH_MEMORY;
		}
	} else if (strncmp(reqcommand, "move", strlen("move")) == 0) {
		data.req_cmd = MOVE_CMD;
		data.cmd_string = strdup("move");
		if (data.cmd_string == NULL) {
			_d_msg(DEBUG_ERR,
			       "strdup failed due to insufficient memory\n");
			return RPM_INSTALLER_ERR_NOT_ENOUGH_MEMORY;
		}
	} else if (strncmp(reqcommand, "smack", strlen("smack")) == 0) {
		return __ri_process_smack(keyid, pkgid);
	} else if (strncmp(reqcommand, "eflwgt-install", strlen("eflwgt-install")) == 0) {
		return _rpm_installer_package_install_with_dbpath(pkgid);
	} else if (strncmp(reqcommand, "eflwgt-remove", strlen("eflwgt-remove")) == 0) {
		return _rpm_installer_package_uninstall_with_dbpath(pkgid);
	} else if (strncmp(reqcommand, "rpm-enable", strlen("rpm-enable")) == 0) {
		if (strstr(pkgid, ":") == NULL)
			ret = _rpm_process_enable(pkgid);
		else
			ret = _rpm_process_enabled_list(pkgid);
		return ret;
	} else if (strncmp(reqcommand, "rpm-disable", strlen("rpm-disable")) == 0) {
		if (strstr(pkgid, ":") == NULL)
			ret = _rpm_process_disable(pkgid);
		else
			ret = _rpm_process_disabled_list(pkgid);
		return ret;
	} else {
		_d_msg(DEBUG_INFO, "wrong input parameter\n");
		_d_msg(DEBUG_RESULT, "%d\n", RPM_INSTALLER_ERR_WRONG_PARAM);
		return RPM_INSTALLER_ERR_WRONG_PARAM;
	}

	data.pkgid = pkgid;
	backendstate = _ri_get_backend_state();

	rc = rpmReadConfigFiles(NULL, NULL);
	if (rc == RPMRC_OK) {
		_d_msg(DEBUG_INFO, "Successfully read rpm configuration\n");
	} else {
		_d_msg(DEBUG_ERR, "Unable to read RPM configuration.\n");
		if (data.cmd_string) {
			free(data.cmd_string);
			data.cmd_string = NULL;
		}
		return RPM_INSTALLER_ERR_INTERNAL;
	}

	if (RECOVER_CMD == data.req_cmd) {
		if (0 == backendstate) {
			int lastbackstate;

			/* check the current state of backend */
			lastbackstate = _ri_get_backend_state_info();

			if (REQUEST_COMPLETED == lastbackstate) {
				_d_msg(DEBUG_INFO,
				       " Rpm Installer recovery is in REQUEST_COMPLETED  \n");
				snprintf(scrolllabel, sizeof(scrolllabel),
					 "No Recovery Needed");
			} else
				ret = __ri_native_recovery(lastbackstate);
			if (ret == 0)
				snprintf(scrolllabel, sizeof(scrolllabel),
					 "Recovery Success");
			else
				snprintf(scrolllabel, sizeof(scrolllabel),
					"Recovery Failed");

			/* set the backend state as completed */
			_ri_set_backend_state(1);
		} else {
			/* nothing to recover */
			_d_msg(DEBUG_INFO,
			       " Rpm Installer recovery Nothing to be done\n");
			ret = 0;
			snprintf(scrolllabel, sizeof(scrolllabel),
				 "No Recovery Needed");
		}
		_d_msg(DEBUG_RESULT, "%d\n", ret);
		if (data.cmd_string) {
			free(data.cmd_string);
			data.cmd_string = NULL;
		}
		return ret;

	}
	if (backendstate == 0) {

		/* Non Recovery case
		 *
		 * Another Instance may be running
		 * or something went wrong in last execution
		 * Check for it
		 */
		if (__ri_is_another_instance_running(RPM)) {
			if (data.pkgid) {
				_ri_broadcast_status_notification
				    (data.pkgid, "error",
				     "Another Instance Running");
				_ri_stat_cb(data.pkgid, "error",
					    "Another Instance Running");
				_ri_broadcast_status_notification
				    (data.pkgid, "end", "fail");
				_ri_stat_cb(data.pkgid, "end",
					    "fail");
			} else {
				_ri_broadcast_status_notification
				    ("unknown", "error",
				     "Another Instance Running");
				_ri_stat_cb("unknown", "error",
					    "Another Instance Running");
				_ri_broadcast_status_notification
				    ("unknown", "end", "fail");
				_ri_stat_cb("unknown", "end", "fail");
			}
			_d_msg(DEBUG_INFO,
			       "Request Failed as "
			       "Another Instance is running \n");
			ret = RPM_INSTALLER_ERR_RESOURCE_BUSY;
			if (data.cmd_string) {
				free(data.cmd_string);
				data.cmd_string = NULL;
			}
			return ret;
		} else {
			int lastbackstate;

			/* check the current state of backend */
			lastbackstate = _ri_get_backend_state_info();

			/* Publish Notification that backend has started */
//			_ri_broadcast_status_notification(data.pkgid, "start", data.cmd_string);
//			_ri_broadcast_status_notification(data.pkgid, "command", data.cmd_string);

			if (REQUEST_COMPLETED == lastbackstate) {
				_d_msg(DEBUG_INFO,
				       " Rpm Installer recovery"
				       " is in REQUEST_COMPLETED  \n");
				ret = 0;
			} else
				ret = __ri_native_recovery(lastbackstate);
			if (ret != 0) {
				_d_msg(DEBUG_INFO,
					"recovery of last request failed\n");
			} else {
				_d_msg(DEBUG_INFO,
				       "recovery of last request success\n");
			}

			/* set the backend state as completed */
			_ri_set_backend_state(1);
		}
	}

	/* set the backend state as started for the current request*/
	_ri_set_backend_state(0);

#ifdef SEND_PKGPATH
	gpkgname = strdup(data.pkgid);

	/* Publish Notification that backend has started */
	if (data.pkgid)
		_ri_broadcast_status_notification(data.pkgid, "start",
						  data.cmd_string);
	else
		_ri_broadcast_status_notification("unknown", "start",
						  data.cmd_string);
#endif

	_ri_set_backend_state_info(REQUEST_ACCEPTED);

	/* Set the input request info */
	_ri_save_last_input_info(data.pkgid, data.req_cmd,
				 data.force_overwrite);

	switch (data.req_cmd) {
	case INSTALL_CMD:
		{
			_d_msg(DEBUG_INFO, "[%s] --install %s\n",
			       "backend", data.pkgid);
#ifdef SEND_PKGPATH
			_ri_broadcast_status_notification(data.pkgid,
							  "command", "Install");
#endif
			if (data.force_overwrite == FORCE_OVERWITE) {
				_d_msg(DEBUG_INFO,
				       "[%s] --install %s --force-overwrite\n",
				       "backend", data.pkgid);
				ret =
				    _rpm_installer_package_install
				    (data.pkgid, true, "--force");
			} else {
				if(data.pkgid == NULL) {
					_d_msg(DEBUG_ERR, "pkgid is null");
					break;
				}
				_d_msg(DEBUG_INFO, "[%s] --install %s\n",
				       "backend", data.pkgid);
				ret =
				    _rpm_installer_package_install
				    (data.pkgid, false, NULL);
			}
			if (ret == RPM_INSTALLER_ERR_NEED_USER_CONFIRMATION) {
				break;
			} else if (ret == RPM_INSTALLER_SUCCESS) {
				_d_msg(DEBUG_INFO, "install success\n");
				_ri_broadcast_status_notification(data.pkgid,
								  "end", "ok");
				_ri_stat_cb(data.pkgid, "end", "ok");
			} else {

				char *errstr = NULL;
				_ri_error_no_to_string(ret, &errstr);
				_ri_broadcast_status_notification(data.pkgid,
								  "error",
								  errstr);
				_ri_stat_cb(data.pkgid, "error", errstr);
				_ri_broadcast_status_notification(data.pkgid,
								  "end",
								  "fail");
				sleep(2);
				_ri_stat_cb(data.pkgid, "end", "fail");
				_d_msg(DEBUG_ERR,
				       "install failed with err(%d) (%s)\n",
				       ret, errstr);
			}
		}
		break;
	case DELETE_CMD:
		{
			_d_msg(DEBUG_INFO, "[%s] uninstall %s\n",
			       "backend", data.pkgid);
#ifdef SEND_PKGPATH
			_ri_broadcast_status_notification(data.pkgid,
							  "command", "Remove");
#endif
			ret = __ri_uninstall_package(data.pkgid);
			if (ret != 0) {
				char *errstr = NULL;
				_ri_error_no_to_string(ret, &errstr);
				_ri_broadcast_status_notification(data.pkgid,
								  "error",
								  errstr);
				_ri_stat_cb(data.pkgid, "error", errstr);
				sleep(2);
				_ri_broadcast_status_notification(data.pkgid,
								  "end",
								  "fail");
				_ri_stat_cb(data.pkgid, "end", "fail");
				_d_msg(DEBUG_ERR,
				       "remove failed with err(%d) (%s)\n",
				       ret, errstr);
			} else {
				_d_msg(DEBUG_INFO, "remove success\n");
				_ri_broadcast_status_notification(data.pkgid,
								  "end", "ok");
				_ri_stat_cb(data.pkgid, "end", "ok");
			}
		}
		break;
	case CLEARDATA_CMD:
		{
			_d_msg(DEBUG_INFO, "[%s] clear data %s\n",
			       "backend", data.pkgid);
#ifdef SEND_PKGPATH
			_ri_broadcast_status_notification(data.pkgid,
							  "command", "clear");
#endif
			ret = __ri_clear_private_data(data.pkgid);
			if (ret != 0) {
				char *errstr = NULL;
				_ri_error_no_to_string(ret, &errstr);
				_ri_broadcast_status_notification(data.pkgid,
								  "error",
								  errstr);
				_ri_stat_cb(data.pkgid, "error", errstr);
				_ri_broadcast_status_notification(data.pkgid,
								  "end",
								  "fail");
				_ri_stat_cb(data.pkgid, "end", "fail");
				_d_msg(DEBUG_ERR,
				       "clear data failed with err(%d) (%s)\n",
				       ret, errstr);
			} else {
				_d_msg(DEBUG_INFO, "clear data success\n");
				_ri_broadcast_status_notification(data.pkgid,
								  "end", "ok");
				_ri_stat_cb(data.pkgid, "end", "ok");
			}
			break;
		}
	case MOVE_CMD:
		{
			_d_msg(DEBUG_INFO, "[%s] move %s\n",
			       "backend", data.pkgid);
#ifdef SEND_PKGPATH
			_ri_broadcast_status_notification(data.pkgid,
							  "command", "move");
#endif
			ret = __ri_move_package(data.pkgid, move_type);
			if (ret != 0) {
				char *errstr = NULL;
				_ri_error_no_to_string(ret, &errstr);
				_ri_broadcast_status_notification(data.pkgid,
								  "error",
								  errstr);
				_ri_stat_cb(data.pkgid, "error", errstr);
				_ri_broadcast_status_notification(data.pkgid,
								  "end",
								  "fail");
				_ri_stat_cb(data.pkgid, "end", "fail");
				_d_msg(DEBUG_ERR,
				       "move failed with err(%d) (%s)\n",
				       ret, errstr);
			} else {
				_d_msg(DEBUG_INFO, "move success\n");
				_ri_broadcast_status_notification(data.pkgid,
								  "end", "ok");
				_ri_stat_cb(data.pkgid, "end", "ok");
			}
			break;
		}

	default:
		{
			_ri_broadcast_status_notification("unknown", "command",
							  "unknown");
			_ri_broadcast_status_notification("unknown", "error",
							  "not supported");
			_ri_stat_cb("unknown", "error", "not supported");
			_ri_broadcast_status_notification("unknown",
							  "end", "fail");
			_ri_stat_cb("unknown", "end", "fail");
			_d_msg(DEBUG_ERR, "unknown command \n");
			ret = RPM_INSTALLER_ERR_WRONG_PARAM;
		}
	}

	if (gpkgname) {
		free(gpkgname);
		gpkgname = NULL;
	}

	if (data.cmd_string) {
		free(data.cmd_string);
		data.cmd_string = NULL;
	}

	if (_ri_get_backend_state_info() != REQUEST_PENDING) {
		_ri_set_backend_state_info(REQUEST_COMPLETED);
		/* set the backend state as completed */
		_ri_set_backend_state(1);
		_d_msg(DEBUG_INFO, "%d\n", ret);
		_d_msg_deinit();
	}
	return ret;
}
