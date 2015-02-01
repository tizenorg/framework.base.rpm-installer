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
#include <pkgmgr_installer.h>

#include "rpm-installer.h"
#include "rpm-frontend.h"
#include "rpm-installer-type.h"

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
		_LOGE("[__ri_uninstall_package]%s "
		       "not installed\n", pkgid);
	} else if (ret != 0) {
		_LOGE(
		       "[__ri_uninstall_package]%s uninstall failed(%d)\n",
		       pkgid, ret);
	} else {
		_LOGE(
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
		_LOGE(
		       "[__clear_private_data]%s clear data successful\n",
		       pkgid);
	} else {
		_LOGE(
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
	if(gpkgname){
		free(gpkgname);
		gpkgname = NULL;
	}
	gpkgname = strdup(pkgid);
	if(!gpkgname){
		_LOGE("Malloc failed!!");
		return RPM_INSTALLER_ERR_INTERNAL;
	}
	ret = _rpm_move_pkg(pkgid, move_type);
	if (ret == RPM_INSTALLER_SUCCESS) {
		_LOGE(
		       "[__ri_move_package]%s move successful\n",
		       pkgid);
	} else {
		_LOGE(
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

	_LOGD("Rpm Installer Recovery Entry \n");

	/* which package it was installing and what was state at that time */
	_ri_get_last_input_info(&pn, &lreq, &opt);

	switch (lastbackstate) {
	case REQUEST_ACCEPTED:
	case GOT_PACKAGE_INFO_SUCCESSFULLY:
		/*
		 * restart the last operation
		 */
		_LOGD(
			      "Rpm Installer Recovery started. state=%d \n", lastbackstate);
		switch (lreq) {
		case INSTALL_CMD:
			err =
			    _rpm_installer_package_install(pn, true, "--force", NULL);
			if (err)
				goto RECOVERYERROR;
			break;

		case DELETE_CMD:
			err = _rpm_installer_package_uninstall(pn);
			if (err)
				goto RECOVERYERROR;
			break;
		case EFLWGT_INSTALL_CMD:
			err = _rpm_installer_package_uninstall(pn);
			if(err)
				goto RECOVERYERROR;
			break;

		case CLEARDATA_CMD:
		case MOVE_CMD:
		case RECOVER_CMD:
			/*TODO*/
			_LOGD(
					"Recovery of command(%d) is to be implemented\n", lreq);
			if(pn) free(pn);
			return 0;
		}
		_LOGD(
			      " Rpm Installer Recovery Ended \n");
		break;
	case REQUEST_COMPLETED:
		_LOGD(
			      " Rpm Installer Recovery. Nothing To Be Done\n");
		_ri_set_backend_state_info(REQUEST_COMPLETED);
		break;

	case REQUEST_PENDING:
		_LOGD(
				"Rpm Installer Recovery started. state=%d\n", lastbackstate);
		/*Only package downgradation can be the case*/
		err = _rpm_installer_package_install(pn, true, "--force", NULL);
		if (err != RPM_INSTALLER_SUCCESS &&
			err != RPM_INSTALLER_ERR_NEED_USER_CONFIRMATION) {
			goto RECOVERYERROR;
		}
		_LOGD(
			      " Rpm Installer Recovery ended \n");
		_ri_set_backend_state_info(REQUEST_COMPLETED);
		break;

	default:
		/*
		 * Unknown state
		 * No need to recover
		 */
		_LOGD(
			      " Rpm Installer Recovery Default state \n");
		break;

	}
	if(pn) free(pn);
	return 0;

 RECOVERYERROR:
	_LOGE("Error in Recovery error number = (%d)\n",
		      err);
	if(pn) free(pn);
	return err;

}

static int __ri_check_root_path(const char *pkgid)
{
	char dirpath[BUF_SIZE] = {'\0'};
	struct stat stFileInfo;

	snprintf(dirpath, BUF_SIZE, "/usr/apps/%s", pkgid);

	(void)stat(dirpath, &stFileInfo);

	if (S_ISDIR(stFileInfo.st_mode)) {
		return 0;	//it menas "/usr/apps/pkgid"
	}
	return 1;		//it menas "/opt/usr/apps/pkgid"
}

void __ri_make_directory(const char *pkgid)
{
	char usr_pkg[BUF_SIZE] = {'\0'};
	char opt_pkg[BUF_SIZE] = {'\0'};
	int ret = 0;

	snprintf(usr_pkg, BUF_SIZE, "%s/%s/%s", USR_APPS, pkgid, AUTHOR_SIGNATURE_XML);
	snprintf(opt_pkg, BUF_SIZE, "%s/%s/%s", OPT_USR_APPS, pkgid, AUTHOR_SIGNATURE_XML);

	// check author signature
	if ((access(opt_pkg, R_OK) == 0) || (access(usr_pkg, R_OK) == 0)) {
		_LOGE("pkgid[%s] has author-signature",pkgid);

		// root path
		memset(opt_pkg, '\0', BUF_SIZE);
		snprintf(opt_pkg, BUF_SIZE, "%s/%s", OPT_USR_APPS, pkgid);
		if (access(opt_pkg, R_OK) != 0) {
			_LOGE("dont have [%s]\n",opt_pkg);
			ret = mkdir(opt_pkg, DIRECTORY_PERMISSION_755);
			if (ret < 0) {
				_LOGE("directory making is failed.\n");
			}else{
				_LOGE("directory[%s] is created", opt_pkg);
			}
		}

		// shared
		memset(opt_pkg, '\0', BUF_SIZE);
		snprintf(opt_pkg, BUF_SIZE, "%s/%s/shared", OPT_USR_APPS, pkgid);
		if (access(opt_pkg, R_OK) != 0) {
			_LOGE("dont have [%s]\n",opt_pkg);
			ret = mkdir(opt_pkg, DIRECTORY_PERMISSION_755);
			if (ret < 0) {
				_LOGE("directory making is failed.\n");
			}else{
				_LOGE("directory[%s] is created", opt_pkg);
			}
		}

		// shared/data
		memset(opt_pkg, '\0', BUF_SIZE);
		snprintf(opt_pkg, BUF_SIZE, "%s/%s/shared/data", OPT_USR_APPS, pkgid);
		if (access(opt_pkg, R_OK) != 0) {
			_LOGE("dont have [%s]\n",opt_pkg);
			ret = mkdir(opt_pkg, DIRECTORY_PERMISSION_755);
			if (ret < 0) {
				_LOGE("directory making is failed.\n");
			}else{
				_LOGE("directory[%s] is created", opt_pkg);
			}
		}

		// shared/trusted
		memset(opt_pkg, '\0', BUF_SIZE);
		snprintf(opt_pkg, BUF_SIZE, "%s/%s/shared/trusted", OPT_USR_APPS, pkgid);
		if (access(opt_pkg, R_OK) != 0) {
			_LOGE("dont have [%s],\n",opt_pkg);
			ret = mkdir(opt_pkg, DIRECTORY_PERMISSION_755);
			if (ret < 0) {
				_LOGE("directory making is failed.\n");
			}else{
				_LOGE("directory[%s] is created", opt_pkg);
			}
		}

	}
}

static int __ri_process_smack(char *keyid, char *pkgid)
{
	int ret = 0;

	/*apply smack for ug*/
	if(strcmp(keyid,"ug-smack")==0) {
		_LOGD("only apply smack for ug\n");
		const char *perm[] = {"http://tizen.org/privilege/appsetting", NULL};
		_ri_apply_smack(pkgid,__ri_check_root_path(pkgid));
		_ri_privilege_enable_permissions(pkgid, 1, perm, 1);
	/*apply smack for rpm package*/
	} else if (strcmp(keyid,"rpm-smack")==0) {
		_LOGD("apply smack for rpm");
		__ri_make_directory(pkgid);
		_ri_apply_smack(pkgid,__ri_check_root_path(pkgid));

	/*soft-reset for rpm package*/
	} else if (strcmp(keyid,"soft-reset")==0) {
		_LOGD("soft-reset\n");
		_ri_soft_reset(pkgid);

	/*register xml to db, call pkgmgr parser*/
	} else if (strcmp(keyid,"core-xml")==0) {
		_LOGD("install corexml");
		ret = _rpm_installer_corexml_install(pkgid);
		if (ret != 0) {
			_LOGE("corexml_install failed with err(%d)\n", ret);
		} else {
			_LOGD("manifest is installed successfully");
		}
	/*apply privilege for rpm package*/
	} else if (strcmp(keyid,"rpm-perm")==0) {
		_LOGD("apply privileges for rpm");
		ret = _ri_apply_privilege(pkgid, 0);
		if (ret != 0) {
			_LOGE("apply privileges failed with err(%d)", ret);
		} else {
			_LOGD("apply privileges success");
		}
	/*check csc xml*/
	} else if (strcmp(keyid,"csc-xml")==0) {
		_LOGD("csc xml for rpm\n");
		ret = _rpm_process_cscxml(pkgid);
		if (ret != 0) {
			_LOGE("install csc xml failed with err(%d)\n", ret);
		} else {
			_LOGD("install csc xml success\n");
		}

	/*check csc coretpk*/
	} else if (strcmp(keyid,"csc-core")==0) {
		_LOGD("csc for coretpk\n");
		ret = _rpm_process_csc_coretpk(pkgid);
		if (ret != 0) {
			_LOGE("install coretpk csc failed with err(%d)\n", ret);
		} else {
			_LOGD("install coretpk csc success\n");
		}

	/*check fota*/
	} else if (strcmp(keyid,"rpm-fota")==0) {
		_LOGD("fota process for rpm\n");
		ret = _rpm_process_fota(pkgid);
		if (ret != 0) {
			_LOGE("fota process failed with err(%d)\n", ret);
		} else {
			_LOGD("fota process success\n");
		}
	/*check fota*/
	} else if (strcmp(keyid,"rpm-rw-fota")==0) {
		_LOGD("rw fota process for rpm\n");
		ret = _rpm_process_fota_for_rw(pkgid);
		if (ret != 0) {
			_LOGE("rw fota process failed with err(%d)\n", ret);
		} else {
			_LOGD("rw fota process success\n");
		}
	} else {
		_LOGE("smack cmd error\n");
		ret = -1;
	}

	return ret;
}

int _rpm_backend_interface(char *keyid, char *pkgid, char *reqcommand, char *clientid)
{
	int ret = -1;
	ri_backend_data data = { 0 };
	int backendstate;
	rpmRC rc;
	if (reqcommand == NULL) {
		_LOGE("reqcommand is NULL\n");
		return RPM_INSTALLER_ERR_WRONG_PARAM;
	}
	if (keyid == NULL || pkgid == NULL) {
		if (strncmp(reqcommand, "recover", strlen("recover"))) {
			_LOGE(" Either keyid/pkgid is NULL\n");
			return RPM_INSTALLER_ERR_WRONG_PARAM;
		}
		_LOGE(" Either keyid/pkgid is NULL\n");
		return RPM_INSTALLER_ERR_WRONG_PARAM;
	}

	if (strncmp(reqcommand, "install", strlen("install")) == 0) {
		data.req_cmd = INSTALL_CMD;
		data.cmd_string = strdup("install");
		if (data.cmd_string == NULL) {
			_LOGE(
			       "strdup failed due to insufficient memory\n");
			return RPM_INSTALLER_ERR_NOT_ENOUGH_MEMORY;
		}
	} else if (strncmp(reqcommand, "remove", strlen("remove")) == 0) {
		data.req_cmd = DELETE_CMD;
		data.cmd_string = strdup("uninstall");
		if (data.cmd_string == NULL) {
			_LOGE(
			       "strdup failed due to insufficient memory\n");
			return RPM_INSTALLER_ERR_NOT_ENOUGH_MEMORY;
		}
	} else if (strncmp(reqcommand, "recover", strlen("recover")) == 0) {
		data.req_cmd = RECOVER_CMD;
		data.cmd_string = strdup("recover");
		if (data.cmd_string == NULL) {
			_LOGE(
			       "strdup failed due to insufficient memory\n");
			return RPM_INSTALLER_ERR_NOT_ENOUGH_MEMORY;
		}
	} else if (strncmp(reqcommand, "cleardata", strlen("cleardata")) == 0) {
		data.req_cmd = CLEARDATA_CMD;
		data.cmd_string = strdup("cleardata");
		if (data.cmd_string == NULL) {
			_LOGE(
			       "strdup failed due to insufficient memory\n");
			return RPM_INSTALLER_ERR_NOT_ENOUGH_MEMORY;
		}
	} else if (strncmp(reqcommand, "move", strlen("move")) == 0) {
		data.req_cmd = MOVE_CMD;
		data.cmd_string = strdup("move");
		if (data.cmd_string == NULL) {
			_LOGE(
			       "strdup failed due to insufficient memory\n");
			return RPM_INSTALLER_ERR_NOT_ENOUGH_MEMORY;
		}
	} else if (strncmp(reqcommand, "smack", strlen("smack")) == 0) {
		return __ri_process_smack(keyid, pkgid);
	} else if (strncmp(reqcommand, "eflwgt-install", strlen("eflwgt-install")) == 0) {
		data.req_cmd = EFLWGT_INSTALL_CMD;
		data.cmd_string = strdup("eflwgt-install");
		if (data.cmd_string == NULL) {
			_LOGE(
				"strdup failed due to insufficient memory\n");
			return RPM_INSTALLER_ERR_NOT_ENOUGH_MEMORY;
		}
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
		_LOGD("wrong input parameter\n");
		_LOGD("%d\n", RPM_INSTALLER_ERR_WRONG_PARAM);
		return RPM_INSTALLER_ERR_WRONG_PARAM;
	}

	data.pkgid = pkgid;
	backendstate = _ri_get_backend_state();

	rc = rpmReadConfigFiles(NULL, NULL);
	if (rc == RPMRC_OK) {
		_LOGD("Successfully read rpm configuration\n");
	} else {
		_LOGE("Unable to read RPM configuration.\n");
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
				_LOGD(
				       " Rpm Installer recovery is in REQUEST_COMPLETED  \n");
				snprintf(scrolllabel, sizeof(scrolllabel),
					 "No Recovery Needed");
			} else{
				ret = __ri_native_recovery(lastbackstate);
				if (ret == 0)
					snprintf(scrolllabel, sizeof(scrolllabel),
						 "Recovery Success");
				else
					snprintf(scrolllabel, sizeof(scrolllabel),
						"Recovery Failed");
			}
			/* set the backend state as completed */
			_ri_set_backend_state(1);
		} else {
			/* nothing to recover */
			_LOGD(
			       " Rpm Installer recovery Nothing to be done\n");
			ret = 0;
			snprintf(scrolllabel, sizeof(scrolllabel),
				 "No Recovery Needed");
		}
		_LOGD("%d\n", ret);
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
				    (data.pkgid, "rpm", "error",
				     "Another Instance Running");
				_ri_stat_cb(data.pkgid, "error",
					    "Another Instance Running");
				_ri_broadcast_status_notification
				    (data.pkgid, "rpm", "end", "fail");
				_ri_stat_cb(data.pkgid, "end",
					    "fail");
			} else {
				_ri_broadcast_status_notification
				    ("unknown", "unknown", "error",
				     "Another Instance Running");
				_ri_stat_cb("unknown", "error",
					    "Another Instance Running");
				_ri_broadcast_status_notification
				    ("unknown", "unknown", "end", "fail");
				_ri_stat_cb("unknown", "end", "fail");
			}
			_LOGD(
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
//			_ri_broadcast_status_notification(data.pkgid, "rpm", "start", data.cmd_string);
//			_ri_broadcast_status_notification(data.pkgid, "rpm", "command", data.cmd_string);

			if (REQUEST_COMPLETED == lastbackstate) {
				_LOGD(
				       " Rpm Installer recovery"
				       " is in REQUEST_COMPLETED  \n");
				ret = 0;
			} else
				ret = __ri_native_recovery(lastbackstate);
			if (ret != 0) {
				_LOGD(
					"recovery of last request failed\n");
			} else {
				_LOGD(
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
		_ri_broadcast_status_notification(data.pkgid, "rpm", "start",
						  data.cmd_string);
	else
		_ri_broadcast_status_notification("unknown", "start",
						  data.cmd_string);
#endif

	_ri_set_backend_state_info(REQUEST_ACCEPTED);

	/* Set the input request info */
	if(data.pkgid == NULL)
		return RPM_INSTALLER_ERR_PKG_NOT_FOUND;
	_ri_save_last_input_info(data.pkgid, data.req_cmd,
					 data.force_overwrite);

	switch (data.req_cmd) {
	case INSTALL_CMD:
		{
			_LOGD("[%s] --install %s\n",
			       "backend", data.pkgid);
#ifdef SEND_PKGPATH
			_ri_broadcast_status_notification(data.pkgid, "rpm",
							  "command", "Install");
#endif
			if (data.force_overwrite == FORCE_OVERWITE) {
				_LOGD(
				       "[%s] --install %s --force-overwrite\n",
				       "backend", data.pkgid);
				ret =
				    _rpm_installer_package_install
				    (data.pkgid, true, "--force", clientid);
			} else {
				if(data.pkgid == NULL) {
					_LOGE("pkgid is null");
					break;
				}
				_LOGD("[%s] --install %s\n",
				       "backend", data.pkgid);
				ret =
				    _rpm_installer_package_install
				    (data.pkgid, false, NULL, clientid);
			}
		}
		break;
	case DELETE_CMD:
		{
			_LOGD("[%s] uninstall %s\n",
			       "backend", data.pkgid);
#ifdef SEND_PKGPATH
			_ri_broadcast_status_notification(data.pkgid, "rpm",
							  "command", "Remove");
#endif
			ret = __ri_uninstall_package(data.pkgid);
			if (ret != 0) {
				_LOGD("remove fail\n");
			} else {
				_LOGD("remove success\n");
			}
		}
		break;
	case CLEARDATA_CMD:
		{
			_LOGD("[%s] clear data %s\n",
			       "backend", data.pkgid);
#ifdef SEND_PKGPATH
			_ri_broadcast_status_notification(data.pkgid, "rpm",
							  "command", "clear");
#endif
			ret = __ri_clear_private_data(data.pkgid);
			if (ret != 0) {
				char *errstr = NULL;
				_ri_error_no_to_string(ret, &errstr);
				_ri_broadcast_status_notification(data.pkgid, "rpm",
								  "error",
								  errstr);
				_ri_stat_cb(data.pkgid, "error", errstr);
				_ri_broadcast_status_notification(data.pkgid, "rpm",
								  "end",
								  "fail");
				_ri_stat_cb(data.pkgid, "end", "fail");
				_LOGE(
				       "clear data failed with err(%d) (%s)\n",
				       ret, errstr);
			} else {
				_LOGD("clear data success\n");
				_ri_broadcast_status_notification(data.pkgid, "rpm",
								  "end", "ok");
				_ri_stat_cb(data.pkgid, "end", "ok");
			}
			break;
		}
	case MOVE_CMD:
		{
			_LOGD("[%s] move %s\n",
			       "backend", data.pkgid);
#ifdef SEND_PKGPATH
			_ri_broadcast_status_notification(data.pkgid, "rpm",
							  "command", "move");
#endif
			ret = __ri_move_package(data.pkgid, move_type);
			if (ret != 0) {
				char *errstr = NULL;
				_ri_error_no_to_string(ret, &errstr);
				_ri_broadcast_status_notification(data.pkgid, "rpm",
								  "error",
								  errstr);
				_ri_stat_cb(data.pkgid, "error", errstr);
				_ri_broadcast_status_notification(data.pkgid, "rpm",
								  "end",
								  "fail");
				_ri_stat_cb(data.pkgid, "end", "fail");
				_LOGE(
				       "move failed with err(%d) (%s)\n",
				       ret, errstr);
			} else {
				_LOGD("move success\n");
				_ri_broadcast_status_notification(data.pkgid, "rpm",
								  "end", "ok");
				_ri_stat_cb(data.pkgid, "end", "ok");
			}
			break;
		}
		case EFLWGT_INSTALL_CMD:
			{

			_LOGD("[%s] eflwgt-install %s\n",
						   "backend", data.pkgid);
#ifdef SEND_PKGPATH
			_ri_broadcast_status_notification(data.pkgid, "rpm",
								  "command", "eflwgt-install");
#endif
			ret = _rpm_installer_package_install_with_dbpath(data.pkgid, clientid);
			if (ret != 0) {
				char *errstr = NULL;
				_ri_error_no_to_string(ret, &errstr);
				_ri_broadcast_status_notification(data.pkgid, "rpm",
									  "error",
									  errstr);
				_ri_stat_cb(data.pkgid, "error", errstr);
				sleep(2);
				_ri_broadcast_status_notification(data.pkgid, "rpm",
								  "end",
								  "fail");
				_ri_stat_cb(data.pkgid, "end", "fail");
				_LOGE("eflwgt-install failed with err(%d) (%s)\n",
						   ret, errstr);
			} else {
				_LOGD("eflwgt-install success\n");
				_ri_broadcast_status_notification(data.pkgid, "rpm",
								  "end", "ok");
				_ri_stat_cb(data.pkgid, "end", "ok");
			}
				_ri_remove_wgt_unzip_dir();
				break;
			}

	default:
		{
			_ri_broadcast_status_notification("unknown", "unknown",
							  "command",
							  "unknown");
			_ri_broadcast_status_notification("unknown", "unknown",
							  "error",
							  "not supported");
			_ri_stat_cb("unknown", "error", "not supported");
			_ri_broadcast_status_notification("unknown", "unknown",
							  "end", "fail");
			_ri_stat_cb("unknown", "end", "fail");
			_LOGE("unknown command \n");
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
		_LOGD("%d\n", ret);
	}
	return ret;
}
