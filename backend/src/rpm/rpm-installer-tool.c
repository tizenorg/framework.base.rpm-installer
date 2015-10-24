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
#include <sys/time.h>
#include <time.h>
#include <security-server-perm-types.h>
#include <pkgmgr_installer.h>
#include <pkgmgr_parser.h>

#include "rpm-installer.h"
#include "rpm-frontend.h"
#include "installer-type.h"
#include "installer-util.h"

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
static inline int __ri_find_pid_by_cmdline(const char *dname, const char *cmdline, const char *priv);

static int __ri_uninstall_package(char *pkgid)
{

	if (pkgid == NULL)
		return RPM_INSTALLER_ERR_WRONG_PARAM;
	int ret = 0;
	ret = _rpm_installer_package_uninstall(pkgid);
	if (ret == RPM_INSTALLER_ERR_PACKAGE_NOT_INSTALLED) {
		_LOGE("[__ri_uninstall_package]%s not installed\n", pkgid);
	} else if (ret != 0) {
		_LOGE("[__ri_uninstall_package]%s uninstall failed(%d)\n", pkgid, ret);
	} else {
		_LOGE("[__ri_uninstall_package]%s successfully uninstalled\n", pkgid);
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
		_LOGE("[__clear_private_data]%s clear data successful\n", pkgid);
	} else {
		_LOGE("[__clear_private_data]%s clear data failed(%d)\n", pkgid, ret);
	}
	return ret;
}

static int __ri_move_package(char *pkgid, int move_type)
{
	if (pkgid == NULL)
		return RPM_INSTALLER_ERR_WRONG_PARAM;
	int ret = 0;
	if (gpkgname) {
		free(gpkgname);
		gpkgname = NULL;
	}
	gpkgname = strdup(pkgid);
	if (!gpkgname) {
		_LOGE("Malloc failed!!");
		return RPM_INSTALLER_ERR_INTERNAL;
	}
	ret = _rpm_move_pkg(pkgid, move_type);
	if (ret == RPM_INSTALLER_SUCCESS) {
		_LOGE("[__ri_move_package]%s move successful\n", pkgid);
	} else {
		_LOGE("[__ri_move_package]%s move failed(%d)\n", pkgid, ret);
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

static inline int __ri_find_pid_by_cmdline(const char *dname, const char *cmdline, const char *priv)
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
		_LOGD("Rpm Installer Recovery started. state=%d \n", lastbackstate);
		switch (lreq) {
		case INSTALL_CMD:
			err = _rpm_installer_package_install(pn, true, "--force", NULL);
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
			if (err)
				goto RECOVERYERROR;
			break;

		case CLEARDATA_CMD:
		case MOVE_CMD:
		case RECOVER_CMD:
			/*TODO*/
			_LOGD("Recovery of command(%d) is to be implemented\n", lreq);
			if (pn)
				free(pn);
			return 0;
		}
		_LOGD(" Rpm Installer Recovery Ended \n");
		break;

	case REQUEST_COMPLETED:
		_LOGD(" Rpm Installer Recovery. Nothing To Be Done\n");
		_ri_set_backend_state_info(REQUEST_COMPLETED);
		break;

	case REQUEST_PENDING:
		_LOGD("Rpm Installer Recovery started. state=%d\n", lastbackstate);
		/*Only package downgradation can be the case */
		err = _rpm_installer_package_install(pn, true, "--force", NULL);
		if (err != RPM_INSTALLER_SUCCESS && err != RPM_INSTALLER_ERR_NEED_USER_CONFIRMATION) {
			goto RECOVERYERROR;
		}
		_LOGD(" Rpm Installer Recovery ended \n");
		_ri_set_backend_state_info(REQUEST_COMPLETED);
		break;

	default:
		/*
		 * Unknown state
		 * No need to recover
		 */
		_LOGD(" Rpm Installer Recovery Default state \n");
		break;

	}
	if (pn)
		free(pn);
	return 0;

RECOVERYERROR:
	_LOGE("Error in Recovery error number = (%d)\n", err);
	if (pn)
		free(pn);
	return err;

}

static int __ri_check_root_path(const char *pkgid)
{
	char dirpath[BUF_SIZE] = { '\0' };
	struct stat stFileInfo;

	snprintf(dirpath, BUF_SIZE, "%s/%s", USR_APPS, pkgid);

	if (stat(pkgid, &stFileInfo) < 0) {
		return 0;
	}

	if (S_ISDIR(stFileInfo.st_mode)) {
		return 0;				/* it means "/usr/apps/pkgid" */
	}
	return 1;					/* it means "/opt/usr/apps/pkgid" */
}

void __ri_make_directory(const char *pkgid)
{
	char usr_pkg[BUF_SIZE] = { '\0' };
	char opt_pkg[BUF_SIZE] = { '\0' };
	int ret = 0;

	snprintf(usr_pkg, BUF_SIZE, "%s/%s/%s", USR_APPS, pkgid, AUTHOR_SIGNATURE_XML);
	snprintf(opt_pkg, BUF_SIZE, "%s/%s/%s", OPT_USR_APPS, pkgid, AUTHOR_SIGNATURE_XML);

	/* check author signature */
	if ((access(opt_pkg, R_OK) == 0) || (access(usr_pkg, R_OK) == 0)) {
		_LOGE("pkgid[%s] has author-signature", pkgid);

		/* root path */
		memset(opt_pkg, '\0', BUF_SIZE);
		snprintf(opt_pkg, BUF_SIZE, "%s/%s", OPT_USR_APPS, pkgid);
		if (access(opt_pkg, R_OK) != 0) {
			_LOGE("dont have [%s]\n", opt_pkg);
			ret = mkdir(opt_pkg, DIRECTORY_PERMISSION_755);
			if (ret < 0) {
				_LOGE("directory making is failed.\n");
			} else {
				_LOGE("directory[%s] is created", opt_pkg);
			}
		}

		/* data */
		memset(opt_pkg, '\0', BUF_SIZE);
		snprintf(opt_pkg, BUF_SIZE, "%s/%s/data", OPT_USR_APPS, pkgid);
		if (access(opt_pkg, R_OK) != 0) {
			_LOGE("dont have [%s]\n",opt_pkg);
			ret = mkdir(opt_pkg, DIRECTORY_PERMISSION_755);
			if (ret < 0) {
				_LOGE("directory making is failed.\n");
			}else{
				_LOGE("directory[%s] is created", opt_pkg);
			}
		}

		/* shared */
		memset(opt_pkg, '\0', BUF_SIZE);
		snprintf(opt_pkg, BUF_SIZE, "%s/%s/shared", OPT_USR_APPS, pkgid);
		if (access(opt_pkg, R_OK) != 0) {
			_LOGE("dont have [%s]\n", opt_pkg);
			ret = mkdir(opt_pkg, DIRECTORY_PERMISSION_755);
			if (ret < 0) {
				_LOGE("directory making is failed.\n");
			} else {
				_LOGE("directory[%s] is created", opt_pkg);
			}
		}

		/* shared/data */
		memset(opt_pkg, '\0', BUF_SIZE);
		snprintf(opt_pkg, BUF_SIZE, "%s/%s/shared/data", OPT_USR_APPS, pkgid);
		if (access(opt_pkg, R_OK) != 0) {
			_LOGE("dont have [%s]\n", opt_pkg);
			ret = mkdir(opt_pkg, DIRECTORY_PERMISSION_755);
			if (ret < 0) {
				_LOGE("directory making is failed.\n");
			} else {
				_LOGE("directory[%s] is created", opt_pkg);
			}
		}

		/* shared/trusted */
		memset(opt_pkg, '\0', BUF_SIZE);
		snprintf(opt_pkg, BUF_SIZE, "%s/%s/shared/trusted", OPT_USR_APPS, pkgid);
		if (access(opt_pkg, R_OK) != 0) {
			_LOGE("dont have [%s],\n", opt_pkg);
			ret = mkdir(opt_pkg, DIRECTORY_PERMISSION_755);
			if (ret < 0) {
				_LOGE("directory making is failed.\n");
			} else {
				_LOGE("directory[%s] is created", opt_pkg);
			}
		}

	}
}

static char *__find_info_from_xml(const char *manifest, const char *find_info)
{
	const xmlChar *node = NULL;
	xmlTextReaderPtr reader = NULL;
	char *info_val = NULL;
	xmlChar *tmp = NULL;

	if (manifest == NULL || find_info == NULL) {
		printf("Input argument is NULL\n");
		return NULL;
	}

	reader = xmlReaderForFile(manifest, NULL, 0);

	if (reader) {
		if (_child_element(reader, -1)) {
			node = xmlTextReaderConstName(reader);
			if (!node) {
				printf("xmlTextReaderConstName value is NULL\n");
				goto end;
			}

			if (!strcmp(ASCII(node), "manifest")) {
				tmp = xmlTextReaderGetAttribute(reader, XMLCHAR(find_info));
				if (tmp) {
					FREE_AND_STRDUP(ASCII(tmp), info_val);
					if (info_val == NULL)
						printf("Malloc Failed");

					FREE_AND_NULL(tmp);
				}
			} else {
				printf("Manifest Node is not found\n");
			}
		}
	} else {
		printf("xmlReaderForFile value is NULL\n");
	}

end:
	if (reader) {
		xmlFreeTextReader(reader);
	}

	return info_val;
}

static int __check_time(long privous_time)
{
	long current_time;
	struct timeval tv;

	gettimeofday(&tv, NULL);
	current_time = tv.tv_sec * 1000l + tv.tv_usec / 1000l;

	return (int)(current_time - privous_time);
}

int _ri_init_db(const char *xml_path)
{
	retvm_if(xml_path == NULL, RPM_INSTALLER_ERR_WRONG_PARAM, "xml_path is NULL.");

	int ret = 0;
	int visibility = 0;
	int spend_time = 0;
	long check_time;
	char *pkg_id = NULL;
	char *type = NULL;
	char signature_file[BUF_SIZE] = {0, };
	struct timeval tv;
	char *smack_label = NULL;

	// check type
	type = __find_info_from_xml(xml_path, "type");
	tryvm_if((type != NULL) && (strcmp(type, "wgt") == 0), ret = -1, "__find_info_from_xml(%s) failed. [type]", xml_path);

	// get pkg_id
	pkg_id = __find_info_from_xml(xml_path, "package");
	tryvm_if(pkg_id == NULL, ret = -1, "__find_info_from_xml(%s) failed. [package]", xml_path);

	_LOGD("package=[%s], type=[%s]", pkg_id, type);

	ret = __get_smack_label_from_xml(xml_path, pkg_id, &smack_label);
	_LOGD("smack_label[%s], ret[%d]\n", smack_label, ret);

	// validate xml
	ret = pkgmgr_parser_check_manifest_validation(xml_path);
	tryvm_if(ret < 0, ret = -1, "pkgmgr_parser_check_manifest_validation(%s) failed. ret=[%d]", xml_path, ret);

	gettimeofday(&tv, NULL);
	check_time = tv.tv_sec * 1000l + tv.tv_usec / 1000l;

	_LOGD("=========================================================================");
	_LOGD("install corexml=[%s]", xml_path);

	// install corexml
	ret = _rpm_installer_corexml_install(xml_path);
	tryvm_if(ret != 0, ret = -1, "_rpm_installer_corexml_install(%s) failed. ret=[%d]", xml_path, ret);

	spend_time = __check_time(check_time);
	_LOGD("corexml is installed, time=[%d]ms", spend_time);

	gettimeofday(&tv, NULL);
	check_time = tv.tv_sec * 1000l + tv.tv_usec / 1000l;

	// smack
	_LOGD("apply smack for rpm");
#ifdef _APPFW_FEATURE_DIRECTORY_PERMISSION_OPT_ONLY
	__ri_make_directory(pkg_id);
#else
	ret = _coretpk_installer_make_directory(pkg_id, true);
	if (ret < 0) {
		_LOGE("_coretpk_installer_make_directory failed. ret=[%d]", ret);
	}
#endif
	_ri_apply_smack(pkg_id, __ri_check_root_path(pkg_id), smack_label);

	spend_time = __check_time(check_time);
	_LOGD("smack is applied, time=[%d]ms", spend_time);

	gettimeofday(&tv, NULL);
	check_time = tv.tv_sec * 1000l + tv.tv_usec / 1000l;

	// privilege
	_LOGD("apply privileges for rpm");
	if (strstr(xml_path, "usr/share/packages")) {
		snprintf(signature_file, BUF_SIZE, "%s/%s/%s", USR_APPS, pkg_id, SIGNATURE1_XML);
	} else {
		snprintf(signature_file, BUF_SIZE, "%s/%s/%s", OPT_USR_APPS, pkg_id, SIGNATURE1_XML);
	}

	if (access(signature_file, F_OK) != 0) {
		_LOGE("[%s] is not existed.", signature_file);
	} else {
		ret = _ri_get_visibility_from_signature_file(signature_file, &visibility, false);
		if (ret != 0) {
			_LOGE("_ri_get_visibility_from_signature_file(%s) failed. ret=[%d]", signature_file, ret);
		}
	}

	_LOGD("visibility=[%d][%s]", visibility, pkg_id);
	ret = _ri_apply_privilege(pkg_id, visibility, smack_label);
	if (ret != 0) {
		_LOGE("_ri_apply_privilege(%s, %d) failed. ret=[%d]", pkg_id, visibility, ret);
	}

	spend_time = __check_time(check_time);
	_LOGD("privileges are applied, time=[%d]ms", spend_time);

	_LOGD("=========================================================================");

catch:
	FREE_AND_NULL(type);
	FREE_AND_NULL(pkg_id);
	FREE_AND_NULL(smack_label);

	return ret;
}

static int _rpm_process_initdb(void)
{
	int ret = 0;
	DIR *dir = NULL;
	struct dirent entry, *result;
	char *manifest_dirs[2] = { USR_SHARE_PACKAGES, OPT_SHARE_PACKAGES };
	int index = 0;
	char buf[BUF_SIZE] = { 0 };

	int spend_time = 0;
	int total_time = 0;
	int pkg_success_cnt = 0;

	long check_time;
	struct timeval tv;

	/* Read the manifest directories */
	for (index = 0; index < 2; index++) {
		dir = opendir(manifest_dirs[index]);
		if (!dir) {
			if (strerror_r(errno, buf, sizeof(buf)) == 0)
				_LOGE("Failed to access the [%s] because %s", manifest_dirs[index], buf);
			return -1;
		}

		/*Initialization*/
		pkg_success_cnt = 0;

		for (ret = readdir_r(dir, &entry, &result);
			ret == 0 && result != NULL;
			ret = readdir_r(dir, &entry, &result)) {

				if (entry.d_name[0] == '.') continue;

				if (!strstr(entry.d_name, ".xml"))
					continue;

				/*Set the manifest file's full path*/
				memset(buf, '\0', BUF_SIZE);
				snprintf(buf, sizeof(buf), "%s/%s", manifest_dirs[index], entry.d_name);

				gettimeofday(&tv, NULL);
				check_time = tv.tv_sec * 1000l + tv.tv_usec / 1000l;

				ret = _ri_init_db(buf);
				if (ret == 0) {
					_LOGD("[_rpm_process_initdb-SUCCESS] _ri_init_db(%s) success!", buf);
					pkg_success_cnt++;
				} else {
					_LOGE("[_rpm_process_initdb-FAIL] _ri_init_db(%s) failed!", buf);
				}

				spend_time = __check_time(check_time);
				_LOGD("time=[%d]ms", spend_time);

				total_time = total_time + spend_time;
			}

		closedir(dir);
		_LOGD("+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++");
		_LOGD("package manager db init for manifest xml, directory=[%s]", manifest_dirs[index]);
		_LOGD("package total success count : %d", pkg_success_cnt);
		_LOGD("time for total process      : %d  sec", (total_time) / 1000);
		_LOGD("+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++");
	}

	return ret;
}

static int __ri_process_smack(char *keyid, char *pkgid)
{
	int ret = 0;
	char *smack_label = NULL;

	ret = __get_smack_label_from_db(pkgid, &smack_label);
	_LOGD("smack_label[%s], ret[%d]\n", smack_label, ret);

	/* apply smack for ug */
	if (strcmp(keyid, "ug-smack") == 0) {
		_LOGD("only apply smack for ug\n");
		const char *perm[] = { "http://tizen.org/privilege/appsetting", NULL };
		_ri_apply_smack(pkgid, __ri_check_root_path(pkgid), smack_label);
		_ri_privilege_enable_permissions(smack_label, PERM_APP_TYPE_WRT, perm, 1);
		/* apply smack for rpm package */
	} else if (strcmp(keyid, "rpm-smack") == 0) {
		_LOGD("apply smack for rpm");
		__ri_make_directory(pkgid);
		_ri_apply_smack(pkgid,__ri_check_root_path(pkgid), smack_label);
		/*register xml to db, call pkgmgr parser*/
	} else if (strcmp(keyid,"core-xml") == 0) {
		_LOGD("install corexml");
		ret = _rpm_installer_corexml_install(pkgid);
		if (ret != 0) {
			_LOGE("corexml_install failed with err(%d)\n", ret);
		} else {
			_LOGD("manifest is installed successfully");
		}
		/* apply privilege for rpm package */
	} else if (strcmp(keyid, "rpm-perm") == 0) {
		_LOGD("apply privileges for rpm");
		ret = _ri_apply_privilege(pkgid, 0, smack_label);
		if (ret != 0) {
			_LOGE("apply privileges failed with err(%d)", ret);
		} else {
			_LOGD("apply privileges success");
		}
		/* check csc xml */
	} else if (strcmp(keyid, "csc-xml") == 0) {
		_LOGD("csc xml for rpm\n");
		ret = _rpm_process_cscxml(pkgid);
		if (ret != 0) {
			_LOGE("install csc xml failed with err(%d)\n", ret);
		} else {
			_LOGD("install csc xml success\n");
		}

		/* Check initdb */
	} else if (strcmp(keyid, "rpm_initdb") == 0) {
		_LOGD("initdb request for rpms");
		ret = _rpm_process_initdb();
		if (ret != 0) {
			_LOGE("initdb process failed with err(%d)\n", ret);
		} else {
			_LOGD("initdb process success\n");
		}

	} else {
		_LOGE("smack cmd error\n");
		ret = -1;
	}

	FREE_AND_NULL(smack_label);

	return ret;
}

int _rpm_backend_interface(char *keyid, char *pkgid, char *reqcommand, char *clientid)
{
	int ret = -1;
	ri_backend_data data = { 0 };
	int backendstate;
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
			_LOGE("strdup failed due to insufficient memory\n");
			return RPM_INSTALLER_ERR_NOT_ENOUGH_MEMORY;
		}
	} else if (strncmp(reqcommand, "remove", strlen("remove")) == 0) {
		data.req_cmd = DELETE_CMD;
		data.cmd_string = strdup("uninstall");
		if (data.cmd_string == NULL) {
			_LOGE("strdup failed due to insufficient memory\n");
			return RPM_INSTALLER_ERR_NOT_ENOUGH_MEMORY;
		}
	} else if (strncmp(reqcommand, "recover", strlen("recover")) == 0) {
		data.req_cmd = RECOVER_CMD;
		data.cmd_string = strdup("recover");
		if (data.cmd_string == NULL) {
			_LOGE("strdup failed due to insufficient memory\n");
			return RPM_INSTALLER_ERR_NOT_ENOUGH_MEMORY;
		}
	} else if (strncmp(reqcommand, "cleardata", strlen("cleardata")) == 0) {
		data.req_cmd = CLEARDATA_CMD;
		data.cmd_string = strdup("cleardata");
		if (data.cmd_string == NULL) {
			_LOGE("strdup failed due to insufficient memory\n");
			return RPM_INSTALLER_ERR_NOT_ENOUGH_MEMORY;
		}
	} else if (strncmp(reqcommand, "move", strlen("move")) == 0) {
		data.req_cmd = MOVE_CMD;
		data.cmd_string = strdup("move");
		if (data.cmd_string == NULL) {
			_LOGE("strdup failed due to insufficient memory\n");
			return RPM_INSTALLER_ERR_NOT_ENOUGH_MEMORY;
		}
	} else if (strncmp(reqcommand, "smack", strlen("smack")) == 0) {
		return __ri_process_smack(keyid, pkgid);
	} else if (strncmp(reqcommand, "eflwgt-install", strlen("eflwgt-install")) == 0) {
		data.req_cmd = EFLWGT_INSTALL_CMD;
		data.cmd_string = strdup("eflwgt-install");
		if (data.cmd_string == NULL) {
			_LOGE("strdup failed due to insufficient memory\n");
			return RPM_INSTALLER_ERR_NOT_ENOUGH_MEMORY;
		}
	} else {
		_LOGD("wrong input parameter\n");
		_LOGD("%d\n", RPM_INSTALLER_ERR_WRONG_PARAM);
		return RPM_INSTALLER_ERR_WRONG_PARAM;
	}

	data.pkgid = pkgid;
	backendstate = _ri_get_backend_state();

	if (RECOVER_CMD == data.req_cmd) {
		if (0 == backendstate) {
			int lastbackstate;

			/* check the current state of backend */
			lastbackstate = _ri_get_backend_state_info();

			if (REQUEST_COMPLETED == lastbackstate) {
				_LOGD(" Rpm Installer recovery is in REQUEST_COMPLETED  \n");
				snprintf(scrolllabel, sizeof(scrolllabel), "No Recovery Needed");
			} else {
				ret = __ri_native_recovery(lastbackstate);
				if (ret == 0)
					snprintf(scrolllabel, sizeof(scrolllabel), "Recovery Success");
				else
					snprintf(scrolllabel, sizeof(scrolllabel), "Recovery Failed");
			}
			/* set the backend state as completed */
			_ri_set_backend_state(1);
		} else {
			/* nothing to recover */
			_LOGD(" Rpm Installer recovery Nothing to be done\n");
			ret = 0;
			snprintf(scrolllabel, sizeof(scrolllabel), "No Recovery Needed");
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
		 /*
		if (__ri_is_another_instance_running(RPM)) {
			if (data.pkgid) {
				_ri_broadcast_status_notification(data.pkgid, PKGTYPE_RPM, "error", "Another Instance Running");
				_ri_stat_cb(data.pkgid, "error", "Another Instance Running");
				_ri_broadcast_status_notification(data.pkgid, PKGTYPE_RPM, "end", "fail");
				_ri_stat_cb(data.pkgid, "end", "fail");
			} else {
				_ri_broadcast_status_notification("unknown", "unknown", "error", "Another Instance Running");
				_ri_stat_cb("unknown", "error", "Another Instance Running");
				_ri_broadcast_status_notification("unknown", "unknown", "end", "fail");
				_ri_stat_cb("unknown", "end", "fail");
			}
			_LOGD("Request Failed as Another Instance is running \n");
			ret = RPM_INSTALLER_ERR_RESOURCE_BUSY;
			if (data.cmd_string) {
				free(data.cmd_string);
				data.cmd_string = NULL;
			}
			return ret;
		} else */
		{
			int lastbackstate;

			/* check the current state of backend */
			lastbackstate = _ri_get_backend_state_info();

			/* Publish Notification that backend has started */
			/* _ri_broadcast_status_notification(data.pkgid, "start", data.cmd_string); */
			/* _ri_broadcast_status_notification(data.pkgid, "command", data.cmd_string); */

			if (REQUEST_COMPLETED == lastbackstate) {
				_LOGD(" Rpm Installer recovery is in REQUEST_COMPLETED  \n");
				ret = 0;
			} else
				ret = __ri_native_recovery(lastbackstate);
			if (ret != 0) {
				_LOGD("recovery of last request failed\n");
			} else {
				_LOGD("recovery of last request success\n");
			}

			/* set the backend state as completed */
			_ri_set_backend_state(1);
		}
	}

	/* set the backend state as started for the current request */
	_ri_set_backend_state(0);

#ifdef SEND_PKGPATH
	gpkgname = strdup(data.pkgid);

	/* Publish Notification that backend has started */
	if (data.pkgid)
		_ri_broadcast_status_notification(data.pkgid, PKGTYPE_RPM, "start", data.cmd_string);
	else
		_ri_broadcast_status_notification("unknown", "unknown", "start", data.cmd_string);
#endif

	_ri_set_backend_state_info(REQUEST_ACCEPTED);

	/* Set the input request info */
	if (data.pkgid == NULL) {
		FREE_AND_NULL(data.cmd_string);
		return RPM_INSTALLER_ERR_PKG_NOT_FOUND;
	}
	_ri_save_last_input_info(data.pkgid, data.req_cmd, data.force_overwrite);

	switch (data.req_cmd) {
	case INSTALL_CMD:
		{
			_LOGD("[%s] --install %s\n", "backend", data.pkgid);
#ifdef SEND_PKGPATH
			_ri_broadcast_status_notification(data.pkgid, PKGTYPE_RPM, "command", "Install");
#endif
			if (data.force_overwrite == FORCE_OVERWITE) {
				_LOGD("[%s] --install %s --force-overwrite\n", "backend", data.pkgid);
				ret = _rpm_installer_package_install(data.pkgid, true, "--force", clientid);
			} else {
				if (data.pkgid == NULL) {
					_LOGE("pkgid is null");
					break;
				}
				_LOGD("[%s] --install %s\n", "backend", data.pkgid);
				ret = _rpm_installer_package_install(data.pkgid, false, NULL, clientid);
			}
		}
		break;
	case DELETE_CMD:
		{
			_LOGD("[%s] uninstall %s\n", "backend", data.pkgid);
#ifdef SEND_PKGPATH
			_ri_broadcast_status_notification(data.pkgid, PKGTYPE_RPM, "command", "Remove");
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
			_LOGD("[%s] clear data %s\n", "backend", data.pkgid);
#ifdef SEND_PKGPATH
			_ri_broadcast_status_notification(data.pkgid, PKGTYPE_RPM, "command", "clear");
#endif
			ret = __ri_clear_private_data(data.pkgid);
			if (ret != 0) {
				char *errstr = NULL;
				_ri_error_no_to_string(ret, &errstr);
				_ri_broadcast_status_notification(data.pkgid, PKGTYPE_RPM, "error", errstr);
				_ri_stat_cb(data.pkgid, "error", errstr);
				_ri_broadcast_status_notification(data.pkgid, PKGTYPE_RPM, "end", "fail");
				_ri_stat_cb(data.pkgid, "end", "fail");
				_LOGE("clear data failed with err(%d) (%s)\n", ret, errstr);
			} else {
				_LOGD("clear data success\n");
				_ri_broadcast_status_notification(data.pkgid, PKGTYPE_RPM, "end", "ok");
				_ri_stat_cb(data.pkgid, "end", "ok");
			}
			break;
		}
	case MOVE_CMD:
		{
			_LOGD("[%s] move %s\n", "backend", data.pkgid);
#ifdef SEND_PKGPATH
			_ri_broadcast_status_notification(data.pkgid, PKGTYPE_RPM, "command", "move");
#endif
			ret = __ri_move_package(data.pkgid, move_type);
			if (ret != 0) {
				char *errstr = NULL;
				_ri_error_no_to_string(ret, &errstr);
				_ri_broadcast_status_notification(data.pkgid, PKGTYPE_RPM, "error", errstr);
				_ri_stat_cb(data.pkgid, "error", errstr);
				_ri_broadcast_status_notification(data.pkgid, PKGTYPE_RPM, "end", "fail");
				_ri_stat_cb(data.pkgid, "end", "fail");
				_LOGE("move failed with err(%d) (%s)\n", ret, errstr);
			} else {
				_LOGD("move success\n");
				_ri_broadcast_status_notification(data.pkgid, PKGTYPE_RPM, "end", "ok");
				_ri_stat_cb(data.pkgid, "end", "ok");
			}
			break;
		}
	case EFLWGT_INSTALL_CMD:
		{
			_LOGD("[%s] eflwgt-install %s\n", "backend", data.pkgid);
#ifdef SEND_PKGPATH
			_ri_broadcast_status_notification(data.pkgid, PKGTYPE_RPM, "command", "eflwgt-install");
#endif
			ret = _rpm_installer_package_install_with_dbpath(data.pkgid, clientid);
			if (ret != 0) {
				char *errstr = NULL;
				_ri_error_no_to_string(ret, &errstr);
				_ri_broadcast_status_notification(data.pkgid, PKGTYPE_RPM, "error", errstr);
				_ri_stat_cb(data.pkgid, "error", errstr);
				sleep(2);
				_ri_broadcast_status_notification(data.pkgid, PKGTYPE_RPM, "end", "fail");
				_ri_stat_cb(data.pkgid, "end", "fail");
				_LOGE("eflwgt-install failed with err(%d) (%s)\n", ret, errstr);
			} else {
				_LOGD("eflwgt-install success\n");
				_ri_broadcast_status_notification(data.pkgid, PKGTYPE_RPM, "end", "ok");
				_ri_stat_cb(data.pkgid, "end", "ok");
			}
			break;
		}

	default:
		{
			_ri_broadcast_status_notification("unknown", "unknown", "command", "unknown");
			_ri_broadcast_status_notification("unknown", "unknown", "error", "not supported");
			_ri_stat_cb("unknown", "error", "not supported");
			_ri_broadcast_status_notification("unknown", "unknown", "end", "fail");
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
