/*
 * rpm-installer
 *
 * Copyright (c) 2000 - 2011 Samsung Electronics Co., Ltd. All rights reserved.
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
#include <stdarg.h>
#include <sys/wait.h>
#include <sys/types.h>
#include <unistd.h>
#include <wait.h>
#include <stdio.h>
#include <ctype.h>		/* for isspace () */
#include <string.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <dirent.h>
#include <sys/statvfs.h>
#include <syslog.h>

#include "installer-type.h"
#include "installer-util.h"

#ifdef _APPFW_FEATURE_DELTA_UPDATE
int _installer_util_create_dir(const char* dirpath, mode_t mode)
{
	int ret = 0;
	char buf[BUF_SIZE] = { 0, };

	ret = mkdir(dirpath, mode);
	if (ret < 0) {
		if (access(dirpath, F_OK) == 0) {
			_installer_util_delete_dir(dirpath);
			ret = _installer_util_mkpath(dirpath, mode);
			if (ret < 0) {
				if( strerror_r(errno, buf, sizeof(buf)) == 0) {
					_LOGE("mkdir(%s) failed. [%d][%s]", dirpath, errno, buf);
				}
				ret = RPM_INSTALLER_ERR_INTERNAL;
				goto catch;
			}
		} else {
			if( strerror_r(errno, buf, sizeof(buf)) == 0) {
				_LOGE("access(%s) failed. [%d][%s]", dirpath, errno, buf);
			}
			ret = RPM_INSTALLER_ERR_INTERNAL;
			goto catch;
		}
	}
catch:
	return ret;
}
#endif



/* Function with behaviour like `mkdir -p'  */
int _installer_util_mkpath(const char *s, mode_t mode)
{
	char *q = NULL, *r = NULL, *path = NULL, *up = NULL;
	int ret = -1;

	if (strcmp(s, ".") == 0 || strcmp(s, "/") == 0)
		return 0;

	if ((path = strdup(s)) == NULL){
		_LOGE("Not enough memory");
		goto catch;
	}

	if ((q = strdup(s)) == NULL){
		_LOGE("Not enough memory");
		goto catch;
	}

	if ((r = dirname(q)) == NULL)
		goto catch;

	if ((up = strdup(r)) == NULL) {
		_LOGE("Not enough memory");
		goto catch;
	}

	if ((_installer_util_mkpath(up, mode) == -1) && (errno != EEXIST)){
		goto catch;
	}

	if ((mkdir(path, mode) == -1) && (errno != EEXIST))
		ret = -1;
	else
		ret = 0;

catch:
	if (up != NULL)
		free(up);

	if(q != NULL)
		free(q);

	if(path != NULL)
		free(path);

	return ret;

}



int _installer_util_copy_file(const char *src_path, const char *dest_path)
{
	retvm_if(src_path == NULL, RPM_INSTALLER_ERR_WRONG_PARAM, "src_path is NULL.");
	retvm_if(dest_path == NULL, RPM_INSTALLER_ERR_WRONG_PARAM, "dest_path is NULL.");

	int ret = 0;
	FILE *src = NULL;
	FILE *dest = NULL;
	int rc = 0;
	int idx = 0;
	unsigned char temp_buf[8192] = {'\0', };
	size_t size_of_uchar = sizeof(unsigned char);
	size_t size_of_temp_buf = sizeof(temp_buf);
	char *path = NULL;
	char *p = NULL;
	char buf[BUF_SIZE] = { 0, };

	_LOGD("src[%s], dest[%s]",src_path,dest_path);

	src = fopen(src_path, "r");
	strerror_r(errno, buf, sizeof(buf));
	tryvm_if(src == NULL, ret = -1, "fopen(%s) failed. [%d][%s]", src_path, errno, buf);

	dest = fopen(dest_path, "w");
	if (dest == NULL) {
		/* No such file or directory */
		strerror_r(errno, buf, sizeof(buf));
		tryvm_if(errno != ENOENT, ret = -1, "fopen(%s) failed. [%d][%s]", dest_path, errno, buf);

		path = strdup(dest_path);
		tryvm_if(path == NULL, ret = -1, "out of memory");
		p = strrchr(path, '/');
		tryvm_if(p == NULL, ret = -1, "strrchr(%s) failed.", path);

		p++;
		idx = strlen(path) - strlen(p);
		path[idx] = '\0';

		/* make the parent dir */
		if (access(path, F_OK) != 0) {
			const char *mkdir_argv[] = { "/bin/mkdir", "-p", path, NULL };
			ret = _ri_xsystem(mkdir_argv);
			tryvm_if(ret != 0, ret = -1, "_ri_xsystem(mkdir_argv) failed. [%s]", path);

			_LOGD("create directory=[%s]", path);
		}

		/* open the file */
		dest = fopen(dest_path, "w");
		strerror_r(errno, buf, sizeof(buf));
		tryvm_if(dest == NULL, ret = -1, "fopen(%s) failed. [%d][%s]", dest_path, errno, buf);
	}

	while (!feof(src)) {
		rc = fread(temp_buf, size_of_uchar, size_of_temp_buf, src);
		fwrite(temp_buf, size_of_uchar, rc, dest);
	}

	_LOGD("copy: [%s]->[%s]", src_path, dest_path);

catch:
	if (path) {
		free(path);
	}

	if (src) {
		fclose(src);
	}

	if (dest) {
		fclose(dest);
	}

    return  ret;
}

int _installer_util_copy_dir(const char *src_dir, const char *dest_dir)
{
	retvm_if(src_dir == NULL, RPM_INSTALLER_ERR_WRONG_PARAM, "src_dir is NULL.");
	retvm_if(dest_dir == NULL, RPM_INSTALLER_ERR_WRONG_PARAM, "dest_dir is NULL.");

	int ret = 0;
	DIR *dp = NULL;
	struct dirent entry, *result;
	struct stat stFileInfo;
	char buf[BUF_SIZE] = { 0, };

	_LOGD("src[%s], dest[%s]",src_dir,dest_dir);
	dp = opendir(src_dir);
	strerror_r(errno, buf, sizeof(buf));
	tryvm_if(dp == NULL, ret = -1, "opendir(%s) failed. [%d][%s]", src_dir, errno, buf);

	if (access(dest_dir, F_OK) != 0) {
		ret = _installer_util_mkpath(dest_dir, DIRECTORY_PERMISSION_755);
		if (ret < 0) {
			strerror_r(errno, buf, sizeof(buf));
			LOGE("mkdir() err: [%s]", buf);
			goto catch;
		}
		_LOGD("create directory=[%s]", dest_dir);
	}

	for (ret = readdir_r(dp, &entry, &result);
			ret == 0 && result != NULL;
			ret = readdir_r(dp, &entry, &result)) {
		if (((strcmp(entry.d_name, ".")) == 0) || (strcmp(entry.d_name, "..") == 0)) {
			continue;
		}

		char src_filename[FILENAME_MAX] = {0, };
		char dest_filename[FILENAME_MAX] = {0, };
		snprintf(src_filename, FILENAME_MAX, "%s/%s", src_dir, entry.d_name);
		snprintf(dest_filename, FILENAME_MAX, "%s/%s", dest_dir, entry.d_name);

		if (lstat(src_filename, &stFileInfo) < 0) {
			_LOGE("lstat(%s) failed.", src_filename);
			perror(src_filename);
			continue;
		}

		if (S_ISDIR(stFileInfo.st_mode)) {
			_installer_util_copy_dir(src_filename, dest_filename);
		} else if (S_ISLNK(stFileInfo.st_mode)) {
			_LOGE("skip: symlink=[%s]", src_filename);
			continue;
		} else {
			ret = _installer_util_copy_file(src_filename, dest_filename);
			if (ret < 0) {
				_LOGE("_installer_util_copy_file is failed.");
			}
		}
	}

	_LOGD("copy_dir: [%s]->[%s]", src_dir, dest_dir);

catch:
	if (dp) {
		(void)closedir(dp);
	}

	return ret;
}

int _installer_util_delete_dir(const char *dir_path)
{
	retvm_if(dir_path == NULL, RPM_INSTALLER_ERR_WRONG_PARAM, "dir_path is NULL.");

	int ret = 0;
	DIR *dp = NULL;
	struct dirent entry, *result;
	char abs_filename[FILENAME_MAX] = {0, };
	struct stat stFileInfo;
	char buf[BUF_SIZE] = { 0, };

	_LOGD("delete_dir=[%s]", dir_path);

	dp = opendir(dir_path);
	strerror_r(errno, buf, sizeof(buf));
	tryvm_if(dp == NULL, ret = -1, "opendir(%s) failed. [%d][%s]", dir_path, errno, buf);

	for (ret = readdir_r(dp, &entry, &result);
			ret == 0 && result != NULL;
			ret = readdir_r(dp, &entry, &result)) {

		snprintf(abs_filename, FILENAME_MAX, "%s/%s", dir_path, entry.d_name);
		if (lstat(abs_filename, &stFileInfo) < 0) {
			_LOGE("lstat(%s) failed.", abs_filename);
			perror(abs_filename);
			continue;
		}

		if (S_ISDIR(stFileInfo.st_mode)) {
			if (strcmp(entry.d_name, ".") && strcmp(entry.d_name, "..")) {
				_installer_util_delete_dir(abs_filename);
				(void)remove(abs_filename);
			}
		} else {
			(void)remove(abs_filename);
		}
	}

	(void)closedir(dp);
	dp = NULL;

	(void)remove(dir_path);

catch:
	return ret;
}

void _installer_util_free_pkg_info(pkginfo *pkg_info)
{
	if (pkg_info) {
		if (pkg_info->privileges) {
			GList *list = NULL;

			list = g_list_first(pkg_info->privileges);
			while (list) {
				if (list->data) {
					xmlFree(list->data);
				}
				list = g_list_next(list);
			}
			g_list_free(pkg_info->privileges);
			pkg_info->privileges = NULL;
		}

		free(pkg_info);
		pkg_info = NULL;
	}
}

#ifdef _APPFW_FEATURE_DELTA_UPDATE
void _installer_util_free_delta_info(delta_info *info)
{
	if (info && info->pkg_info){
		_installer_util_free_pkg_info(info->pkg_info);
	}
	if (info) {
		GList *list = NULL;
		if (info->modify_files_list) {
			list = g_list_first(info->modify_files_list);
			while (list) {
				if (list->data) {
					xmlFree(list->data);
				}
				list = g_list_next(list);
			}
			g_list_free(info->modify_files_list);
			info->modify_files_list = NULL;
		}
		if (info->add_files_list) {
			list = g_list_first(info->add_files_list);
			while (list) {
				if (list->data) {
					xmlFree(list->data);
				}
				list = g_list_next(list);
			}
			g_list_free(info->add_files_list);
			info->add_files_list= NULL;
		}
		if (info->remove_files_list) {
			list = g_list_first(info->remove_files_list);
			while (list) {
				if (list->data) {
					xmlFree(list->data);
				}
				list = g_list_next(list);
			}
			g_list_free(info->remove_files_list);
			info->remove_files_list = NULL;
		}
		free(info);
		info = NULL;
	}
	return;
}
#endif

int _installer_util_get_configuration_value(const char *value)
{
	retvm_if(value == NULL, RPM_INSTALLER_ERR_WRONG_PARAM, "value is NULL.");

	char buffer[BUF_SIZE] = {0, };
	char *p = NULL;
	FILE *fi = NULL;
	int len = 0;
	int ret = 0;
	char buf[BUF_SIZE] = { 0, };

	ret = access(CORETPK_CONFIG_PATH, F_OK);
	strerror_r(errno, buf, sizeof(buf));
	tryvm_if(ret != 0, ret = 1, "access(%s) failed. [%d][%s]", CORETPK_CONFIG_PATH, errno, buf);

	fi = fopen(CORETPK_CONFIG_PATH, "r");
	strerror_r(errno, buf, sizeof(buf));
	tryvm_if(fi == NULL, ret = 1, "fopen(%s) failed. [%d][%s]", CORETPK_CONFIG_PATH, errno, buf);

	while (fgets(buffer, BUF_SIZE, fi) != NULL) {
		/* buffer will be like signature=off, on */
		if (strncmp(buffer, value, strlen(value)) == 0) {
			len = strlen(buffer);
			/* remove newline character */
			buffer[len - 1] = '\0';
			p = strchr(buffer, '=');
			if (p) {
				p++;
				if (strcmp(p, "on") == 0) {
					ret = 1;
				} else {
					ret = 0;
				}
				_LOGE("[%s]=[%s]", value, p);
				break;
			}
		} else {
			continue;
		}
	}

catch:
	if (fi) {
		fclose(fi);
	}

	return ret;
}

char *_installer_util_get_str(const char *str, const char *pKey)
{
	const char* p = NULL;
	const char* pStart = NULL;
	const char* pEnd = NULL;

	if (str == NULL)
		return NULL;

	char *pBuf = strdup(str);
	if(!pBuf){
		_LOGE("Malloc failed !");
		return NULL;
	}

	p = strstr(pBuf, pKey);
	if (p == NULL){
		if(pBuf){
			free(pBuf);
			pBuf = NULL;
		}
		return NULL;
	}

	pStart = p + strlen(pKey);
	pEnd = strchr(pStart, SEPERATOR_END);

	if (pEnd == NULL){
		if(pBuf){
			free(pBuf);
			pBuf = NULL;
		}
		return NULL;
	}

	size_t len = pEnd - pStart;

	if (len <= 0){
		if(pBuf){
			free(pBuf);
			pBuf = NULL;
		}
		return NULL;
	}
	char *pRes = (char*)malloc(len + 1);
	if(!pRes){
		if(pBuf){
			free(pBuf);
			pBuf = NULL;
		}
		_LOGE("Malloc failed!");
		return NULL;
	}
	strncpy(pRes, pStart, len);
	pRes[len] = 0;

	if(pBuf){
		free(pBuf);
		pBuf = NULL;
	}

	return pRes;
}

int _installer_util_extract_version(const char* version, int* major, int* minor, int* macro)
{
	char* version_temp = NULL;
	char* major_str = NULL;
	char* minor_str = NULL;
	char* macro_str = NULL;
	char* save_str = NULL;

	version_temp = strdup(version);

	major_str = strtok_r(version_temp, ".", &save_str);
	if (major_str == NULL)
	{
		_LOGE("%s strtok_r() failed. major version is NULL.", __func__);
		free(version_temp);
		return -1;
	}

	minor_str = strtok_r(NULL, ".", &save_str);
	if (minor_str == NULL)
	{
		_LOGE("%s strtok_r() failed. minor version is NULL.", __func__);
		free(version_temp);
		return -1;
	}

	*major = atoi(major_str);
	*minor = atoi(minor_str);

	macro_str = strtok_r(NULL, ".", &save_str);
	if (macro_str == NULL)
	{
		_LOGD("%s strtok_r() failed. macro version is NULL.", __func__);
		_LOGD("%s version = [%s] -> major = [%d], minor = [%d]", __func__, version, *major, *minor);
	}
	else
	{
		*macro = atoi(macro_str);
		_LOGD("%s version = [%s] -> major = [%d], minor = [%d], macro = [%d]", __func__, version, *major, *minor, *macro);
	}

	free(version_temp);

	return 0;
}

int _installer_util_compare_version(const char* old_version, const char* new_version)
{
	int res = 0;
	int old_version_major = 0;
	int old_version_minor = 0;
	int old_version_macro = 0;
	int new_version_major = 0;
	int new_version_minor = 0;
	int new_version_macro = 0;

	res = _installer_util_extract_version(new_version, &new_version_major, &new_version_minor, &new_version_macro);
	if (res < 0)
	{
		_LOGE("%s extract_verison() failed.(%d)", __func__, res);
		return VERSION_ERROR;
	}

	res = _installer_util_extract_version(old_version, &old_version_major, &old_version_minor, &old_version_macro);
	if (res < 0)
	{
		_LOGE("%s extract_verison() failed.(%d)", __func__, res);
		return VERSION_ERROR;
	}

	_LOGD("new[%d.%d.%d] old[%d.%d.%d]", new_version_major, new_version_minor, new_version_macro,
		 old_version_major, old_version_minor, old_version_macro);

	if (new_version_major > old_version_major)
	{
		return VERSION_NEW;
	}
	else if (new_version_major < old_version_major)
	{
		return VERSION_OLD;
	}

	if (new_version_minor > old_version_minor)
	{
		return VERSION_NEW;
	}
	else if (new_version_minor < old_version_minor)
	{
		return VERSION_OLD;
	}

	if (new_version_macro > old_version_macro)
	{
		return VERSION_NEW;
	}
	else if (new_version_macro < old_version_macro)
	{
		return VERSION_OLD;
	}

	return VERSION_SAME;
}

int _ri_get_attribute(xmlTextReaderPtr reader, char *attribute, const char **xml_attribute)
{
	if(xml_attribute == NULL){
		_LOGE("@xml_attribute is NULL!!");
		return -1;
	}
	xmlChar	*attrib_val = xmlTextReaderGetAttribute(reader,XMLCHAR(attribute));
	if(attrib_val)
		*xml_attribute = ASCII(attrib_val);

	return 0;
}

int _ri_next_child_element(xmlTextReaderPtr reader, int depth)
{
	int ret = xmlTextReaderRead(reader);
	int cur = xmlTextReaderDepth(reader);
	while (ret == 1) {

		switch (xmlTextReaderNodeType(reader)) {
		case XML_READER_TYPE_ELEMENT:
			if (cur == depth + 1)
				return 1;
			break;
		case XML_READER_TYPE_TEXT:
			if (cur == depth + 1)
				return 0;
			break;
		case XML_READER_TYPE_END_ELEMENT:
			if (cur == depth)
				return 0;
			break;
		default:
			if (cur <= depth)
				return 0;
			break;
		}
		ret = xmlTextReaderRead(reader);
		cur = xmlTextReaderDepth(reader);
	}
	return ret;
}

void _ri_error_no_to_string(int errnumber, char **errstr)
{
	if (errstr == NULL) {
		_LOGE("errstr is NULL.");
		return;
	}

	if (errnumber == RPM_INSTALLER_SUCCESS) {
		_LOGE("Not Error. [SUCCESS]");
		return;
	}

	switch (errnumber) {
	case RPM_INSTALLER_ERR_WRONG_PARAM:
		*errstr = RPM_INSTALLER_ERR_WRONG_PARAM_STR;
		break;
	case RPM_INSTALLER_ERR_DBUS_PROBLEM:
		*errstr = RPM_INSTALLER_ERR_DBUS_PROBLEM_STR;
		break;
	case RPM_INSTALLER_ERR_NOT_ENOUGH_MEMORY:
		*errstr = RPM_INSTALLER_ERR_NOT_ENOUGH_MEMORY_STR;
		break;
	case RPM_INSTALLER_ERR_PACKAGE_EXIST:
		*errstr = RPM_INSTALLER_ERR_PACKAGE_EXIST_STR;
		break;
	case RPM_INSTALLER_ERR_PACKAGE_NOT_INSTALLED:
		*errstr = RPM_INSTALLER_ERR_PACKAGE_NOT_INSTALLED_STR;
		break;
	case RPM_INSTALLER_ERR_RESOURCE_BUSY:
		*errstr = RPM_INSTALLER_ERR_RESOURCE_BUSY_STR;
		break;
	case RPM_INSTALLER_ERR_UNKNOWN:
		*errstr = RPM_INSTALLER_ERR_UNKNOWN_STR;
		break;
	case RPM_INSTALLER_ERR_PKG_NOT_FOUND:
		*errstr = RPM_INSTALLER_ERR_PKG_NOT_FOUND_STR;
		break;
	case RPM_INSTALLER_ERR_NOT_SUPPOTED_VERSION:
		*errstr = RPM_INSTALLER_ERR_NOT_SUPPOTED_VERSION_STR;
		break;
	case RPM_INSTALLER_ERR_NOT_SUPPORTED_API_VERSION:
		*errstr = RPM_INSTALLER_ERR_NOT_SUPPORTED_API_VERSION_STR;
		break;
	case RPM_INSTALLER_ERR_NO_RPM_FILE:
		*errstr = RPM_INSTALLER_ERR_NO_RPM_FILE_STR;
		break;
	case RPM_INSTALLER_ERR_DB_ACCESS_FAILED:
		*errstr = RPM_INSTALLER_ERR_DB_ACCESS_FAILED_STR;
		break;
	case RPM_INSTALLER_ERR_RPM_OPERATION_FAILED:
		*errstr = RPM_INSTALLER_ERR_RPM_OPERATION_FAILED_STR;
		break;
	case RPM_INSTALLER_ERR_PACKAGE_NOT_UPGRADED:
		*errstr = RPM_INSTALLER_ERR_PACKAGE_NOT_UPGRADED_STR;
		break;
	case RPM_INSTALLER_ERR_RPM_SCRIPT_WRONG_ARGS:
		*errstr = RPM_INSTALLER_ERR_RPM_SCRIPT_WRONG_ARGS_STR;
		break;
	case RPM_INSTALLER_ERR_PACKAGE_INSTALLATION_DISABLED:
		*errstr = RPM_INSTALLER_ERR_PACKAGE_INSTALLATION_DISABLED_STR;
		break;
	case RPM_INSTALLER_ERR_PACKAGE_UNINSTALLATION_DISABLED:
		*errstr = RPM_INSTALLER_ERR_PACKAGE_UNINSTALLATION_DISABLED_STR;
		break;
	case RPM_INSTALLER_ERR_CLEAR_DATA_FAILED:
		*errstr = RPM_INSTALLER_ERR_CLEAR_DATA_FAILED_STR;
		break;
	case RPM_INSTALLER_ERR_INTERNAL:
		*errstr = RPM_INSTALLER_ERR_INTERNAL_STR;
		break;
	case RPM_INSTALLER_ERR_NO_MANIFEST:
		*errstr = RPM_INSTALLER_ERR_NO_MANIFEST_STR;
		break;
	case RPM_INSTALLER_ERR_INVALID_MANIFEST:
		*errstr = RPM_INSTALLER_ERR_INVALID_MANIFEST_STR;
		break;
	case RPM_INSTALLER_ERR_SIG_NOT_FOUND:
		*errstr = RPM_INSTALLER_ERR_SIG_NOT_FOUND_STR;
		break;
	case RPM_INSTALLER_ERR_SIG_INVALID:
		*errstr = RPM_INSTALLER_ERR_SIG_INVALID_STR;
		break;
	case RPM_INSTALLER_ERR_SIG_VERIFICATION_FAILED:
		*errstr = RPM_INSTALLER_ERR_SIG_VERIFICATION_FAILED_STR;
		break;
	case RPM_INSTALLER_ERR_ROOT_CERT_NOT_FOUND:
		*errstr = RPM_INSTALLER_ERR_ROOT_CERT_NOT_FOUND_STR;
		break;
	case RPM_INSTALLER_ERR_CERT_INVALID:
		*errstr = RPM_INSTALLER_ERR_CERT_INVALID_STR;
		break;
	case RPM_INSTALLER_ERR_CERTCHAIN_VERIFICATION_FAILED:
		*errstr = RPM_INSTALLER_ERR_CERTCHAIN_VERIFICATION_FAILED_STR;
		break;
	case RPM_INSTALLER_ERR_NO_CONFIG:
		*errstr = RPM_INSTALLER_ERR_NO_CONFIG_STR;
		break;
	case RPM_INSTALLER_ERR_INVALID_CONFIG:
		*errstr = RPM_INSTALLER_ERR_INVALID_CONFIG_STR;
		break;
	case RPM_INSTALLER_ERR_CMD_NOT_SUPPORTED:
		*errstr = RPM_INSTALLER_ERR_CMD_NOT_SUPPORTED_STR;
		break;
	case RPM_INSTALLER_ERR_PRIVILEGE_UNAUTHORIZED:
		*errstr = RPM_INSTALLER_ERR_PRIVILEGE_UNAUTHORIZED_STR;
		break;
	case RPM_INSTALLER_ERR_PRIVILEGE_UNKNOWN:
		*errstr = RPM_INSTALLER_ERR_PRIVILEGE_UNKNOWN_ERR_STR;
		break;
	case RPM_INSTALLER_ERR_PRIVILEGE_USING_LEGACY_FAILED:
		*errstr = RPM_INSTALLER_ERR_PRIVILEGE_USING_LEGACY_FAILED_STR;
		break;
	case RPM_INSTALLER_ERR_CERTIFICATE_EXPIRED:
		*errstr = RPM_INSTALLER_ERR_CERTIFICATE_EXPIRED_STR;
		break;
	case RPM_INSTALLER_ERR_UNZIP_FAILED:
		*errstr = RPM_INSTALLER_ERR_UNZIP_FAILED_STR;
		break;
	case RPM_INSTALLER_ERR_PACKAGE_INVALID:
		*errstr = RPM_INSTALLER_ERR_PACKAGE_INVALID_STR;
		break;
	default:
		*errstr = RPM_INSTALLER_ERR_UNKNOWN_STR;
		break;
	}
}

int _ri_string_to_error_no(const char *errstr)
{
	if (errstr == NULL)
		return RPM_INSTALLER_ERR_UNKNOWN;

	int errnumber = RPM_INSTALLER_ERR_UNKNOWN;

	if (strcmp(errstr, RPM_INSTALLER_SUCCESS_STR) == 0)
		errnumber = RPM_INSTALLER_SUCCESS;
	else if (strcmp(errstr, RPM_INSTALLER_ERR_WRONG_PARAM_STR) == 0)
		errnumber = RPM_INSTALLER_ERR_WRONG_PARAM;
	else if (strcmp(errstr, RPM_INSTALLER_ERR_DBUS_PROBLEM_STR) == 0)
		errnumber = RPM_INSTALLER_ERR_DBUS_PROBLEM;
	else if (strcmp(errstr, RPM_INSTALLER_ERR_NOT_ENOUGH_MEMORY_STR) == 0)
		errnumber = RPM_INSTALLER_ERR_NOT_ENOUGH_MEMORY;
	else if (strcmp(errstr, RPM_INSTALLER_ERR_PACKAGE_EXIST_STR) == 0)
		errnumber = RPM_INSTALLER_ERR_PACKAGE_EXIST;
	else if (strcmp(errstr, RPM_INSTALLER_ERR_PACKAGE_NOT_INSTALLED_STR) == 0)
		errnumber = RPM_INSTALLER_ERR_PACKAGE_NOT_INSTALLED;
	else if (strcmp(errstr, RPM_INSTALLER_ERR_RESOURCE_BUSY_STR) == 0)
		errnumber = RPM_INSTALLER_ERR_RESOURCE_BUSY;
	else if (strcmp(errstr, RPM_INSTALLER_ERR_UNKNOWN_STR) == 0)
		errnumber = RPM_INSTALLER_ERR_UNKNOWN;
	else if (strcmp(errstr, RPM_INSTALLER_ERR_PKG_NOT_FOUND_STR) == 0)
		errnumber = RPM_INSTALLER_ERR_PKG_NOT_FOUND;
	else if (strcmp(errstr, RPM_INSTALLER_ERR_NOT_SUPPOTED_VERSION_STR) == 0)
		errnumber = RPM_INSTALLER_ERR_NOT_SUPPOTED_VERSION;
	else if (strcmp(errstr, RPM_INSTALLER_ERR_NOT_SUPPORTED_API_VERSION_STR) == 0)
		errnumber = RPM_INSTALLER_ERR_NOT_SUPPORTED_API_VERSION;
	else if (strcmp(errstr, RPM_INSTALLER_ERR_NO_RPM_FILE_STR) == 0)
		errnumber = RPM_INSTALLER_ERR_NO_RPM_FILE;
	else if (strcmp(errstr, RPM_INSTALLER_ERR_DB_ACCESS_FAILED_STR) == 0)
		errnumber = RPM_INSTALLER_ERR_DB_ACCESS_FAILED;
	else if (strcmp(errstr, RPM_INSTALLER_ERR_RPM_OPERATION_FAILED_STR) == 0)
		errnumber = RPM_INSTALLER_ERR_RPM_OPERATION_FAILED;
	else if (strcmp(errstr, RPM_INSTALLER_ERR_PACKAGE_NOT_UPGRADED_STR) == 0)
		errnumber = RPM_INSTALLER_ERR_PACKAGE_NOT_UPGRADED;
	else if (strcmp(errstr, RPM_INSTALLER_ERR_RPM_SCRIPT_WRONG_ARGS_STR) == 0)
		errnumber = RPM_INSTALLER_ERR_RPM_SCRIPT_WRONG_ARGS;
	else if (strcmp(errstr, RPM_INSTALLER_ERR_PACKAGE_INSTALLATION_DISABLED_STR) == 0)
		errnumber = RPM_INSTALLER_ERR_PACKAGE_INSTALLATION_DISABLED;
	else if (strcmp(errstr, RPM_INSTALLER_ERR_PACKAGE_UNINSTALLATION_DISABLED_STR) == 0)
		errnumber = RPM_INSTALLER_ERR_PACKAGE_UNINSTALLATION_DISABLED;
	else if (strcmp(errstr, RPM_INSTALLER_ERR_CLEAR_DATA_FAILED_STR) == 0)
		errnumber = RPM_INSTALLER_ERR_CLEAR_DATA_FAILED;
	else if (strcmp(errstr, RPM_INSTALLER_ERR_INTERNAL_STR) == 0)
		errnumber = RPM_INSTALLER_ERR_INTERNAL;
	else if (strcmp(errstr, RPM_INSTALLER_ERR_NO_MANIFEST_STR) == 0)
		errnumber = RPM_INSTALLER_ERR_NO_MANIFEST;
	else if (strcmp(errstr, RPM_INSTALLER_ERR_INVALID_MANIFEST_STR) == 0)
		errnumber = RPM_INSTALLER_ERR_INVALID_MANIFEST;
	else if (strcmp(errstr, RPM_INSTALLER_ERR_SIG_NOT_FOUND_STR) == 0)
		errnumber = RPM_INSTALLER_ERR_SIG_NOT_FOUND;
	else if (strcmp(errstr, RPM_INSTALLER_ERR_SIG_INVALID_STR) == 0)
		errnumber = RPM_INSTALLER_ERR_SIG_INVALID;
	else if (strcmp(errstr, RPM_INSTALLER_ERR_SIG_VERIFICATION_FAILED_STR) == 0)
		errnumber = RPM_INSTALLER_ERR_SIG_VERIFICATION_FAILED;
	else if (strcmp(errstr, RPM_INSTALLER_ERR_ROOT_CERT_NOT_FOUND_STR) == 0)
		errnumber = RPM_INSTALLER_ERR_ROOT_CERT_NOT_FOUND;
	else if (strcmp(errstr, RPM_INSTALLER_ERR_CERT_INVALID_STR) == 0)
		errnumber = RPM_INSTALLER_ERR_CERT_INVALID;
	else if (strcmp(errstr, RPM_INSTALLER_ERR_CERTCHAIN_VERIFICATION_FAILED_STR) == 0)
		errnumber = RPM_INSTALLER_ERR_CERTCHAIN_VERIFICATION_FAILED;
	else if (strcmp(errstr, RPM_INSTALLER_ERR_NO_CONFIG_STR) == 0)
		errnumber = RPM_INSTALLER_ERR_NO_CONFIG;
	else if (strcmp(errstr, RPM_INSTALLER_ERR_INVALID_CONFIG_STR) == 0)
		errnumber = RPM_INSTALLER_ERR_INVALID_CONFIG;
	else if (strcmp(errstr, RPM_INSTALLER_ERR_CMD_NOT_SUPPORTED_STR) == 0)
		errnumber = RPM_INSTALLER_ERR_CMD_NOT_SUPPORTED;
	else if (strcmp(errstr, RPM_INSTALLER_ERR_PRIVILEGE_UNAUTHORIZED_STR) == 0)
		errnumber = RPM_INSTALLER_ERR_PRIVILEGE_UNAUTHORIZED;
	else if (strcmp(errstr, RPM_INSTALLER_ERR_PRIVILEGE_UNKNOWN_ERR_STR) == 0)
		errnumber = RPM_INSTALLER_ERR_PRIVILEGE_UNKNOWN;
	else if (strcmp(errstr, RPM_INSTALLER_ERR_PRIVILEGE_USING_LEGACY_FAILED_STR) == 0)
		errnumber = RPM_INSTALLER_ERR_PRIVILEGE_USING_LEGACY_FAILED;
	else if (strcmp(errstr, RPM_INSTALLER_ERR_CERTIFICATE_EXPIRED_STR) == 0)
		errnumber = RPM_INSTALLER_ERR_CERTIFICATE_EXPIRED;
	else if (strcmp(errstr, RPM_INSTALLER_ERR_UNZIP_FAILED_STR) == 0)
		errnumber = RPM_INSTALLER_ERR_UNZIP_FAILED;
	else if (strcmp(errstr, RPM_INSTALLER_ERR_PACKAGE_INVALID_STR) == 0)
		errnumber = RPM_INSTALLER_ERR_PACKAGE_INVALID;
	else
		errnumber = RPM_INSTALLER_ERR_UNKNOWN;

	return errnumber;
}

char* _manifest_to_package(const char* manifest)
{
	char *package;

	if(manifest == NULL) {
		_LOGE("manifest is NULL.\n");
		return NULL;
	}

	package = strdup(manifest);
	if(package == NULL) {
		_LOGE("strdup failed.\n");
		return NULL;
	}

	if (!strstr(package, ".xml")) {
		_LOGE("%s is not a manifest file\n", manifest);
		free(package);
		return NULL;
	}

	return package;
}

int _child_element(xmlTextReaderPtr reader, int depth)
{
	int ret = xmlTextReaderRead(reader);
	int cur = xmlTextReaderDepth(reader);
	while (ret == 1) {

		switch (xmlTextReaderNodeType(reader)) {
			case XML_READER_TYPE_ELEMENT:
				if (cur == depth + 1)
					return 1;
				break;
			case XML_READER_TYPE_TEXT:
				/*text is handled by each function separately*/
				if (cur == depth + 1)
					return 0;
				break;
			case XML_READER_TYPE_END_ELEMENT:
				if (cur == depth)
					return 0;
				break;
			default:
				if (cur <= depth)
					return 0;
				break;
			}

		ret = xmlTextReaderRead(reader);
		cur = xmlTextReaderDepth(reader);
	}
	return ret;
}

/*
This Function reads the package field from the xml file.
*/
int  _get_package_name_from_xml(char* manifest, char** pkgname){

	const char *val = NULL;
	const xmlChar *node;
	xmlTextReaderPtr reader;
	int ret = PMINFO_R_OK;

	if(manifest == NULL) {
		_LOGE("Input argument is NULL\n");
		return PMINFO_R_ERROR;
	}

	if(pkgname == NULL) {
		_LOGE("Argument supplied to hold return value is NULL\n");
		return PMINFO_R_ERROR;
	}

	reader = xmlReaderForFile(manifest, NULL, 0);

	if (reader){
		if ( _child_element(reader, -1)) {
			node = xmlTextReaderConstName(reader);
			if (!node) {
				_LOGE("xmlTextReaderConstName value is NULL\n");
				ret =  PMINFO_R_ERROR;
				goto end;
			}

			if (!strcmp(ASCII(node), "manifest")) {
				ret = _ri_get_attribute(reader,"package",&val);
				if(ret != 0){
					_LOGE("@Error in getting attribute value");
					ret = PMINFO_R_ERROR;
					goto end;
				}

				if(val){
					*pkgname = strdup(val);
					if(*pkgname == NULL){
						_LOGE("Malloc Failed!!");
						ret = PMINFO_R_ERROR;
						goto end;
					}
				}
			} else {
				_LOGE("Unable to create xml reader\n");
				ret =  PMINFO_R_ERROR;
			}
		}
	} else {
		_LOGE("xmlReaderForFile value is NULL\n");
		return PMINFO_R_ERROR;
	}

end:
	xmlFreeTextReader(reader);

	if(val)
		free((void*)val);

	return ret;
}

int _ri_recursive_delete_dir(char *dirname)
{
	int ret=0;
	DIR *dp;
	struct dirent entry, *result;
	char abs_filename[FILENAME_MAX];
	struct stat stFileInfo;
	dp = opendir(dirname);
	if (dp != NULL) {
		for (ret = readdir_r(dp, &entry, &result);
				ret == 0 && result != NULL;
				ret = readdir_r(dp, &entry, &result)) {

			snprintf(abs_filename, FILENAME_MAX, "%s/%s", dirname,
				 entry.d_name);
			if (lstat(abs_filename, &stFileInfo) < 0)
				perror(abs_filename);
			if (S_ISDIR(stFileInfo.st_mode)) {
				if (strcmp(entry.d_name, ".") &&
				    strcmp(entry.d_name, "..")) {
					ret=_ri_recursive_delete_dir(abs_filename);
					if(ret < 0)
						_LOGE("_ri_recursive_delete_dir fail\n");

					ret=remove(abs_filename);
					if(ret < 0)
						_LOGE("remove fail\n");
				}
			} else {
				ret = remove(abs_filename);
				if(ret < 0)
					_LOGE("Couldn't remove abs_filename\n");
			}
		}
		(void)closedir(dp);
	} else {
		_LOGE("Couldn't open the directory\n");
		if (errno == ENOENT)
			return RPM_INSTALLER_SUCCESS;
		else
			return RPM_INSTALLER_ERR_CLEAR_DATA_FAILED;
	}

	return RPM_INSTALLER_SUCCESS;
}

 int _ri_xsystem(const char *argv[])
{
	int status = 0;
	pid_t pid;
	pid = fork();
	switch (pid) {
	case -1:
		perror("fork failed");
		return -1;
	case 0:
		/* child */
		execvp(argv[0], (char *const *)argv);
		_exit(-1);
	default:
		/* parent */
		break;
	}
	if (waitpid(pid, &status, 0) == -1) {
		perror("waitpid failed");
		return -1;
	}
	if (WIFSIGNALED(status)) {
		perror("signal");
		return -1;
	}
	if (!WIFEXITED(status)) {
		/* shouldn't happen */
		perror("should not happen");
		return -1;
	}
	return WEXITSTATUS(status);
}

int _ri_get_available_free_memory(const char *opt_path, unsigned long *free_mem)
{
	struct statvfs buf;
	int ret = 0;
	if (opt_path == NULL || free_mem == NULL) {
		_LOGE("Invalid input parameter\n");
		return -1;
	}
	memset((void *)&buf, '\0', sizeof(struct statvfs));
	ret = statvfs(opt_path, &buf);
	if (ret) {
		_LOGE("statvfs(%s) failed.", opt_path);
		return -1;
	}
	*free_mem = (buf.f_bfree * buf.f_bsize)/SIZE_KB;
	return 0;
}


unsigned long  _ri_calculate_file_size(const char *filename)
{
	struct stat stFileInfo;

	if (stat(filename, &stFileInfo) < 0) {
		perror(filename);
		return 0;
	} else
		return (stFileInfo.st_size/SIZE_KB);
}

unsigned long  _ri_calculate_rpm_size( char* rpm_file)
{
	_LOGE("librpm not used/supported");
	return 0;
}
