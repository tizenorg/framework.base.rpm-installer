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
#include "rpm-installer-util.h"

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

void _ri_error_no_to_string(int errnumber, char **errstr)
{
	if (errstr == NULL)
		return;
	switch (errnumber) {
	case RPM_INSTALLER_SUCCESS:
		*errstr = RPM_INSTALLER_SUCCESS_STR;
		break;
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
	default:
		*errstr = RPM_INSTALLER_ERR_UNKNOWN_STR;
		break;
	}
}

int _ri_string_to_error_no(char *errstr)
{
	int errnumber = RPM_INSTALLER_ERR_UNKNOWN;
	if (errstr == NULL)
		return errnumber;

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
	else if (strcmp(errstr, RPM_INSTALLER_ERR_PACKAGE_NOT_INSTALLED_STR)
		 == 0)
		errnumber = RPM_INSTALLER_ERR_PACKAGE_NOT_INSTALLED;
	else if (strcmp(errstr, RPM_INSTALLER_ERR_RESOURCE_BUSY_STR) == 0)
		errnumber = RPM_INSTALLER_ERR_RESOURCE_BUSY;
	else if (strcmp(errstr, RPM_INSTALLER_ERR_UNKNOWN_STR) == 0)
		errnumber = RPM_INSTALLER_ERR_UNKNOWN;
	else if (strcmp(errstr, RPM_INSTALLER_ERR_PKG_NOT_FOUND_STR) == 0)
		errnumber = RPM_INSTALLER_ERR_PKG_NOT_FOUND;
	else if (strcmp(errstr, RPM_INSTALLER_ERR_NOT_SUPPOTED_VERSION_STR) ==
		 0)
		errnumber = RPM_INSTALLER_ERR_NOT_SUPPOTED_VERSION;
	else if (strcmp(errstr, RPM_INSTALLER_ERR_NO_RPM_FILE_STR) == 0)
		errnumber = RPM_INSTALLER_ERR_NO_RPM_FILE;
	else if (strcmp(errstr, RPM_INSTALLER_ERR_DB_ACCESS_FAILED_STR) == 0)
		errnumber = RPM_INSTALLER_ERR_DB_ACCESS_FAILED;
	else if (strcmp(errstr, RPM_INSTALLER_ERR_RPM_OPERATION_FAILED_STR)
		 == 0)
		errnumber = RPM_INSTALLER_ERR_RPM_OPERATION_FAILED;
	else if (strcmp(errstr, RPM_INSTALLER_ERR_PACKAGE_NOT_UPGRADED_STR) ==
		 0)
		errnumber = RPM_INSTALLER_ERR_PACKAGE_NOT_UPGRADED;
	else if (strcmp(errstr, RPM_INSTALLER_ERR_RPM_SCRIPT_WRONG_ARGS_STR) ==
		 0)
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
	else
		errnumber = RPM_INSTALLER_ERR_UNKNOWN;

	return errnumber;
}

int _rpm_delete_dir(char *dirname)
{
	int ret = 0;
	DIR *dp;
	struct dirent *ep;
	char abs_filename[FILENAME_MAX];
	struct stat stFileInfo;

	if (dirname == NULL) {
		_LOGE("dirname is NULL.");
		return -1;
	}

	_LOGD("delete_dir=[%s]", dirname);

	dp = opendir(dirname);
	if (dp != NULL) {
		while ((ep = readdir(dp))) {
			snprintf(abs_filename, FILENAME_MAX, "%s/%s", dirname, ep->d_name);
			if (lstat(abs_filename, &stFileInfo) < 0) {
				_LOGE("lstat(%s) failed.", abs_filename);
				perror(abs_filename);
			}

			if (S_ISDIR(stFileInfo.st_mode)) {
				if (strcmp(ep->d_name, ".") && strcmp(ep->d_name, "..")) {
					_rpm_delete_dir(abs_filename);
					(void)remove(abs_filename);
				}
			} else {
				(void)remove(abs_filename);
			}
		}
		(void)closedir(dp);
	} else {
		_LOGE("opendir(%s) failed.", dirname);
		return -1;
	}

	ret = remove(dirname);
	if (ret < 0)
		_LOGE("remove(%s) failed.", dirname);

	return 0;
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

/* Extract the basename from the file's path */
char *_ri_basename(char *name)
{
	int length;
	length = name ? strlen(name) : 0;
	if (!length)
		return ".";

	while (--length > 0 && name[length] != '/');

	return length <= 0 ? name : name + length + (name[length] == '/');
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
This Function get the package name from the rpm file's path..
*/
int  _get_pkgname_from_rpm_name(char * pkgfile, char **rpm_name){

	char* rpm_file = NULL;
	char  name[PATH_MAX] = {0};
	char  temp[PATH_MAX]={0};
	char *saveptr = NULL;;
	char *str= NULL;
	char c ;
	int ret = RPM_INSTALLER_SUCCESS;

	if(pkgfile == NULL || rpm_name == NULL){
		_LOGE("Invalid Parameter!!");
		return RPM_INSTALLER_ERR_WRONG_PARAM;

	}
	_LOGD("RPM path is [%s]",pkgfile);

	/* Get the rpm name from rpm file's path */
	rpm_file = _ri_basename(pkgfile);
	_LOGD("RPM name is [%s]",rpm_file);

	strncpy(name,rpm_file,strlen(rpm_file));
	str = strtok_r(name, "-", &saveptr);
	if(rpm_file[strlen(name)] != '\0'){
		c = rpm_file[strlen(name) + 1];
	}else{
		if(strstr(name,".rpm")){
			name[strlen(name)-strlen(".rpm")]='\0';
		}
		*rpm_name = strdup(name);
		if(*rpm_name == NULL){
			_LOGE("Malloc failed!!");
			ret = RPM_INSTALLER_ERR_NOT_ENOUGH_MEMORY;
		}
		goto end;
	}

	while(!isdigit(c)){
		memset(temp,'\0',PATH_MAX);
		str = strtok_r(NULL, "-", &saveptr);
		snprintf(temp,PATH_MAX,"-%s",str);
		strncat(name,temp,strlen(temp));
		if(rpm_file[strlen(name)] != '\0'){
			c = rpm_file[strlen(name) + 1];
		}else{
			break;
		}
	}
	if(strstr(name,".rpm")){
		name[strlen(name)-strlen(".rpm")]='\0';
	}
	*rpm_name = strdup(name);
	if(*rpm_name == NULL){
		_LOGE("Malloc failed!!");
		ret = RPM_INSTALLER_ERR_NOT_ENOUGH_MEMORY;
	}

end:
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
	struct dirent *ep;
	char abs_filename[FILENAME_MAX];
	struct stat stFileInfo;
	dp = opendir(dirname);
	if (dp != NULL) {
		while ((ep = readdir(dp))) {
			snprintf(abs_filename, FILENAME_MAX, "%s/%s", dirname,
				 ep->d_name);
			if (lstat(abs_filename, &stFileInfo) < 0)
				perror(abs_filename);
			if (S_ISDIR(stFileInfo.st_mode)) {
				if (strcmp(ep->d_name, ".") &&
				    strcmp(ep->d_name, "..")) {
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
void _ri_remove_wgt_unzip_dir()
{
	if (!access(DIR_RPM_INSTALLER_APPLICATIONS_TEMP, F_OK)) {
		_ri_recursive_delete_dir(DIR_RPM_INSTALLER_APPLICATIONS_TEMP);
		(void)remove(DIR_RPM_INSTALLER_APPLICATIONS_TEMP);
	}

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
		_LOGE("Unable to get /opt/usr memory information\n");
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

void _ri_process_config_node(xmlTextReaderPtr reader, pkginfo * info)
{
	const xmlChar *node;
	const char *pkgid = NULL;
	const char *version = NULL;
	node = xmlTextReaderConstName(reader);
	if (node == NULL) {
		return;
	}
	if (strcmp(ASCII(node), "widget") == 0) {
		if (xmlTextReaderNodeType(reader) == 1) {
			if(_ri_get_attribute(reader,"version",&version) != 0){
				_LOGE("@Error while getting the attribute value");
				return;
			}
				snprintf(info->version, VERSION_MAX_LEN - 1, "%s", version);
				_LOGD("<version> %s", info->version);
		}
	}


	if (strcmp(ASCII(node), "tizen:application") == 0) {
		if (xmlTextReaderNodeType(reader) == 1) {
			if(_ri_get_attribute(reader,"package",&pkgid) != 0){
				_LOGE("@Error while getting the attribute value");
				return;
			}
			snprintf(info->package_name, PKG_MAX_LEN - 1, "%s", pkgid);
			_LOGD("<package> %s", info->package_name);
		}
	}
	if(pkgid){
		free((void*)pkgid);
		pkgid = NULL;
	}

	if(version){
		free((void*)version);
		version = NULL;
	}
	return;

}

int  _ri_stream_config_file(const char* filename, pkginfo *info)
{
	xmlTextReaderPtr reader;
	int ret = RPM_INSTALLER_SUCCESS;

	_LOGD("Reading config file [%s]",filename);
	reader = xmlReaderForFile(filename,NULL,0);
	if (reader != NULL) {
		ret = xmlTextReaderRead(reader);
		while (ret == 1) {
			_ri_process_config_node(reader, info);
			ret = xmlTextReaderRead(reader);
		}
		xmlFreeTextReader(reader);
		if (ret != 0) {
			_LOGE("%s : failed to parse\n", filename);
			ret = RPM_INSTALLER_ERR_INTERNAL;
		}
	} else {
		_LOGE("Unable to open %s\n", filename);
		ret = RPM_INSTALLER_ERR_INTERNAL;
	}
	return ret;
}

unsigned long  _ri_calculate_rpm_size( char* rpm_file)
{
	Header 	hdr = NULL;
	rpmts 	ts;
	rpmtd 	td;
	FD_t	fd;
	rpmRC	rc;
	rpmVSFlags vsflags = 0;
	unsigned long  size = 0;

	/* Initialize rpm */
	rc = rpmReadConfigFiles(NULL,NULL);
	if( rc != RPMRC_OK){
		_LOGE("\n failed to read RPM configuration files");
		return size;
	}
	/* Open the rpm file */
	fd = Fopen(rpm_file, "r.ufdio");
	if ((!fd) || Ferror(fd)){
		_LOGE("\n failed to open %s package file",rpm_file);
		if(fd)
			Fclose(fd);
		return size ;
	}

	hdr = headerNew();
	ts = rpmtsCreate();
	td = rpmtdNew();
	vsflags |= _RPMVSF_NODIGESTS;
	vsflags |= _RPMVSF_NOSIGNATURES;
	vsflags |= RPMVSF_NOHDRCHK;
	(void)rpmtsSetVSFlags(ts, vsflags);

	rc = rpmReadPackageFile(ts,fd,rpm_file,&hdr);
	if(rc != RPMRC_OK){
		_LOGE("\n Couldn't read rpm package file");
		size = 0;
		Fclose(fd);
		goto err;
	}
	headerGet(hdr,RPMTAG_SIZE,td,HEADERGET_MINMEM);
	size = rpmtdGetNumber(td);

	err:
	rpmtdFreeData(td);
	rpmtdFree(td);
	headerFree(hdr);
	rpmtsFree(ts);

	return size;
}

unsigned long  _ri_calculate_dir_size(const char *dirname)
{
	static unsigned long  total = 0;
	unsigned long  size = 0;
	DIR *dp = NULL;
	struct dirent *ep = NULL;
	char abs_filename[FILENAME_MAX] = { 0, };;
	dp = opendir(dirname);
	if (dp != NULL) {
		while ((ep = readdir(dp)) != NULL) {
			struct stat stFileInfo;

			snprintf(abs_filename, FILENAME_MAX, "%s/%s", dirname,
				 ep->d_name);

			if (stat(abs_filename, &stFileInfo) < 0)
				perror(abs_filename);
			else {
				/* If file is rpm then get the size from rpm header. */
				if(strstr(ep->d_name,".rpm")){
					size = _ri_calculate_rpm_size(abs_filename);
					if( size == 0){
						_LOGE("\n error in computing the rpm's size");
					}
					total += size;
				}else{
				total += (unsigned long)stFileInfo.st_size;
				}

				if (S_ISDIR(stFileInfo.st_mode)) {
					if (strcmp(ep->d_name, ".")
					    && strcmp(ep->d_name, "..")) {
						_ri_calculate_dir_size
						    (abs_filename);
					}
				} else {
					/*Do Nothing */
				}
			}
		}
		(void)closedir(dp);
	} else {
		_LOGE("\n error in opening directory ");
	}
	return (total/SIZE_KB);
}


/*
This function unzip the wgt package.
It read and validate the config.xml file.
It checks whether the free size avaiable to install this package.
*/

int _ri_wgt_package_extract(char *pkgid)
{
	if(pkgid == NULL)
		return RPM_INSTALLER_ERR_INTERNAL;

	int ret = RPM_INSTALLER_SUCCESS;
	const char *argv[5] = { RPM_UNZIP, pkgid, "-d", DIR_RPM_INSTALLER_APPLICATIONS_TEMP, NULL};
	char config_file_name[PATH_MAX] = {0};
	pkginfo *info = NULL;
	unsigned long free_mem = 0;
	unsigned long reqd_size = 0;
	mode_t mode = DIR_PERMS;

	/* 1. Delete the temp folder if already present*/
	if (!access(DIR_RPM_INSTALLER_APPLICATIONS_TEMP, F_OK)) {
		_ri_recursive_delete_dir(DIR_RPM_INSTALLER_APPLICATIONS_TEMP);
		(void)remove(DIR_RPM_INSTALLER_APPLICATIONS_TEMP);
	}

	/* 1.2 Create temp folder */
	ret = mkdir(DIR_RPM_INSTALLER_APPLICATIONS_TEMP, mode);
	if (ret != 0) {
		_LOGE("Temporary folder creation failed");
		return RPM_INSTALLER_ERR_INTERNAL;
	}
	/* 1.3 Unzip wgt to temp folder*/
	ret = _ri_xsystem(argv);
	if (ret != 0) {
		_LOGE("Unzip to Temporary folder failed");
		return  RPM_INSTALLER_ERR_INTERNAL;
	}

	/* Read the config.xml file and get the information*/
	snprintf(config_file_name,PATH_MAX,"%s/%s", DIR_RPM_INSTALLER_APPLICATIONS_TEMP,WGT_CONFIG);
	_LOGD("Config File is [%s]",config_file_name);
	if(access(config_file_name,F_OK)){
		/* Return if info config is absent */
		_LOGE("No Config File [%s] found\n", config_file_name);
		return  RPM_INSTALLER_ERR_NO_CONFIG;
	}
	_LOGD("Config File [%s] found\n", config_file_name);

	/*populate pkginfo */
	info = (pkginfo *)calloc(1, sizeof(pkginfo));
	if (info == NULL) {
		_LOGE("Memory allocation failed");
		return  RPM_INSTALLER_ERR_NOT_ENOUGH_MEMORY;
	}

	/* Parse config file and store the info in pkginfo struct */
	ret = _ri_stream_config_file(config_file_name,info);
	if(ret != RPM_INSTALLER_SUCCESS){
		_LOGE("Config file's parsing Failed");
		if(info){
			free(info);
			info = NULL;
		}
		return RPM_INSTALLER_ERR_INTERNAL;
	}

	/* 3. Validate the pkginfo*/
	if (strlen(info->package_name) == 0 || strlen(info->version) == 0) {
		_LOGE("Package name or version is not found in Config File");
		if (info) {
			free(info);
			info = NULL;
		}
		return RPM_INSTALLER_ERR_INVALID_CONFIG;
	}

	/* 4. Check the free memory  in RW partition*/
	ret = _ri_get_available_free_memory(RPM_INSTALLER_RW_INSTALL_PATH, &free_mem);
	if (ret<0) {
		_LOGE("Error in getting available free memory");
		if (info) {
			free(info);
			info = NULL;
		}
		return RPM_INSTALLER_ERR_INTERNAL;
	} else {
		/* Compare with size required by package*/
		reqd_size = _ri_calculate_dir_size(DIR_RPM_INSTALLER_APPLICATIONS_TEMP);
		if (reqd_size ==0) {
			_LOGE("Error in getting file size");
			if (info) {
				free(info);
				info = NULL;
			}
			return RPM_INSTALLER_ERR_INTERNAL;
		} else {
			if (reqd_size > free_mem) {
				_LOGE("Not enough memory");
				if (info) {
					free(info);
					info = NULL;
				}
				return  RPM_INSTALLER_ERR_NOT_ENOUGH_MEMORY;
			}
		}
	}

	_LOGD("Required size to install pkg is [%lu KB] and available memory is  [%lu KB]",reqd_size,free_mem);

	if (info) {
		free(info);
		info = NULL;
	}

	return ret;
}

int _verify_wgt_package_signature_files(void)
{

	char buff[PATH_MAX] = {0};
	int ret = RPM_INSTALLER_SUCCESS;
	char cwd[PATH_MAX]={0};
	char *temp = NULL;
	int visibility = 0;

	temp = getcwd(cwd, PATH_MAX);
	if ( ( temp == NULL) || (cwd[0] == '\0')) {
		_LOGE("@getcwd() failed.\n");
		ret = RPM_INSTALLER_ERR_INTERNAL;
		goto end;
	}

	ret = chdir(DIR_RPM_INSTALLER_APPLICATIONS_TEMP);
	if(ret != 0){
		_LOGE("Change directory failed!");
		goto end;
	}

	/*Verify the author-signature file */
	memset(buff, '\0', PATH_MAX);
	snprintf(buff, PATH_MAX, "%s/%s",DIR_RPM_INSTALLER_APPLICATIONS_TEMP,AUTHOR_SIGNATURE_XML);

	if (access(buff, F_OK) == 0) {
		_LOGD("auth-signature.xml found in %s\n", DIR_RPM_INSTALLER_APPLICATIONS_TEMP);
		ret = _ri_verify_sig_and_cert(buff, &visibility);
		if (ret) {
			_LOGE("Failed to verify [%s]\n", buff);
			ret = RPM_INSTALLER_ERR_SIG_INVALID;
			goto end;
		}else{
		_LOGD("Successfully verified [%s]\n", buff);
		}
	}

	/*Verify the signature2.xml file */
	memset(buff, '\0', PATH_MAX);
	snprintf(buff, PATH_MAX, "%s/%s",DIR_RPM_INSTALLER_APPLICATIONS_TEMP,SIGNATURE2_XML);

	if (access(buff, F_OK) == 0) {
		_LOGD("signature2.xml found in %s\n", DIR_RPM_INSTALLER_APPLICATIONS_TEMP);
		ret = _ri_verify_sig_and_cert(buff, &visibility);
		if (ret) {
			_LOGE("Failed to verify [%s]\n", buff);
			ret = RPM_INSTALLER_ERR_SIG_INVALID;
			goto end;
		}else{
		_LOGD("Successfully verified [%s]\n", buff);
		}
	}

	/*Verify the signature1.xml file*/
	memset(buff, '\0', PATH_MAX);
	snprintf(buff,PATH_MAX,"%s/%s", DIR_RPM_INSTALLER_APPLICATIONS_TEMP,SIGNATURE1_XML);

	if (access(buff, F_OK) == 0) {
		_LOGD("signature1.xml found in %s\n", DIR_RPM_INSTALLER_APPLICATIONS_TEMP);
		ret = _ri_verify_sig_and_cert(buff, &visibility);
		if (ret) {
			_LOGE("Failed to verify [%s]\n", buff);
			ret = RPM_INSTALLER_ERR_SIG_INVALID;
			goto end;
		}else{
		_LOGD("Successfully verified [%s]\n", buff);
		}
	}

	if(chdir(cwd)){
		_LOGE("chdir failed [%s]",strerror(errno));
		ret = RPM_INSTALLER_ERR_INTERNAL;
	}

	end:

		return ret;

}

char* _get_rpm_file_from_wgt_package(char* dirname)
{

        DIR *dp = NULL;
        struct dirent *ep = NULL;
        char abs_filename[FILENAME_MAX] = { 0, };
        dp = opendir(dirname);
	int found = 0;
        if (dp != NULL) {
                while ((ep = readdir(dp)) != NULL) {
                        snprintf(abs_filename, FILENAME_MAX, "%s/%s", dirname,
                                 ep->d_name);
                        if (strstr(abs_filename,".rpm")!=NULL){
				found = 1;
				break;
                        }
                }
                (void)closedir(dp);
        }

	if(found){
		_LOGD("rpm name is [%s]",abs_filename);
		return strdup(abs_filename);
	}

	return NULL;

}

/*
This function processes the modified wgt package .
*/
int _ri_process_wgt_package(char** pkgid)
{
	if(*pkgid == NULL)
		return RPM_INSTALLER_ERR_INTERNAL;

	unsigned long free_mem = 0;
	unsigned long file_size = 0;
	int ret = RPM_INSTALLER_SUCCESS;


	/* check memory available*/
	ret = _ri_get_available_free_memory(RPM_INSTALLER_RW_INSTALL_PATH, &free_mem);
	if (ret<0) {
		_LOGE("Error in getting available free memory");
		return RPM_INSTALLER_ERR_INTERNAL;
	} else {
		file_size = _ri_calculate_file_size(*pkgid);
		if (file_size <=0) {
			_LOGE("Error in getting file size");
			return RPM_INSTALLER_ERR_INTERNAL;
		} else {
			if (file_size > free_mem) {
				_LOGE("Not enough memory");
				return RPM_INSTALLER_ERR_NOT_ENOUGH_MEMORY;
			}
		}
	}

	_LOGD("Package file [%s] size is [%lu]KB and free size in RW directory is [%lu]KB",*pkgid,file_size,free_mem);

	/* unzip the wgt package */
	ret = _ri_wgt_package_extract(*pkgid);
	if(ret != RPM_INSTALLER_SUCCESS)
		return ret;

	_LOGD("wgt package is extracted to [%s]",DIR_RPM_INSTALLER_APPLICATIONS_TEMP);

	ret = _verify_wgt_package_signature_files();
	if(ret != RPM_INSTALLER_SUCCESS){
		_LOGE("signature verification [%d]",ret);
		return ret;
	}
	_LOGD("Verification of wgt package's signature files is done");

	if(*pkgid){
		free(*pkgid);
		*pkgid = NULL;
	}
	/* Change the data->pkgid to the unzipped package's rpm */
	*pkgid = _get_rpm_file_from_wgt_package(DIR_RPM_INSTALLER_APPLICATIONS_TEMP);
	if(*pkgid == NULL)
		return RPM_INSTALLER_ERR_INTERNAL;
	else
		_LOGD("rpm is [%s]",*pkgid);

	return RPM_INSTALLER_SUCCESS;
}
