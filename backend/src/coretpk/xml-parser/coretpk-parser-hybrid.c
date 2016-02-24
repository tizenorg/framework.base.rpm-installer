/*
 * coretpk-installer
 *
 * Copyright (c) 2000 - 2011 Samsung Electronics Co., Ltd. All rights reserved.
 *
 * Contact: Jayoun Lee <airjany@samsung.com>, junsuk.oh <junsuk77.oh@samsung.com>,
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

#define _GNU_SOURCE

#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>
#include <pkgmgr-info.h>
#include <pkgmgr_parser.h>
#include <privilege-control.h>
#include <cert-service.h>

#include "coretpk-installer-internal.h"
#include "installer-type.h"
#include "installer-util.h"
#include "rpm-installer.h"

#define LOG_PRINT_LINE_MAX 20
#define LOG_BUFFER_COUNT_MAX 4096

static int __coretpk_parser_hybrid_to_file(const char *web_xml, const char *core_xml);
static int __coretpk_parser_hybrid_merge_privilege(char* merged_buf, char* core_buf, int* filesize);
static int __coretpk_parser_hybrid_merge_ui_application(char* merged_buf, char* core_buf, int* filesize);
static int __coretpk_parser_hybrid_merge_service_application(char* merged_buf, char* core_buf, int* filesize);
static int __coretpk_parser_hybrid_merge_widget_tag(char* merged_buf, char* core_buf, int* filesize);
static int __coretpk_parser_hybrid_merge_tag(char* merged_buf, char* core_buf, int* filesize, const char* start_tag, const char* end_tag);

static int __coretpk_parser_hybrid_get_part(const char* start_point, const char* start_tag, const char* end_tag, char** buf, int* length, char** next);
static int __coretpk_parser_hybrid_merge_to(const char* merged_buf, int* filesize, const char* tag, const char* buf, int length);
static int __coretpk_parser_hybrid_dump_log_data(char *data, int length);

static int __coretpk_parser_hybrid_convert_api_visibility(int privilegeLevel, int *apiVisibility);
static int _coretpk_installer_hybrid_convert_manifest(const char *manifest, const char *pkgid, int apiVisibility);

int __coretpk_parser_hybrid_to_file(const char *web_xml, const char *core_xml)
{
	int ret = RPM_INSTALLER_ERR_WRONG_PARAM;
	int res = 0;
	FILE* web_xml_file = NULL;
	FILE* core_xml_file = NULL;
	struct stat web_fileinfo;
	struct stat core_fileinfo;
	int web_xml_filesize = 0;
	int core_xml_filesize = 0;
	int merged_size = 0;
	char* merged_buf = NULL;
	char* core_buf = NULL;
	int read_bytes = 0;
	char* manifest_tag = NULL;
	int filesize = 0;
	FILE* result_xml_file = NULL;
	int result_write_bytes = 0;

	res = stat(web_xml, &web_fileinfo);
	tryvm_if(res < 0, ret = RPM_INSTALLER_ERR_WRONG_PARAM, "fstat() failed, web_xml=[%s]\n", web_xml);

	res = stat(core_xml, &core_fileinfo);
	tryvm_if(res < 0, ret = RPM_INSTALLER_ERR_WRONG_PARAM, "fstat() failed, core_xml=[%s]\n", core_xml);

	web_xml_filesize = web_fileinfo.st_size;
	core_xml_filesize = core_fileinfo.st_size;
	merged_size = web_xml_filesize + core_xml_filesize;

	web_xml_file = fopen(web_xml, "r");
	tryvm_if(web_xml_file == NULL, ret = RPM_INSTALLER_ERR_WRONG_PARAM, "fopen() failed, web_xml=[%s]\n", web_xml);

	merged_buf = (char*)calloc(1, merged_size + 1);
	tryvm_if(merged_buf == NULL, ret = RPM_INSTALLER_ERR_WRONG_PARAM, "merged_buf is NULL");

	read_bytes = fread(merged_buf, 1, web_xml_filesize, web_xml_file);
	tryvm_if(read_bytes <= 0, ret = RPM_INSTALLER_ERR_WRONG_PARAM, "fread() failed, web_xml=[%s]", web_xml);

	core_xml_file = fopen(core_xml, "r");
	tryvm_if(core_xml_file == NULL, ret = RPM_INSTALLER_ERR_WRONG_PARAM, "fopen() failed, core_xml=[%s]\n", core_xml);

	core_buf = (char*)calloc(1, core_xml_filesize + 1);
	tryvm_if(core_buf == NULL, ret = RPM_INSTALLER_ERR_WRONG_PARAM, "core_buf is NULL");

	read_bytes = fread(core_buf, 1, core_xml_filesize, core_xml_file);
	tryvm_if(read_bytes <= 0, ret = RPM_INSTALLER_ERR_WRONG_PARAM, "fread() failed, core_xml=[%s]", core_xml);
	core_buf[read_bytes] = '\0';

	manifest_tag = strcasestr(merged_buf, "</manifest>");
	tryvm_if(manifest_tag == NULL, ret = RPM_INSTALLER_ERR_WRONG_PARAM, "manifest_tag is NULL");

	filesize = web_xml_filesize;

	__coretpk_parser_hybrid_merge_privilege(merged_buf, core_buf, &filesize);
	__coretpk_parser_hybrid_merge_ui_application(merged_buf, core_buf, &filesize);
	__coretpk_parser_hybrid_merge_service_application(merged_buf, core_buf, &filesize);
	__coretpk_parser_hybrid_merge_widget_tag(merged_buf, core_buf, &filesize);

	result_xml_file = fopen(web_xml, "w");
	tryvm_if(result_xml_file == NULL, ret = RPM_INSTALLER_ERR_WRONG_PARAM, "fopen() failed, result_xml=[%s]", web_xml);

	result_write_bytes = fwrite(merged_buf, 1, filesize, result_xml_file);
	tryvm_if(result_write_bytes != filesize, ret = RPM_INSTALLER_ERR_WRONG_PARAM, "fwrite() failed, result_write_bytes=[%d]", result_write_bytes);


    ret = RPM_INSTALLER_SUCCESS;

catch:

	if(result_xml_file != NULL){
		fclose(result_xml_file);
		result_xml_file = NULL;
	}
	if(core_xml_file != NULL){
		fclose(core_xml_file);
		core_xml_file = NULL;
	}
	if(web_xml_file != NULL){
		fclose(web_xml_file);
		web_xml_file = NULL;
	}
	FREE_AND_NULL(merged_buf);
	FREE_AND_NULL(core_buf);
	return ret;
}

int __coretpk_parser_hybrid_merge_privilege(char* merged_buf, char* core_buf, int* filesize)
{
	int ret = RPM_INSTALLER_ERR_WRONG_PARAM;
	char* merged_privilege_detected = NULL;
	char* merged_point = NULL;
	char* core_privilege_start = NULL;
	char* core_privilege_end = NULL;
	int privilege_len = 0;
	int core_buf_len = 0;
	char* selected_privilege_buf = NULL;

	retvm_if(merged_buf == NULL, RPM_INSTALLER_ERR_WRONG_PARAM, "merged_buf is NULL");
	retvm_if(core_buf == NULL, RPM_INSTALLER_ERR_WRONG_PARAM, "core_buf is NULL");
	retvm_if(filesize <= 0, RPM_INSTALLER_ERR_WRONG_PARAM, "filesize is NULL");

	if (strcasestr(core_buf, "</privileges>") == NULL) {
		return RPM_INSTALLER_SUCCESS;
    }

	merged_privilege_detected = strcasestr(merged_buf, "</privileges>");
	core_buf_len = strlen(core_buf);

	selected_privilege_buf = (char*)calloc(1, core_buf_len + 1);
	tryvm_if(selected_privilege_buf == NULL, ret = RPM_INSTALLER_ERR_WRONG_PARAM, "selected_privilege_buf is NULL");

	if (merged_privilege_detected == NULL) {
		_LOGD("no privileges are detected in web xml");

		core_privilege_start = strcasestr(core_buf, "<privileges>");
		core_privilege_end = strcasestr(core_buf, "</privileges>");

		privilege_len = core_privilege_end - core_privilege_start + strlen("</privileges>");
		merged_point = strcasestr(merged_buf, "<ui-application");

		_LOGD("inserted privileges of core xml");
		__coretpk_parser_hybrid_dump_log_data(core_privilege_start, privilege_len);
	} else {
		char* privilege_buf = NULL;
		char* each_privilege_start = NULL;
		char* each_privilege_end = NULL;
		int each_privilege_len = 0;
		char each_privilege_buf[512] = {0};

		_LOGD("privileges are detected in web xml");

		core_privilege_start = strcasestr(core_buf, "<privilege>");
		core_privilege_end = strcasestr(core_buf, "</privileges>");

		privilege_len = core_privilege_end - core_privilege_start;
		merged_point = strcasestr(merged_buf, "</privileges>");

		_LOGD("original privilege of core xml");
		__coretpk_parser_hybrid_dump_log_data(core_privilege_start, privilege_len);

		privilege_buf = (char*)calloc(1, privilege_len + 1);
		tryvm_if(privilege_buf == NULL, ret = RPM_INSTALLER_ERR_WRONG_PARAM, "privilege_buf is NULL");
		strncpy(privilege_buf, core_privilege_start, privilege_len);

		each_privilege_start = privilege_buf;

		while (each_privilege_start && (each_privilege_start < privilege_buf + privilege_len))
		{
			each_privilege_end = strcasestr(each_privilege_start, "</privilege>");
			each_privilege_len = each_privilege_end - each_privilege_start + strlen("</privilege>");
			if ((each_privilege_end > 0) && each_privilege_len > 0)
			{
				memset(each_privilege_buf, 0, sizeof(each_privilege_buf));
				memcpy(each_privilege_buf, each_privilege_start, each_privilege_len);
				_LOGD("[%s]", each_privilege_buf);

			if (strcasestr(merged_buf, each_privilege_buf) == 0)
			{
				strncat(selected_privilege_buf, each_privilege_buf, core_buf_len);
			}
			else
			{
				_LOGD("this privilege is discarded, [%s]", each_privilege_buf);
			}
			}
			else
			{
				_LOGD("end of privileges merging");
				break;
			}

				each_privilege_start = strcasestr(each_privilege_end, "<privilege>");
		}

		core_privilege_start = selected_privilege_buf;
		privilege_len = strlen(core_privilege_start);

		_LOGD("filtered privileges of core xml");
		__coretpk_parser_hybrid_dump_log_data(core_privilege_start, privilege_len);
		FREE_AND_NULL(privilege_buf);
	}

	if ((merged_point > 0) && (core_privilege_start > 0) && (privilege_len > 0))
	{
		int last_part_len = 0;
		char* last_part_buf = NULL;

		last_part_len = *filesize - (merged_point - merged_buf);
		last_part_buf = (char*)calloc(1, *filesize + 1);
		tryvm_if(last_part_buf == NULL, ret = RPM_INSTALLER_ERR_INTERNAL,"@calloc failed!!");

		if (last_part_len > 0)
		{
			memcpy(last_part_buf, merged_point, last_part_len);

			_LOGD("last part of merged xml for backup");
			__coretpk_parser_hybrid_dump_log_data(last_part_buf, last_part_len);

			memcpy(merged_point, core_privilege_start, privilege_len);

			memcpy(merged_point + privilege_len, last_part_buf, last_part_len);
			*filesize += privilege_len;
		}
		FREE_AND_NULL(last_part_buf);

	}
	ret = RPM_INSTALLER_SUCCESS;

catch:
	FREE_AND_NULL(selected_privilege_buf);
	return ret;
}

int __coretpk_parser_hybrid_merge_ui_application(char* merged_buf, char* core_buf, int* filesize)
{
    retvm_if(merged_buf == NULL, RPM_INSTALLER_ERR_WRONG_PARAM, "merged_buf is NULL");
    retvm_if(core_buf == NULL, RPM_INSTALLER_ERR_WRONG_PARAM, "core_buf is NULL");
    retvm_if(filesize <= 0, RPM_INSTALLER_ERR_WRONG_PARAM, "filesize is NULL");

    if (strcasestr(core_buf, "</ui-application>") == NULL)
    {
        _LOGD("<ui-application> is NOT detected in core xml");
        return RPM_INSTALLER_SUCCESS;
    }

    _LOGD("<ui-application> is detected in core xml");
    __coretpk_parser_hybrid_merge_tag(merged_buf, core_buf, filesize, "<ui-application", "</ui-application>");

    return RPM_INSTALLER_SUCCESS;
}

int __coretpk_parser_hybrid_merge_service_application(char* merged_buf, char* core_buf, int* filesize)
{
    retvm_if(merged_buf == NULL, RPM_INSTALLER_ERR_WRONG_PARAM, "merged_buf is NULL");
    retvm_if(core_buf == NULL, RPM_INSTALLER_ERR_WRONG_PARAM, "core_buf is NULL");
    retvm_if(filesize <= 0, RPM_INSTALLER_ERR_WRONG_PARAM, "filesize is NULL");

    if (strcasestr(core_buf, "</service-application>") == NULL)
    {
        _LOGD("<service-application> is NOT detected in core xml");
        return RPM_INSTALLER_SUCCESS;
    }

    _LOGD("<service-application> is detected in core xml");
    __coretpk_parser_hybrid_merge_tag(merged_buf, core_buf, filesize, "<service-application", "</service-application>");

    return RPM_INSTALLER_SUCCESS;
}

int __coretpk_parser_hybrid_merge_widget_tag(char* merged_buf, char* core_buf, int* filesize)
{
    retvm_if(merged_buf == NULL, RPM_INSTALLER_ERR_WRONG_PARAM, "merged_buf is NULL");
    retvm_if(core_buf == NULL, RPM_INSTALLER_ERR_WRONG_PARAM, "core_buf is NULL");
    retvm_if(filesize <= 0, RPM_INSTALLER_ERR_WRONG_PARAM, "filesize is NULL");

    if (strcasestr(core_buf, "</widget>") == NULL)
    {
        _LOGD("<widget> is NOT detected in core xml");
        return RPM_INSTALLER_SUCCESS;
    }

    _LOGD("<widget> is detected in core xml");
    __coretpk_parser_hybrid_merge_tag(merged_buf, core_buf, filesize, "<widget", "</widget>");

    return RPM_INSTALLER_SUCCESS;

}

int __coretpk_parser_hybrid_merge_tag(char* merged_buf, char* core_buf, int* filesize, const char* start_tag, const char* end_tag)
{
    do
    {
        char* buf = NULL;
        int length = 0;
        char* next = NULL;

        __coretpk_parser_hybrid_get_part(core_buf, start_tag, end_tag, &buf, &length, &next);
        if (length > 0)
        {
		__coretpk_parser_hybrid_merge_to(merged_buf, filesize, "</manifest>", buf, length);
        }

        if (buf)
			free(buf);

        core_buf = next;
    }
    while (core_buf > 0);

    return RPM_INSTALLER_SUCCESS;
}

int __coretpk_parser_hybrid_get_part(const char* start_point, const char* start_tag, const char* end_tag, char** buf, int* length, char** next)
{
	int ret = RPM_INSTALLER_ERR_WRONG_PARAM;
	const char* start_buf_point = NULL;
	const char* end_buf_point = NULL;
	int len = 0;

	tryvm_if(start_point == NULL, ret = RPM_INSTALLER_ERR_WRONG_PARAM, "start_point is NULL");
	tryvm_if(start_tag == NULL, ret = RPM_INSTALLER_ERR_WRONG_PARAM, "start_tag is NULL");
	tryvm_if(end_tag == NULL, ret = RPM_INSTALLER_ERR_WRONG_PARAM, "end_tag is NULL");
	tryvm_if(buf == NULL, ret = RPM_INSTALLER_ERR_WRONG_PARAM, "buf is NULL");
	tryvm_if(length == NULL, ret = RPM_INSTALLER_ERR_WRONG_PARAM, "length is NULL");
	tryvm_if(next == NULL, ret = RPM_INSTALLER_ERR_WRONG_PARAM, "next is NULL");

	start_buf_point = strcasestr(start_point, start_tag);
	tryvm_if(start_buf_point == NULL, ret = RPM_INSTALLER_ERR_WRONG_PARAM, "start_buf_point is NULL");

	end_buf_point = strcasestr(start_buf_point, end_tag);
	tryvm_if(end_buf_point == NULL, ret = RPM_INSTALLER_ERR_WRONG_PARAM, "end_buf_point is NULL");

	len = end_buf_point - start_buf_point + strlen(end_tag);
	tryvm_if(len <= 0, ret = RPM_INSTALLER_ERR_WRONG_PARAM, "len is invalid");

	*buf = (char*)calloc(1, len + 1);
	tryvm_if(*buf == NULL, ret = RPM_INSTALLER_ERR_WRONG_PARAM, "*buf is NULL");
	memcpy(*buf, start_buf_point, len);

	_LOGD("extracted part, len=[%d]", len);
	__coretpk_parser_hybrid_dump_log_data(*buf, len);

	*length = len;
	next = (char**)end_buf_point;

	ret = RPM_INSTALLER_SUCCESS;

catch:
    return ret;
}

int __coretpk_parser_hybrid_merge_to(const char* merged_buf, int* filesize, const char* tag, const char* buf, int length)
{
	int ret = RPM_INSTALLER_ERR_WRONG_PARAM;
	char* merged_point = NULL;
	char* last_part_buf = NULL;
	int last_part_length = 0;

    tryvm_if(merged_buf == NULL, ret = RPM_INSTALLER_ERR_WRONG_PARAM, "merged_buf is NULL");
    tryvm_if(*filesize <= 0, ret = RPM_INSTALLER_ERR_WRONG_PARAM, "filesize is invalid");
    tryvm_if(tag == NULL, ret = RPM_INSTALLER_ERR_WRONG_PARAM, "tag is NULL");
    tryvm_if(buf == NULL, ret = RPM_INSTALLER_ERR_WRONG_PARAM, "buf is NULL");
    tryvm_if(length <= 0, ret = RPM_INSTALLER_ERR_WRONG_PARAM, "length is invalid");

    merged_point = (char*)strcasestr(merged_buf, tag);
    tryvm_if(merged_point == NULL, ret = RPM_INSTALLER_ERR_WRONG_PARAM, "tag is not found, tag=[%s]", tag);

    last_part_length = *filesize - (merged_point - merged_buf);
    last_part_buf = (char*)calloc(1, *filesize + 1);
	tryvm_if(last_part_buf == NULL, ret = RPM_INSTALLER_ERR_INTERNAL, "@calloc failed!!");

	if (last_part_length > 0)
	{
		memcpy(last_part_buf, merged_point, last_part_length);

		_LOGD("last part of merged xml for backup");
		__coretpk_parser_hybrid_dump_log_data(last_part_buf, last_part_length);

		memcpy(merged_point, buf, length);
		memcpy(merged_point + length, last_part_buf, last_part_length);
		*filesize += length;
	}

    ret = RPM_INSTALLER_SUCCESS;

catch:
	FREE_AND_NULL(last_part_buf);
	return ret;
}

char __coretpk_parser_hybrid_log_change_hex_to_str(int hex)
{
	char ch = '0';

	const static char	hexValues[]	= {'0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'A', 'B', 'C', 'D', 'E', 'F', 0};


	if (hex >= 0 && hex <= 0x0F)
	{
		ch	= hexValues[hex];
	}
	else
	{
		_LOGD("LogChangeHexToStr: Error! [Hex Val: %d]\n", hex);
	}

	return ch;
}

int __coretpk_parser_hybrid_dump_log_data(char *pData, int dataLen)
{
	if(pData == NULL){
		_LOGE("@No data to dump");
		return 0;
	}
	const char	*szData	= (const char*)pData;
	char		ch = 0;
	int			i = 0, j = 0, idx = 0, idx2 = 0, high = 0, low = 0, temp = 0;

	char		buf[LOG_PRINT_LINE_MAX + 2]			= {0};
	char		buf2[(LOG_PRINT_LINE_MAX + 2) * 3]	= {0};
	char		buf_out[sizeof(buf) + sizeof(buf2) + 1]	= {0};


	if (dataLen > LOG_BUFFER_COUNT_MAX)
	{
		dataLen = LOG_BUFFER_COUNT_MAX;
	}

	_LOGD("------------------------------------------");

	while (i < (int)dataLen)
	{
		ch	= szData[i];

		/* make ascii table */
		if (ch >= 32 && ch <= 128)
		{
			buf[idx++]	= ch;
		}
		else
			buf[idx++]	= '.';

		// make binary table
		high = (ch & 0xf0)>>4;
		low = ch & 0x0f;

		buf2[idx2++]	= __coretpk_parser_hybrid_log_change_hex_to_str(high);
		buf2[idx2++]	= __coretpk_parser_hybrid_log_change_hex_to_str(low);
		buf2[idx2++]	= ' ';

		if (idx >= LOG_PRINT_LINE_MAX)
		{
			memcpy(buf_out, buf2, idx2);

			buf_out[idx2++]	= ' ';
			buf_out[idx2++]	= ' ';

			memcpy(buf_out + idx2, buf, idx);
			buf_out[idx2+idx]	= '\0';

			idx		= 0;
			idx2	= 0;

			_LOGD("%s\n", buf_out);
		}

		i++;
	}

	// last line
	if (idx > 0)
	{
		memcpy(buf_out, buf2, idx2);
		temp	= idx2;

		for (j = 0; j < (LOG_PRINT_LINE_MAX * 3) - temp; j++)
		{
			buf_out[idx2++]	= ' ';
		}

		buf_out[idx2++]	= ' ';
		buf_out[idx2++]	= ' ';

		memcpy(buf_out+idx2, buf, idx);
		buf_out[idx2+idx]	= '\0';

		_LOGD("%s\n", buf_out);
	}

	_LOGD("------------------------------------------");

	return 0;
}

int __coretpk_parser_hybrid_convert_api_visibility(int privilegeLevel, int *apiVisibility)
{
	if (privilegeLevel == PRIVILEGE_PLATFORM) {
		*apiVisibility = CERT_SVC_VISIBILITY_PLATFORM;
	} else if (privilegeLevel == PRIVILEGE_PARTNER) {
		*apiVisibility = CERT_SVC_VISIBILITY_PARTNER;
	} else {
		*apiVisibility = CERT_SVC_VISIBILITY_PUBLIC;
	}

	return RPM_INSTALLER_SUCCESS;
}

int _coretpk_installer_hybrid_convert_manifest(const char *manifest, const char *pkgid, int apiVisibility)
{
	retvm_if(manifest == NULL, RPM_INSTALLER_ERR_WRONG_PARAM, "manifest is NULL.");
	retvm_if(pkgid == NULL, RPM_INSTALLER_ERR_WRONG_PARAM, "pkgid is NULL.");

	int ret = 0;

	ret = mkdir(TEMP_DIR, DIRECTORY_PERMISSION_755);
	if (ret != 0) {
		char buf[BUF_SIZE] = { 0, };
		if ( strerror_r(errno, buf, sizeof(buf)) == 0) {
			_LOGE("mkdir(%s) failed. [%d][%s]", TEMP_DIR, errno, buf);
		}
		return RPM_INSTALLER_ERR_INTERNAL;
	}

	ret = _coretpk_parser_convert_manifest(manifest, pkgid, NULL, true, apiVisibility, NULL);
	if (ret != 0) {
		_LOGE("_coretpk_parser_convert_manifest(%s) failed. ret=[%d]", manifest, ret);
		return RPM_INSTALLER_ERR_INTERNAL;
	}

	return ret;
}

int _coretpk_installer_request_hybrid(int hybridOperation, const char *pPkgPath, int privilegeLevel)
{
	retvm_if(pPkgPath == NULL, RPM_INSTALLER_ERR_WRONG_PARAM, "pPkgPath is NULL.");

	int ret = 0;
	char wgt_xml[BUF_SIZE] = {'\0'};
	char core_xml[BUF_SIZE] = {'\0'};
	char converted_core_xml[BUF_SIZE] = {'\0'};
	char native_id[BUF_SIZE] = {0,};
	pkginfo *info = NULL;
	bool preload = false;
	int apiVisibility = 0;

	_LOGD("request_hybrid(%s) start.", pPkgPath);

	snprintf(core_xml, BUF_SIZE, "%s/%s", pPkgPath, CORETPK_XML);
	retvm_if(access(core_xml, F_OK) != 0, RPM_INSTALLER_ERR_WRONG_PARAM, "cannot access core xml. [%s]", core_xml);

	_LOGD("core xml = [%s]", core_xml);

	// get pkgid and version from xml file
	info = _coretpk_parser_get_manifest_info(core_xml);
	retvm_if(info == NULL, RPM_INSTALLER_ERR_WRONG_PARAM, "_coretpk_parser_get_manifest_info(%s) failed.", core_xml);

	_LOGD("pkgid = [%s], version = [%s]", info->package_name, info->version);

	if (strstr(pPkgPath, OPT_USR_APPS)) {
		snprintf(wgt_xml, BUF_SIZE, "%s/%s.xml", OPT_SHARE_PACKAGES, info->package_name);
	} else {
		snprintf(wgt_xml, BUF_SIZE, "%s/%s.xml", USR_SHARE_PACKAGES, info->package_name);
		preload = true;
	}

	_LOGD("wgt xml = [%s]", wgt_xml);

	__coretpk_parser_hybrid_convert_api_visibility(privilegeLevel, &apiVisibility);
	_LOGD("hybrid_convert_api_visibility(%d => %d) is done.", privilegeLevel, apiVisibility);

	// convert core xml
	ret = _coretpk_installer_hybrid_convert_manifest(core_xml, info->package_name, apiVisibility);
	if (ret != 0) {
		_LOGD("_coretpk_installer_hybrid_convert_manifest(%s, %s) failed.", core_xml, info->package_name);
		_installer_util_free_pkg_info(info);
		return -1;
	}

	snprintf(converted_core_xml, BUF_SIZE, "%s/%s", TEMP_DIR, CORETPK_XML);
	_LOGD("hybrid_convert_manifest(%s) is done.", converted_core_xml);

	// merge xml start
	ret = __coretpk_parser_hybrid_to_file(wgt_xml, converted_core_xml);
	//tryvm_if(ret != 0, ret = RPM_INSTALLER_ERR_WRONG_PARAM, "__coretpk_parser_hybrid_to_file(%s, %s) failed.", wgt_xml, converted_core_xml);
	_LOGD("hybrid_to_file(%s, %s) success", wgt_xml, converted_core_xml);

	// make directory
	ret = _coretpk_installer_make_directory((char*)info->package_name, preload);
	//tryvm_if(ret != 0, ret = RPM_INSTALLER_ERR_WRONG_PARAM, "_coretpk_installer_make_directory(%s) failed.", mfx->package);
	_LOGD("make_directory(%s) success", info->package_name);

	// apply smack to app dir
	ret = _coretpk_installer_apply_smack((char*)info->package_name, 1);
	//tryvm_if(ret != 0, ret = RPM_INSTALLER_ERR_WRONG_PARAM, "@Failed to apply_smack");
	_LOGD("apply_smack(%s, %d) success", info->package_name, ret);

	// apply smack by privilege
	strncat(native_id, (char*)info->package_name, BUF_SIZE - strlen(native_id) - 1);
	strncat(native_id, ".native", BUF_SIZE - strlen(native_id) - 1);

	ret = _ri_privilege_register_package(native_id);
	if (ret != 0) {
		_LOGE("_ri_privilege_register_package(%s) failed. ret = [%d].", native_id, ret);
	} else {
		_LOGD("_ri_privilege_register_package(%s) success.", native_id);
	}

	ret = _coretpk_installer_apply_privilege(native_id, pPkgPath, apiVisibility);
	if (ret != 0) {
		_LOGE("_coretpk_installer_apply_privilege(%s) failed. ret = [%d].", native_id, ret);
	} else {
		_LOGD("_coretpk_installer_apply_privilege(%s) success.", native_id);
	}

	ret = perm_app_add_friend((char*)info->package_name, native_id);
	if (ret != 0) {
		_LOGE("perm_app_add_friend(%s, %s, %d) failed", info->package_name, native_id, ret);
	} else {
		_LOGD("perm_app_add_friend(%s) success.", native_id);
	}

	_installer_util_free_pkg_info(info);

	const char *delete_argv[] = {"/bin/rm", "-rf", TEMP_DIR, NULL};
	ret = _ri_xsystem(delete_argv);
	if(ret != 0){
		_LOGE("delete the directory failed. [%s]",TEMP_DIR);
		//return RPM_INSTALLER_ERR_INTERNAL;
	}

	_LOGD("request_hybrid(%s) end.", pPkgPath);
	return 0;
}
