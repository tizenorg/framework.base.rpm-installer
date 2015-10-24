/*
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

#ifndef _INSTALLER_UTIL_H_
#define _INSTALLER_UTIL_H_

#ifdef __cplusplus
extern "C" {
#endif

#include <string.h>
#include <stdarg.h>
#include <sys/wait.h>
#include <sys/types.h>
#include <unistd.h>
#include <libgen.h>
#include <wait.h>
#include <stdio.h>
#include <dirent.h>
#include <glib.h>
#include <libxml/parser.h>
#include <libxml/xmlreader.h>
#include <libxml/xmlschemas.h>
#include <pkgmgr-info.h>


int _installer_util_copy_file(const char *src_path, const char *dest_path);
int _installer_util_copy_dir(const char *src_dir, const char *dest_dir);
int _installer_util_delete_dir(const char *dir_path);
void _installer_util_free_pkg_info(pkginfo *pkg_info);
int _installer_util_get_configuration_value(const char *value);
char *_installer_util_get_str(const char *str, const char *pKey);
int _installer_util_extract_version(const char* version, int* major, int* minor, int* macro);
int _installer_util_compare_version(const char* old_version, const char* new_version);
int _installer_util_mkpath(const char *s, mode_t mode);

#ifdef _APPFW_FEATURE_DELTA_UPDATE
int _installer_util_create_dir(const char *dir_path, mode_t mode);
void _installer_util_free_delta_info(delta_info *pkg_info);
#endif

void _ri_error_no_to_string(int errnumber, char **errstr);
int _ri_recursive_delete_dir(char *dirname);
int _ri_string_to_error_no(const char *errstr);
int _ri_get_available_free_memory(const char *opt_path, unsigned long *free_mem);
unsigned long  _ri_calculate_file_size(const char *filename);

int _ri_xsystem(const char *argv[]);

int  _get_package_name_from_xml(char* manifest,char** pkgname);
int _child_element(xmlTextReaderPtr reader, int depth);
int _ri_verify_sig_and_cert(const char *sigfile, int *visibility, bool need_verify, char *ca_path);
char* _manifest_to_package(const char* manifest);
unsigned long  _ri_calculate_rpm_size( char* rpm_file);
int _ri_get_attribute(xmlTextReaderPtr reader,char *attribute, const char **xml_attribute);
int _ri_next_child_element(xmlTextReaderPtr reader, int depth);
int _ri_get_visibility_from_signature_file(const char *sigfile, int *visibility, bool save_ca_path);

#ifdef __cplusplus
}
#endif
#endif	/* _INSTALLER_UTIL_H_ */
