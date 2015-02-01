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


#include <package-manager-plugin.h>
#include <unistd.h>
#include <vconf.h>
#include <stdlib.h>
#include <sys/types.h>
#include <dirent.h>

#ifdef __cplusplus
extern "C" {
#endif				/* __cplusplus */

#define API __attribute__ ((visibility("default")))
#define DEBUG_ERR	0x0001
#define DEBUG_INFO	0x0002
#define DEBUG_RESULT	0x0004
#define LIBRPM_LOG	1
#define LIBRPM_SUCCESS	0
#define LIBRPM_ERROR	-1

#define BLOCK_SIZE      4096 /*in bytes*/
#define LIKELY(expr) __builtin_expect((expr), 1)
#define UNLIKELY(expr) __builtin_expect((expr), 0)

int _librpm_get_package_header_info(const char *pkg_path,
			package_manager_pkg_detail_info_t *pkg_detail_info);
int _librpm_get_installed_package_info(const char *pkgid,
			package_manager_pkg_detail_info_t *pkg_detail_info);
int _librpm_app_is_installed(const char *pkgid);
long long _librpm_calculate_dir_size(const char *dirname);

#ifdef __cplusplus
}
#endif			/* __cplusplus */
