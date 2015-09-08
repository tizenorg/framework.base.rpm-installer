/*
 * coretpk-installer
 *
 * Copyright (c) 2000 - 2011 Samsung Electronics Co., Ltd. All rights reserved.
 *
 * Contact:
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

#ifndef __CORETPK_INSTALLER_TYPE_H_
#define __CORETPK_INSTALLER_TYPE_H_

#include "rpm-installer-util.h"

#ifdef __cplusplus
extern "C" {
#endif				/* __cplusplus */

#define CORETPK_INSTALL									"coretpk-install"
#define CORETPK_UNINSTALL								"coretpk-uninstall"
#define CORETPK_DIRECTORY_INSTALL				"coretpk-directory-install"
#define CORETPK_MOVE										"coretpk-move"
#define CORETPK_REINSTALL								"coretpk-reinstall"
#define MAX_BUF_SIZE							4096
#define BUF_SIZE								1024
#define TEMP_DIR								"/opt/usr/rpminstaller"
#define TEMP_XML_DIR							"/tmp/rpminstaller"
#define CORETPK_XML							"tizen-manifest.xml"
#define USR_APPS								"/usr/apps"
#define OPT_USR_APPS							"/opt/usr/apps"
#define USR_SHARE_PACKAGES 					"/usr/share/packages"
#define OPT_SHARE_PACKAGES					"/opt/share/packages"
#define CORETPK_CATEGORY_CONVERTER		"/usr/bin/coretpk_category_converter.sh"

#define SIGNATURE1_XML						"signature1.xml"
#define AUTHOR_SIGNATURE_XML				"author-signature.xml"
#define APP_OWNER_ID							5000
#define APP_GROUP_ID							5000
#define PERM_BASE							(S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH) // 0644
#define PERM_EXECUTE							(S_IXUSR | S_IXGRP | S_IXOTH)
#define PERM_WRITE							(S_IWUSR | S_IWGRP | S_IWOTH)
#define CORETPK_CONFIG_PATH					"/usr/etc/coretpk-installer-config.ini"
#define INCLUDE_ABSOLUTE_PATH				44
#define OPT_STORAGE_SDCARD					"/opt/storage/sdcard/"
#define OPT_STORAGE_SDCARD_APP_ROOT		"/opt/storage/sdcard/apps"
#define INI_VALUE_MAKE_EXT_DIRECTORY		"make-ext-directory"
#define INI_VALUE_SIGNATURE					"signature"
#define INI_VALUE_AUTHOR_SIGNATURE			"author-signature"
#define RDS_DELTA_FILE						".rds_delta"
#define RDS_DELTA_ADD						"#add"
#define RDS_DELTA_DELETE					"#delete"
#define RDS_DELTA_MODIFY					"#modify"

enum rds_state_type {
	RDS_STATE_NONE,
	RDS_STATE_DELETE,
	RDS_STATE_ADD,
	RDS_STATE_MODIFY,
};

enum request_type {
	REQUEST_TYPE_INSTALL,
	REQUEST_TYPE_UNINSTALL,
	REQUEST_TYPE_UPGRADE,
};

#define _LOGL(message, error)	 \
	char exception[BUF_SIZE] = {'\0'}; \
	strerror_r(error, exception, BUF_SIZE); \
	_LOGP("@%s failed[%s]. func:[%s] line:[%d]\n", message, exception, __FUNCTION__, __LINE__)

#define ret_if(expr) do { \
	if (expr) { \
		_LOGE("(%s) ", #expr); \
		return; \
	} \
} while (0)

#define retm_if(expr, fmt, arg...) do { \
	 if (expr) { \
		 _LOGE("(%s) "fmt, #expr, ##arg); \
		 return; \
	 } \
 } while (0)

#define retv_if(expr, val) do { \
		if (expr) { \
			_LOGE("(%s) ", #expr); \
			return (val); \
		} \
	} while (0)

#define retvm_if(expr, val, fmt, arg...) do { \
	if (expr) { \
		_LOGE("(%s) "fmt, #expr, ##arg); \
		return (val); \
	} \
} while (0)

#define tryvm_if(expr, val, fmt, arg...) do { \
	if (expr) { \
		_LOGE("(%s) "fmt, #expr, ##arg); \
		val; \
		goto catch; \
	} \
} while (0)

#ifdef __cplusplus
}
#endif				/* __cplusplus */
#endif				/* __CORETPK_INSTALLER_TYPE_H_ */
