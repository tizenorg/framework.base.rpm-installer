/*
 * rpm-installer
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

#ifndef __RPM_INSTALLER_TYPE_H_
#define __RPM_INSTALLER_TYPE_H_

#ifdef __cplusplus
extern "C" {
#endif				/* __cplusplus */

#define MAX_BUF_SIZE 						4096
#define BUF_SIZE								1024
#define TEMP_DIR								"/opt/usr/rpminstaller"
#define CPIO_SCRIPT							"/usr/bin/cpio_rpm_package.sh"
#define CPIO_SCRIPT_UPDATE_XML				"/usr/bin/cpio_rpm_package_update_xml.sh"
#define RPM_UPDATE_XML 						"/usr/bin/rpm_update_xml.sh"
#define MANIFEST_RW_DIRECTORY				"/opt/share/packages"
#define MANIFEST_RO_DIRECTORY				"/usr/share/packages"
#define USR_APPS								"/usr/apps"
#define OPT_USR_APPS							"/opt/usr/apps"
#define OPT_SHARE_PACKAGES 					"/opt/share/packages"
#define USR_SHARE_PACKAGES 					"/usr/share/packages"
#define PRE_CHECK_FOR_MANIFEST
#define INSTALL_SCRIPT						"/usr/bin/install_rpm_package.sh"
#define INSTALL_SCRIPT_WITH_DBPATH_RO		"/usr/bin/install_rpm_package_with_dbpath_ro.sh"
#define INSTALL_SCRIPT_WITH_DBPATH_RW		"/usr/bin/install_rpm_package_with_dbpath_rw.sh"
#define UNINSTALL_SCRIPT					"/usr/bin/uninstall_rpm_package.sh"
#define UPGRADE_SCRIPT						"/usr/bin/upgrade_rpm_package.sh"
#define UPGRADE_SCRIPT_WITH_DBPATH_RO		"/usr/bin/upgrade_rpm_package_with_dbpath_ro.sh"
#define UPGRADE_SCRIPT_WITH_DBPATH_RW		"/usr/bin/upgrade_rpm_package_with_dbpath_rw.sh"
#define TEMP_DBPATH 							"/opt/usr/rpmdb_tmp"
#define RPM2CPIO								"/usr/bin/rpm2cpio"
#define DEACTIVATION_PKGID_LIST 			"/opt/share/packages/.pkgmgr/rpm-installer/rpm_installer_deactvation_list.txt"
#define OPT_ZIP_FILE	 						"/usr/system/RestoreDir/opt.zip"
#define EFLWGT_TYPE_STR						"eflwgt"
#define TOKEN_PACKAGE_STR					"package="
#define TOKEN_PKGID_STR						"pkgid="
#define TOKEN_STATE_STR						"state="
#define TOKEN_PATH_STR						"path="
#define TOKEN_OPERATION_STR					"op="
#define TOKEN_REMOVE_STR					"removable="
#define SEPERATOR_END						':'
#define SEPERATOR_START						'"'
#define APP_OWNER_ID							5000
#define APP_GROUP_ID							5000
#define MAX_BUFF_LEN							4096
#define MAX_CERT_NUM							9
#define TERMINATE_RETRY_COUNT 				100
#define BIN_DIR_STR							"bin"
#define RES_DIR_STR							"res"
#define SHARED_RES_DIR_STR					"shared/res"
#define LIBAIL_PATH 							"/usr/lib/libail.so.0"
#define QUERY_PACKAGE						"/usr/bin/query_rpm_package.sh"
#define RPM_PKG_INFO							"/var/rpmpkg.info"
#define RPM									"/usr/etc/package-manager/backend/rpm"
#define SMACK_RULES_ALT_PATH					"/etc/smack/accesses2.d/"
#define CORETPK_XML							"tizen-manifest.xml"
#ifdef __cplusplus
}
#endif				/* __cplusplus */
#endif				/* __RPM_INSTALLER_TYPE_H_ */
