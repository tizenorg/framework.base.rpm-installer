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

#define MAX_BUF_SIZE 				4096
#define BUF_SIZE					1024
#define TEMP_DIR					"/opt/usr/rpminstaller"
#define CPIO_SCRIPT					"/usr/bin/cpio_rpm_package.sh"
#define CPIO_SCRIPT_UPDATE_XML		"/usr/bin/cpio_rpm_package_update_xml.sh"
#define MANIFEST_RW_DIRECTORY 		"/opt/share/packages"
#define MANIFEST_RO_DIRECTORY 		"/usr/share/packages"

#ifdef __cplusplus
}
#endif				/* __cplusplus */
#endif				/* __RPM_INSTALLER_TYPE_H_ */
