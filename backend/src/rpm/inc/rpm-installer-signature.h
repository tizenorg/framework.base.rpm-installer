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

#ifndef __RPM_INSTALLER_SIGNATURE_H_
#define __RPM_INSTALLER_SIGNATURE_H_

#ifdef __cplusplus
extern "C" {
#endif				/* __cplusplus */

typedef struct transform_x {
	const char *algorithm;
	struct transform_x *prev;
	struct transform_x *next;
} transform_x;

typedef struct digestmethod_x {
	const char *algorithm;
	struct digestmethod_x *prev;
	struct digestmethod_x *next;
} digestmethod_x;

typedef struct digestvalue_x {
	const char *text;
	struct digestvalue_x *prev;
	struct digestvalue_x *next;
} digestvalue_x;

typedef struct transforms_x {
	struct transform_x *transform;
	struct transforms_x *prev;
	struct transforms_x *next;
} transforms_x;

typedef struct x509certificate_x {
	const char *text;
	struct x509certificate_x *prev;
	struct x509certificate_x *next;
} x509certificate_x;

typedef struct reference_x {
	const char *uri;
	struct transforms_x *transforms;
	struct digestmethod_x *digestmethod;
	struct digestvalue_x *digestvalue;
	struct reference_x *prev;
	struct reference_x *next;
} reference_x;

typedef struct cannonicalizationmethod_x {
	const char *algorithm;
	struct cannonicalizationmethod_x *prev;
	struct cannonicalizationmethod_x *next;
} cannonicalizationmethod_x;

typedef struct signaturemethod_x {
	const char *algorithm;
	struct signaturemethod_x *prev;
	struct signaturemethod_x *next;
} signaturemethod_x;

typedef struct x509data_x {
	x509certificate_x *x509certificate;
	struct x509data_x *prev;
	struct x509data_x *next;
} x509data_x;

typedef struct signedinfo_x {
	struct cannonicalizationmethod_x *cannonicalizationmethod;
	struct signaturemethod_x *signaturemethod;
	struct reference_x *reference;
	struct signedinfo_x *prev;
	struct signedinfo_x *next;
} signedinfo_x;

typedef struct signaturevalue_x {
	const char *text;
	struct signaturevalue_x *prev;
	struct signaturevalue_x *next;
} signaturevalue_x;

typedef struct keyinfo_x {
	struct x509data_x *x509data;
	struct keyinfo_x *prev;
	struct keyinfo_x *next;
} keyinfo_x;

/*This will be parsed later when requirement arises*/
typedef struct object_x {
	const char *id;
	struct object_x *prev;
	struct object_x *next;
} object_x;

typedef struct signature_x {	/*signature xml*/
	const char *id;		/* distributor or author sign*/
	const char *xmlns;	/* namespace*/
	struct signedinfo_x *signedinfo;	/*signature data*/
	struct signaturevalue_x *signaturevalue;	/* signature value*/
	struct keyinfo_x *keyinfo;	/*cert info*/
	struct object_x *object;	/*other parameters in object tag*/
} signature_x;


signature_x *_ri_process_signature_xml(const char *signature_file);
void _ri_free_signature_xml(signature_x *sigx);

#ifdef __cplusplus
}
#endif				/* __cplusplus */
#endif				/* __RPM_INSTALLER_SIGNATURE_H_ */
