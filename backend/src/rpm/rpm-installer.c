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

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#define __USE_GNU
#include <sys/wait.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <wait.h>
#include <stdio.h>
#include <signal.h>
#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <dirent.h>
#include <ctype.h>		/* for isspace () */
#include <wctype.h>		/* for towlower() */
#include <vconf.h>
#include <cert-service.h>
#include <libxml/parser.h>
#include <libxml/tree.h>
#include <libxml/xmlmemory.h>
#include <sqlite3.h>
#include <db-util.h>
#include <sys/xattr.h>

#ifndef XMLSEC_NO_XSLT
#include <libxslt/xslt.h>
#include <libxslt/security.h>
#endif

#include <xmlsec/xmlsec.h>
#include <xmlsec/xmltree.h>
#include <xmlsec/xmldsig.h>
#include <xmlsec/crypto.h>
#include <xmlsec/errors.h>
#include <pkgmgr-info.h>
#include <pkgmgr_parser.h>
#include <package-manager.h>
#include <privilege-control.h>
#include <app_manager.h>
#include <app_manager_extension.h>
#include <aul.h>
#include <dlfcn.h>
#define APP2EXT_ENABLE
#ifdef APP2EXT_ENABLE
#include <app2ext_interface.h>
#endif

#include "rpm-installer-signature.h"
#include "rpm-installer.h"
#include "rpm-frontend.h"
#include "installer-type.h"
#include "installer-util.h"
#include "coretpk-installer-internal.h"
#include "pkgmgr_parser_resource.h"

extern char *gpkgname;
extern int sig_enable;
char *sig1_capath;
int sig1_visibility;

static void __rpm_process_line(char *line);
static void __rpm_perform_read(int fd);
static int __ri_xmlsec_verify_signature(const char *sigxmlfile, char *rootca);
static xmlSecKeysMngrPtr __ri_load_trusted_certs(char *files, int files_size);
static int __ri_verify_file(xmlSecKeysMngrPtr mngr, const char *sigxmlfile);
static int __ri_create_cert_chain(int sigtype, int sigsubtype, char *value);
static void __ri_free_cert_chain(void);
static char *__ri_get_cert_from_file(const char *file);
static int __privilege_func(const char *name, void *user_data);
static void __ri_xmlsec_debug_print(const char *file, int line, const char *func, const char *errorObject, const char *errorSubject, int reason, const char *msg);

int _ri_set_group_id(const char *pkgid, const char *groupid);

static void __str_trim(char *input)
{
	char *trim_str = input;

	if (input == NULL)
		return;

	while (*input != 0) {
		if (!isspace(*input)) {
			*trim_str = *input;
			trim_str++;
		}
		input++;
	}

	*trim_str = 0;
	return;
}

static int __ri_get_op_type(char *op_str)
{
	if (strcmp(op_str, "install") == 0)
		return INSTALL_REQ;
	else if (strcmp(op_str, "update") == 0)
		return UPGRADE_REQ;
	else if (strcmp(op_str, "uninstall") == 0)
		return UNINSTALL_REQ;
	else
		return -1;
}

int __get_version_from_xml(char* manifest, char** version){

	const char *val = NULL;
	const xmlChar *node;
	xmlTextReaderPtr reader;
	int ret = PMINFO_R_OK;

	if(manifest == NULL) {
		_LOGE("Input argument is NULL\n");
		return PMINFO_R_ERROR;
	}

	if(version == NULL) {
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
				ret = _ri_get_attribute(reader, "version", &val);
				if(ret != 0){
					_LOGE("@Error in getting attribute value");
					ret = PMINFO_R_ERROR;
					goto end;
				}

				if(val){
					*version = strdup(val);
					if(*version == NULL){
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

static int __ri_init_csc_xml(char *xml_path, char *removable)
{
	int ret = 0;
	char *csc_tags[3] = { NULL, };

	if (strcmp(removable, "true") == 0)
		csc_tags[0] = "removable=true";
	else
		csc_tags[0] = "removable=false";

	csc_tags[1] = "preload=true";
	csc_tags[2] = NULL;

	ret = pkgmgr_parser_parse_manifest_for_installation(xml_path, csc_tags);

	return ret;
}

static int __ri_create_cert_chain(int sigtype, int sigsubtype, char *value)
{
	if (value == NULL)
		return -1;
	/* _LOGD("Push in list [%d] [%d] [%s]", sigtype, sigsubtype, value); */
	switch (sigtype) {
	case SIG_AUTH:
		switch (sigsubtype) {
		case SIG_SIGNER:
			list[PMINFO_SET_AUTHOR_SIGNER_CERT].cert_type = PMINFO_SET_AUTHOR_SIGNER_CERT;
			list[PMINFO_SET_AUTHOR_SIGNER_CERT].cert_value = strdup(value);
			break;
		case SIG_INTERMEDIATE:
			list[PMINFO_SET_AUTHOR_INTERMEDIATE_CERT].cert_type = PMINFO_SET_AUTHOR_INTERMEDIATE_CERT;
			list[PMINFO_SET_AUTHOR_INTERMEDIATE_CERT].cert_value = strdup(value);
			break;
		case SIG_ROOT:
			/* value is already a mallocd pointer */
			list[PMINFO_SET_AUTHOR_ROOT_CERT].cert_type = PMINFO_SET_AUTHOR_ROOT_CERT;
			list[PMINFO_SET_AUTHOR_ROOT_CERT].cert_value = value;
			break;
		default:
			break;
		}
		break;
	case SIG_DIST1:
		switch (sigsubtype) {
		case SIG_SIGNER:
			list[PMINFO_SET_DISTRIBUTOR_SIGNER_CERT].cert_type = PMINFO_SET_DISTRIBUTOR_SIGNER_CERT;
			list[PMINFO_SET_DISTRIBUTOR_SIGNER_CERT].cert_value = strdup(value);
			break;
		case SIG_INTERMEDIATE:
			list[PMINFO_SET_DISTRIBUTOR_INTERMEDIATE_CERT].cert_type = PMINFO_SET_DISTRIBUTOR_INTERMEDIATE_CERT;
			list[PMINFO_SET_DISTRIBUTOR_INTERMEDIATE_CERT].cert_value = strdup(value);
			break;
		case SIG_ROOT:
			/* value is already a mallocd pointer */
			list[PMINFO_SET_DISTRIBUTOR_ROOT_CERT].cert_type = PMINFO_SET_DISTRIBUTOR_ROOT_CERT;
			list[PMINFO_SET_DISTRIBUTOR_ROOT_CERT].cert_value = value;
			break;
		default:
			break;
		}
		break;
	case SIG_DIST2:
		switch (sigsubtype) {
		case SIG_SIGNER:
			list[PMINFO_SET_DISTRIBUTOR2_SIGNER_CERT].cert_type = PMINFO_SET_DISTRIBUTOR2_SIGNER_CERT;
			list[PMINFO_SET_DISTRIBUTOR2_SIGNER_CERT].cert_value = strdup(value);
			break;
		case SIG_INTERMEDIATE:
			list[PMINFO_SET_DISTRIBUTOR2_INTERMEDIATE_CERT].cert_type = PMINFO_SET_DISTRIBUTOR2_INTERMEDIATE_CERT;
			list[PMINFO_SET_DISTRIBUTOR2_INTERMEDIATE_CERT].cert_value = strdup(value);
			break;
		case SIG_ROOT:
			/* value is already a mallocd pointer */
			list[PMINFO_SET_DISTRIBUTOR2_ROOT_CERT].cert_type = PMINFO_SET_DISTRIBUTOR2_ROOT_CERT;
			list[PMINFO_SET_DISTRIBUTOR2_ROOT_CERT].cert_value = value;
			break;
		default:
			break;
		}
		break;
	default:
		break;
	}

	return 0;
}

static void __ri_free_cert_chain()
{
	int i = 0;
	for (i = 0; i < MAX_CERT_NUM; i++) {
		if (list[i].cert_value) {
			free(list[i].cert_value);
			list[i].cert_value = NULL;
		}
	}
}

static void __ri_xmlsec_debug_print(const char *file, int line, const char *func, const char *errorObject, const char *errorSubject, int reason, const char *msg)
{
	_SLOGE("[%s(%d)] : [%s] : [%s] : [%d] : [%s]", func, line, errorObject, errorSubject, reason, msg);
}

static int __ri_verify_file(xmlSecKeysMngrPtr sec_key_mngr, const char *sigxmlfile)
{
	xmlDocPtr doc = NULL;
	xmlNodePtr node = NULL;
	xmlSecDSigCtxPtr dsigCtx = NULL;
	int res = -1;
	if (sigxmlfile == NULL)
		return -1;
	if (sec_key_mngr == NULL)
		return -1;

	/* set error callback to xmlsec1 */
	xmlSecErrorsSetCallback(__ri_xmlsec_debug_print);

	/* load file */
	doc = xmlParseFile(sigxmlfile);
	if ((doc == NULL) || (xmlDocGetRootElement(doc) == NULL)) {
		_LOGE("unable to parse file \"%s\"\n", sigxmlfile);
		goto err;
	}
	/* find start node */
	node = xmlSecFindNode(xmlDocGetRootElement(doc), xmlSecNodeSignature, xmlSecDSigNs);
	if (node == NULL) {
		_LOGE("start node not found in \"%s\"\n", sigxmlfile);
		goto err;
	}
	/* create signature context */
	dsigCtx = xmlSecDSigCtxCreate(sec_key_mngr);
	if (dsigCtx == NULL) {
		_LOGE("failed to create signature context\n");
		goto err;
	}
	/* Verify signature */
	if (xmlSecDSigCtxVerify(dsigCtx, node) < 0) {
		_LOGE("failed to verify signature\n");
		goto err;
	}
	/* print verification result to stdout */
	if (dsigCtx->status == xmlSecDSigStatusSucceeded) {
		res = 0;
		_LOGD("valid signature");
	} else {
		res = -1;
		_LOGD("invalid signature");
	}

err:
	/* cleanup */
	if (dsigCtx != NULL) {
		xmlSecDSigCtxDestroy(dsigCtx);
	}
	if (doc != NULL) {
		xmlFreeDoc(doc);
	}
	return res;
}

static xmlSecKeysMngrPtr __ri_load_trusted_certs(char *files, int files_size)
{
	xmlSecKeysMngrPtr sec_key_mngr;
	if (files == NULL)
		return NULL;

	if (files_size < 0)
		return NULL;

	sec_key_mngr = xmlSecKeysMngrCreate();
	if (sec_key_mngr == NULL) {
		_LOGE("failed to create keys manager.\n");
		return NULL;
	}

	if (xmlSecCryptoAppDefaultKeysMngrInit(sec_key_mngr) < 0) {
		_LOGE("failed to initialize keys manager.\n");
		xmlSecKeysMngrDestroy(sec_key_mngr);
		return NULL;
	}

	/* load trusted cert */
	if (xmlSecCryptoAppKeysMngrCertLoad(sec_key_mngr, files, xmlSecKeyDataFormatPem, xmlSecKeyDataTypeTrusted) < 0) {
		_LOGE("failed to load pem certificate from \"%s\"\n", files);
		xmlSecKeysMngrDestroy(sec_key_mngr);
		return NULL;
	}

	return sec_key_mngr;
}

static int __ri_xmlsec_verify_signature(const char *sigxmlfile, char *rootca)
{
	int ret = 0;
	xmlSecKeysMngrPtr sec_key_mngr = NULL;
	xmlLoadExtDtdDefaultValue = XML_DETECT_IDS | XML_COMPLETE_ATTRS;
	xmlSubstituteEntitiesDefault(1);

#ifndef XMLSEC_NO_XSLT
	xmlIndentTreeOutput = 1;
	xsltSecurityPrefsPtr sec_prefs = xsltNewSecurityPrefs();
	xsltSetSecurityPrefs(sec_prefs, XSLT_SECPREF_WRITE_FILE, xsltSecurityForbid);
	xsltSetSecurityPrefs(sec_prefs, XSLT_SECPREF_READ_FILE, xsltSecurityForbid);
	xsltSetSecurityPrefs(sec_prefs, XSLT_SECPREF_CREATE_DIRECTORY, xsltSecurityForbid);
	xsltSetSecurityPrefs(sec_prefs, XSLT_SECPREF_WRITE_NETWORK, xsltSecurityForbid);
	xsltSetSecurityPrefs(sec_prefs, XSLT_SECPREF_READ_NETWORK, xsltSecurityForbid);
	xsltSetDefaultSecurityPrefs(sec_prefs);
#endif

	ret = xmlSecInit();
	if (ret < 0) {
		_LOGE("xmlsec initialization failed [%d]\n", ret);
		goto end;
	}
	ret = xmlSecCheckVersion();
	if (ret != 1) {
		_LOGE("Incompatible version of loaded xmlsec library [%d]\n", ret);
		goto end;
	}
#ifdef XMLSEC_CRYPTO_DYNAMIC_LOADING
	ret = xmlSecCryptoDLLoadLibrary(BAD_CAST "openssl");
	if (ret < 0) {
		_LOGE("unable to load openssl library [%d]\n", ret);
		goto end;
	}
#endif

	ret = xmlSecCryptoAppInit(NULL);
	if (ret < 0) {
		_LOGE("crypto initialization failed [%d]\n", ret);
		goto end;
	}
	ret = xmlSecCryptoInit();
	if (ret < 0) {
		_LOGE("xmlsec-crypto initialization failed [%d]\n", ret);
		goto end;
	}

	sec_key_mngr = __ri_load_trusted_certs(rootca, 1);
	if (sec_key_mngr == NULL) {
		_LOGE("loading of trusted certs failed\n");
		ret = -1;
		goto end;
	}

	if (__ri_verify_file(sec_key_mngr, sigxmlfile) < 0) {
		ret = -1;
	}

end:
	if (sec_key_mngr)
		xmlSecKeysMngrDestroy(sec_key_mngr);

	xmlSecCryptoShutdown();
	xmlSecCryptoAppShutdown();
	xmlSecShutdown();
#ifndef XMLSEC_NO_XSLT
	xsltFreeSecurityPrefs(sec_prefs);
	xsltCleanupGlobals();
#endif

	return ret;
}

int _rpm_installer_get_group_id(const char *pkgid, char **result)
{
	int ret = 0;
	const char *value = NULL;
	char author_signature[BUF_SIZE] = { '\0' };
	char *e_rootcert = NULL;
	char *d_rootcert = NULL;
	gsize d_size = 0;
	unsigned char hashout[BUF_SIZE] = { '\0' };
	unsigned int h_size = 0;
	int e_size = 0;
	int length = 0;
	pkgmgrinfo_certinfo_h handle = NULL;

	snprintf(author_signature, BUF_SIZE, "%s/%s/%s", USR_APPS, pkgid, AUTHOR_SIGNATURE_XML);
	if (access(author_signature, F_OK) != 0) {
		_LOGE("[%s] isn't existed.", author_signature);
		return -1;
	}

	ret = pkgmgrinfo_pkginfo_create_certinfo(&handle);
	if (ret < 0) {
		_LOGE("pkgmgrinfo_pkginfo_create_certinfo(%s) failed.", pkgid);
		goto err;
	}

	ret = pkgmgrinfo_pkginfo_load_certinfo(pkgid, handle);
	if (ret < 0) {
		_LOGE("pkgmgrinfo_pkginfo_load_certinfo(%s) failed.", pkgid);
		goto err;
	}

	/* get root certificate */
	ret = pkgmgrinfo_pkginfo_get_cert_value(handle, PMINFO_AUTHOR_SIGNER_CERT, &value);
	if (ret < 0 || value == NULL) {
		_LOGE("pkgmgrinfo_pkginfo_get_cert_value(%s) failed. [%d]", pkgid, ret);
		goto err;
	}

	/* decode cert */
	d_rootcert = (char *)g_base64_decode(value, &d_size);
	if (d_rootcert == NULL) {
		_LOGE("g_base64_decode() failed.");
		goto err;
	}
	_LOGD("g_base64_decode() succeed, d_size=[%d]", d_size);

	/* hash */
	EVP_Digest(d_rootcert, d_size, hashout, &h_size, EVP_sha1(), NULL);
	if (h_size <= 0) {
		_LOGE("EVP_Digest(hash) failed.");
		goto err;
	}
	_LOGD("EVP_Digest() succeed, h_size=[%d]", h_size);

	/* encode cert */
	e_rootcert = g_base64_encode((const guchar *)hashout, h_size);
	if (e_rootcert == NULL) {
		_LOGE("g_base64_encode() failed.");
		goto err;
	}
	e_size = strlen(e_rootcert);
	_LOGD("g_base64_encode() succeed, e_size=[%d]", e_size);

	/* replace / to # */
	for (length = e_size; length >= 0; --length) {
		if (e_rootcert[length] == '/') {
			e_rootcert[length] = '#';
		}
	}

	*result = e_rootcert;

err:
	if (d_rootcert) {
		free(d_rootcert);
	}

	/* destroy cert */
	if (handle) {
		pkgmgrinfo_pkginfo_destroy_certinfo(handle);
	}

	return ret;
}

void __rpm_apply_smack(const char *pkgname, int flag, char *smack_label)
{
	int ret = -1;
	char dirpath[BUF_SIZE] = { '\0' };
	char *groupid = NULL;
	char *shared_data_label = NULL;
	char buf[BUF_SIZE] = { 0, };

	if (smack_label == NULL || strlen(smack_label) == 0) {
		smack_label = (char *)pkgname;
	}

	/* execute privilege APIs. The APIs should not fail */
	_ri_privilege_register_package(smack_label);

	/* home dir. Dont setup path but change smack access to "_" */
	snprintf(dirpath, BUF_SIZE, "%s/%s", USR_APPS, pkgname);
	if (__is_dir(dirpath))
		_ri_privilege_change_smack_label(dirpath, "_", 0);	/* 0 is SMACK_LABEL_ACCESS */
	memset(dirpath, '\0', BUF_SIZE);
	snprintf(dirpath, BUF_SIZE, "%s/%s", OPT_USR_APPS, pkgname);
	if (__is_dir(dirpath))
		_ri_privilege_change_smack_label(dirpath, "_", 0);	/* 0 is SMACK_LABEL_ACCESS */

	/* data */
	memset(dirpath, '\0', BUF_SIZE);
	snprintf(dirpath, BUF_SIZE, "%s/%s/data", OPT_USR_APPS, pkgname);
	if (!__is_dir(dirpath)) {
		ret = mkdir(dirpath, DIRECTORY_PERMISSION_755);
		if (ret < 0) {
			_LOGE("directory making is failed.\n");
		}
	}

	ret = chown(dirpath, APP_OWNER_ID, APP_GROUP_ID);
	if (ret != 0) {
		if( strerror_r(errno, buf, sizeof(buf)) == 0) {
			_LOGE("chown failed!! [%s]", buf);
		}
	}
	_ri_privilege_setup_path(smack_label, dirpath, APP_PATH_PRIVATE, smack_label);

	/* cache */
	memset(dirpath, '\0', BUF_SIZE);
	snprintf(dirpath, BUF_SIZE, "%s/%s/cache", OPT_USR_APPS, pkgname);
	if (!__is_dir(dirpath)) {
		ret = mkdir(dirpath, DIRECTORY_PERMISSION_755);
		if (ret < 0) {
			_LOGE("directory making is failed.\n");
		}
	}
	ret = chown(dirpath, APP_OWNER_ID, APP_GROUP_ID);
	if (ret != 0) {
		if( strerror_r(errno, buf, sizeof(buf)) == 0) {
			_LOGE("chown failed!! [%s]", buf);
		}
	}
	_ri_privilege_setup_path(smack_label, dirpath, APP_PATH_PRIVATE, smack_label);

	/* shared */
	memset(dirpath, '\0', BUF_SIZE);
	snprintf(dirpath, BUF_SIZE, "%s/%s/shared", USR_APPS, pkgname);
	if (__is_dir(dirpath))
		_ri_privilege_change_smack_label(dirpath, "_", 0);	/* 0 is SMACK_LABEL_ACCESS */
	memset(dirpath, '\0', BUF_SIZE);
	snprintf(dirpath, BUF_SIZE, "%s/%s/shared", OPT_USR_APPS, pkgname);
	if (!__is_dir(dirpath)) {
		ret = mkdir(dirpath, DIRECTORY_PERMISSION_755);
		if (ret < 0)
			_LOGE("directory making is failed.\n");
	}
	_ri_privilege_change_smack_label(dirpath, "_", 0);	/* 0 is SMACK_LABEL_ACCESS */
	memset(dirpath, '\0', BUF_SIZE);

	/* shared/res */
	snprintf(dirpath, BUF_SIZE, "%s/%s/shared/res", USR_APPS, pkgname);
	if (__is_dir(dirpath))
		_ri_privilege_setup_path(smack_label, dirpath, PERM_APP_PATH_ANY_LABEL, "_");
	memset(dirpath, '\0', BUF_SIZE);

	snprintf(dirpath, BUF_SIZE, "%s/%s/shared/res", OPT_USR_APPS, pkgname);
	if (__is_dir(dirpath))
		_ri_privilege_setup_path(smack_label, dirpath, PERM_APP_PATH_ANY_LABEL, "_");
	memset(dirpath, '\0', BUF_SIZE);

	/* shared/data */
	snprintf(dirpath, BUF_SIZE, "%s/%s/shared/data", USR_APPS, pkgname);
	if (__is_dir(dirpath)) {
		ret = chown(dirpath, APP_OWNER_ID, APP_GROUP_ID);
		if (ret != 0) {
			if( strerror_r(errno, buf, sizeof(buf)) == 0) {
				_LOGE("chown failed!! [%s]", buf);
			}
		}
		_ri_privilege_setup_path(smack_label, dirpath, PERM_APP_PATH_PUBLIC, NULL);
	}
	memset(dirpath, '\0', BUF_SIZE);

	snprintf(dirpath, BUF_SIZE, "%s/%s/shared/data", OPT_USR_APPS, pkgname);
	if (__is_dir(dirpath)) {
		ret = chown(dirpath, APP_OWNER_ID, APP_GROUP_ID);
		if (ret != 0) {
			if( strerror_r(errno, buf, sizeof(buf)) == 0) {
				_LOGE("chown failed!! [%s]", buf);
			}
		}
		_ri_privilege_setup_path(smack_label, dirpath, PERM_APP_PATH_PUBLIC, NULL);
	}

	/* shared/cache */
	ret = _coretpk_installer_get_smack_label_access(dirpath, &shared_data_label);
	if (ret != 0) {
		_LOGE("_coretpk_installer_apply_directory_policy() failed, appdir=[%s], ret=[%d]", dirpath, ret);
	}
	memset(dirpath, '\0', BUF_SIZE);
	snprintf(dirpath, BUF_SIZE, "%s/%s/shared/cache", OPT_USR_APPS, pkgname);
	if (!__is_dir(dirpath)) {
		ret = mkdir(dirpath, DIRECTORY_PERMISSION_755);
		if (ret < 0) {
			_LOGE("directory making is failed.\n");
		}
	}
	ret = chown(dirpath, APP_OWNER_ID, APP_GROUP_ID);
	if (ret != 0) {
		if( strerror_r(errno, buf, sizeof(buf)) == 0) {
			_LOGE("chown failed!! [%s]", buf);
		}
	}
	ret = _coretpk_installer_set_smack_label_access(dirpath, shared_data_label);
	if (ret != 0) {
		_LOGE("_coretpk_installer_apply_directory_policy() failed, appdir=[%s], ret=[%d]", dirpath, ret);
	}
	ret = _coretpk_installer_set_smack_label_transmute(dirpath, "1");
	if (ret != 0) {
		_LOGE("_coretpk_installer_apply_directory_policy() failed, appdir=[%s], ret=[%d]", dirpath, ret);
	}

	/* /shared/trusted/ */
	memset(dirpath, '\0', BUF_SIZE);
	snprintf(dirpath, BUF_SIZE, "%s/%s/shared/trusted", USR_APPS, pkgname);
	if (__is_dir(dirpath)) {
		ret = chown(dirpath, APP_OWNER_ID, APP_GROUP_ID);
		if (ret != 0) {
			if( strerror_r(errno, buf, sizeof(buf)) == 0) {
				_LOGE("chown failed!! [%s]", buf);
			}
		}

		ret = _rpm_installer_get_group_id(pkgname, &groupid);
		if (ret == 0) {
			_LOGD("group id for trusted directory is [%s]", groupid);
			_ri_privilege_setup_path(smack_label, dirpath, APP_PATH_GROUP_RW, groupid);
			FREE_AND_NULL(groupid);
		}
	}
	memset(dirpath, '\0', BUF_SIZE);

	snprintf(dirpath, BUF_SIZE, "%s/%s/shared/trusted", OPT_USR_APPS, pkgname);

	_LOGD("dirpath [%s]", dirpath);

	ret = _rpm_installer_get_group_id(pkgname, &groupid);
	if (ret == 0) {
		if (__is_dir(dirpath) != 1) {
			_LOGE("dont have [%s]", dirpath);

			ret = mkdir(dirpath, DIRECTORY_PERMISSION_755);
			if (ret == -1 && errno != EEXIST) {
				if( strerror_r(errno, buf, sizeof(buf)) == 0) {
					_LOGE("mkdir failed!! [%s]", buf);
				}
			}
		}

		ret = chown(dirpath, APP_OWNER_ID, APP_GROUP_ID);
		if (ret != 0) {
			if( strerror_r(errno, buf, sizeof(buf)) == 0) {
				_LOGE("chown failed!! [%s]", buf);
			}
		}

		_LOGD("group id for trusted directory is [%s]", groupid);
		_ri_privilege_setup_path(smack_label, dirpath, APP_PATH_GROUP_RW, groupid);
		_ri_set_group_id(pkgname, groupid);

		FREE_AND_NULL(groupid);
	}
}

int __is_dir(const char *dirname)
{
	struct stat stFileInfo;
	if (dirname == NULL) {
		_LOGE("dirname is null\n");
		return 0;
	}

	if (stat(dirname, &stFileInfo) < 0) {
		return 0;
	}

	if (S_ISDIR(stFileInfo.st_mode)) {
		return 1;
	}
	return 0;
}

static void __rpm_process_line(char *line)
{
	char *tok = NULL;
	char *save_str = NULL;
	tok = strtok_r(line, " ", &save_str);
	if (tok) {
		if (!strncmp(tok, "%%", 2)) {
			tok = strtok_r(NULL, " ", &save_str);
			if (tok) {
				_LOGD("Install percentage is %s\n", tok);
				_ri_broadcast_status_notification(gpkgname, PKGTYPE_RPM, "install_percent", tok);
				_ri_stat_cb(gpkgname, "install_percent", tok);
			}
			return;
		}
	}
	return;
}

static void __rpm_perform_read(int fd)
{
	char *buf_ptr = NULL;
	char *tmp_ptr = NULL;
	int size = 0;
	static char buffer[BUF_SIZE] = { 0, };
	static int buffer_position;

	size = read(fd, &buffer[buffer_position], sizeof(buffer) - buffer_position);
	buffer_position += size;
	if (size <= 0)
		return;

	/* Process each line of the recieved buffer */
	buf_ptr = tmp_ptr = buffer;
	while ((tmp_ptr = (char *)memchr(buf_ptr, '\n', buffer + buffer_position - buf_ptr)) != NULL) {
		*tmp_ptr = 0;
		__rpm_process_line(buf_ptr);
		/* move to next line and continue */
		buf_ptr = tmp_ptr + 1;
	}

	/* move the remaining bits at the start of the buffer
	   and update the buffer position */
	buf_ptr = (char *)memrchr(buffer, 0, buffer_position);
	if (buf_ptr == NULL)
		return;

	/* we have processed till the last \n which has now become
	   0x0. So we increase the pointer to next position */
	buf_ptr++;

	memmove(buffer, buf_ptr, buf_ptr - buffer);
	buffer_position = buffer + buffer_position - buf_ptr;
}

int _rpm_xsystem(const char *argv[])
{
	int err = 0;
	int status = 0;
	pid_t pid;
	int pipefd[2];
	int result = 0;
	int fd = 0;

	if (pipe(pipefd) == -1) {
		_LOGE("pipe creation failed\n");
		return -1;
	}
	/* Read progress info via pipe */
	pid = fork();

	switch (pid) {
	case -1:
		_LOGE("fork failed\n");
		return -1;
	case 0:
		/* child */
		close(pipefd[0]);
		close(1);
		close(2);
		fd = dup(pipefd[1]);
		if (fd < 0) {
			_LOGE("dup failed\n");
			_exit(100);
		}

		result = dup(pipefd[1]);
		if (result < 0) {
			_LOGE("dup failed\n");
			_exit(100);
		}

		if (execvp(argv[0], (char *const *)argv) == -1) {
			_LOGE("execvp failed\n");
		}
		_exit(100);
	default:
		/* parent */
		break;
	}

	close(pipefd[1]);

	while ((err = waitpid(pid, &status, WNOHANG)) != pid) {
		if (err < 0) {
			if (errno == EINTR)
				continue;
			_LOGE("waitpid failed\n");
			close(pipefd[0]);
			return -1;
		}

		int select_ret;
		fd_set rfds;
		struct timespec tv;
		FD_ZERO(&rfds);
		FD_SET(pipefd[0], &rfds);
		tv.tv_sec = 1;
		tv.tv_nsec = 0;
		select_ret = pselect(pipefd[0] + 1, &rfds, NULL, NULL, &tv, NULL);
		if (select_ret == 0)
			continue;

		else if (select_ret < 0 && errno == EINTR)
			continue;
		else if (select_ret < 0) {
			_LOGE("select() returned error\n");
			continue;
		}
		if (FD_ISSET(pipefd[0], &rfds))
			__rpm_perform_read(pipefd[0]);
	}

	close(pipefd[0]);
	/* Check for an error code. */
	if (WIFEXITED(status) == 0 || WEXITSTATUS(status) != 0) {
		if (WIFSIGNALED(status) != 0 && WTERMSIG(status) == SIGSEGV) {
			printf("Sub-process %s received a segmentation fault. \n", argv[0]);
		} else if (WIFEXITED(status) != 0) {
			printf("Sub-process %s returned an error code (%u)\n", argv[0], WEXITSTATUS(status));
		} else {
			printf("Sub-process %s exited unexpectedly\n", argv[0]);
		}
	}
	return WEXITSTATUS(status);
}

void __rpm_clear_dir_list(GList *dir_list)
{
	GList *list = NULL;
	app2ext_dir_details *dir_detail = NULL;
	if (dir_list) {
		list = g_list_first(dir_list);
		while (list) {
			dir_detail = (app2ext_dir_details *) list->data;
			if (dir_detail && dir_detail->name) {
				free(dir_detail->name);
			}
			g_free(list->data);
			list = g_list_next(list);
		}
		g_list_free(dir_list);
	}
}

GList *__rpm_populate_dir_list()
{
	GList *dir_list = NULL;
	GList *list = NULL;
	app2ext_dir_details *dir_detail = NULL;
	int i;
	char pkg_ro_content_rpm[3][5] = { "bin", "res", "lib" };

	for (i = 0; i < 3; i++) {
		dir_detail = (app2ext_dir_details *) calloc(1, sizeof(app2ext_dir_details));
		if (dir_detail == NULL) {
			printf("\nMemory allocation failed\n");
			goto FINISH_OFF;
		}
		dir_detail->name = (char *)calloc(1, sizeof(char) * (strlen(pkg_ro_content_rpm[i]) + 2));
		if (dir_detail->name == NULL) {
			printf("\nMemory allocation failed\n");
			free(dir_detail);
			goto FINISH_OFF;
		}
		snprintf(dir_detail->name, (strlen(pkg_ro_content_rpm[i]) + 1), "%s", pkg_ro_content_rpm[i]);
		dir_detail->type = APP2EXT_DIR_RO;
		dir_list = g_list_append(dir_list, dir_detail);
	}
	if (dir_list) {
		list = g_list_first(dir_list);
		while (list) {
			dir_detail = (app2ext_dir_details *) list->data;
			list = g_list_next(list);
		}
	}

	return dir_list;

FINISH_OFF:
	if (dir_list) {
		list = g_list_first(dir_list);
		while (list) {
			dir_detail = (app2ext_dir_details *) list->data;
			if (dir_detail && dir_detail->name) {
				free(dir_detail->name);
			}
			g_free(list->data);
			list = g_list_next(list);
		}
		g_list_free(dir_list);
	}

	return NULL;
}

static char *__ri_get_cert_from_file(const char *file)
{
	FILE *fp_cert = NULL;
	int certlen = 0;
	char *certbuf = NULL;
	char *startcert = NULL;
	char *endcert = NULL;
	int certwrite = 0;
	char *cert = NULL;
	int i = 0;
	int ch = 0;
	int error = 0;

	if (!(fp_cert = fopen(file, "r"))) {
		_LOGE("[ERR][%s] Fail to open file, [%s]\n", __func__, file);
		return NULL;
	}

	fseek(fp_cert, 0L, SEEK_END);

	if (ftell(fp_cert) < 0) {
		_LOGE("[ERR][%s] Fail to find EOF\n", __func__);
		error = 1;
		goto err;
	}

	certlen = ftell(fp_cert);
	if (certlen < 0) {
		_LOGE("[ERR][%s] Fail to find EOF\n", __func__);
		error = 1;
		goto err;
	}

	fseek(fp_cert, 0L, SEEK_SET);

	if (!(certbuf = (char *)malloc(sizeof(char) * (int)certlen))) {
		_LOGE("[ERR][%s] Fail to allocate memory\n", __func__);
		error = 1;
		goto err;
	}
	memset(certbuf, 0x00, (int)certlen);

	i = 0;
	while ((ch = fgetc(fp_cert)) != EOF) {
		if (ch != '\n') {
			certbuf[i] = ch;
			i++;
		}
	}
	certbuf[i] = '\0';

	startcert = strstr(certbuf, "-----BEGIN CERTIFICATE-----") + strlen("-----BEGIN CERTIFICATE-----");
	endcert = strstr(certbuf, "-----END CERTIFICATE-----");
	certwrite = (int)endcert - (int)startcert;

	cert = (char *)malloc(sizeof(char) * (certwrite + 2));
	if (cert == NULL) {
		_LOGE("[ERR][%s] Fail to allocate memory\n", __func__);
		error = 1;
		goto err;
	}
	memset(cert, 0x00, certwrite + 2);
	snprintf(cert, certwrite + 1, "%s", startcert);
	_LOGD("Root CA, len=[%d]\n%s", certwrite, cert);

err:
	if (certbuf)
		free(certbuf);
	fclose(fp_cert);
	if (error)
		return NULL;
	else
		return cert;
}

static int __privilege_func(const char *name, void *user_data)
{
	int ret = 0;
	privilegeinfo *info = (privilegeinfo *) user_data;

	_LOGD("package_id=[%s], privilege=[%s]", info->package_id, name);
	info->privileges = g_list_append(info->privileges, strdup((char *)name));

	if (strcmp(name, EXT_APPDATA_PRIVILEGE_NAME) == 0) {
		_LOGD("it is EXT_APPDATA_PRIVILEGE_NAME");
		if (_coretpk_installer_make_directory_for_ext((char *)info->package_id) < 0) {
			_LOGE("make_directory_for_ext failed.");
		}
	}

	return ret;
}

char *__strlwr(char *str)
{
	int i = 0;

	while (*(str + i) != '\0') {
		if (*(str + i) >= 65 || *(str + i) <= 90) {
			*(str + i) = towlower(*(str + i));
		}
		i++;
	}
	return str;
}

static char *__getvalue(const char *pBuf, const char *pKey)
{
	const char *p = NULL;
	const char *pStart = NULL;
	const char *pEnd = NULL;

	p = strstr(pBuf, pKey);
	if (p == NULL)
		return NULL;

	pStart = p + strlen(pKey) + 1;
	pEnd = strchr(pStart, SEPERATOR_START);
	if (pEnd == NULL)
		return NULL;

	size_t len = pEnd - pStart;
	if (len <= 0)
		return NULL;

	char *pRes = (char *)malloc(len + 1);
	if (pRes == NULL) {
		_LOGE("@malloc failed");
		return NULL;
	}
	strncpy(pRes, pStart, len);
	pRes[len] = 0;

	return pRes;
}

static char *__find_rpm_pkgid(const char *manifest)
{
	FILE *fp = NULL;
	char buf[BUF_SIZE] = { 0 };
	char *pkgid = NULL;

	fp = fopen(manifest, "r");
	if (fp == NULL) {
		_LOGE("csc-info : Fail get : %s\n", manifest);
		return NULL;
	}

	while (fgets(buf, BUF_SIZE, fp) != NULL) {
		__str_trim(buf);
		pkgid = __getvalue(buf, TOKEN_PACKAGE_STR);
		if (pkgid != NULL) {
			fclose(fp);
			return pkgid;
		}
		memset(buf, 0x00, BUF_SIZE);
	}

	if (fp != NULL)
		fclose(fp);

	return NULL;
}

static int __copy_file(const char *src_path, const char *dst_path)
{
	FILE *src, *dst;
	int rc = 0;
	unsigned char temp_buf[8192] = { '\0', };
	size_t size_of_uchar = sizeof(unsigned char);
	size_t size_of_temp_buf = sizeof(temp_buf);
	char buf[BUF_SIZE] = { 0, };

	src = fopen(src_path, "r");
	if (src == NULL) {
		if( strerror_r(errno, buf, sizeof(buf)) == 0) {
			_LOGE("Failed to open(). path=%s, E:%d(%s)", src_path, errno, buf);
		}
		return -1;
	}

	dst = fopen(dst_path, "w");
	if (dst == NULL) {
		if( strerror_r(errno, buf, sizeof(buf)) == 0) {
			_LOGE("Failed to open dst file. file=%s, E:%d(%s)", dst_path, errno, buf);
		}
		fclose(src);
		return -1;
	}

	while (!feof(src)) {
		rc = fread(temp_buf, size_of_uchar, size_of_temp_buf, src);
		fwrite(temp_buf, size_of_uchar, rc, dst);
	}

	fclose(src);
	fclose(dst);
	return 0;
}

static int __ri_install_csc(char *path_str, char *remove_str)
{
	int ret = 0;
	char *pkgid = NULL;
	char delims[] = "/";
	char *token = NULL;
	char argv[BUF_SIZE] = { '\0' };
	char xml_name[BUF_SIZE] = { '\0' };
	char src_file[BUF_SIZE] = { '\0' };
	char dest_file[BUF_SIZE] = { '\0' };
	char *save_str = NULL;

	snprintf(src_file, sizeof(src_file), "%s", path_str);

	/* get pkgid from path str */
	pkgid = __find_rpm_pkgid(path_str);
	if (pkgid == NULL) {
		_LOGE("csc-info : fail to find pkgid\n");
		return -1;
	}
	_LOGD("csc-info : find pkgid=[%s] for installation\n", pkgid);

	/* find xml name */
	token = strtok_r(path_str, delims, &save_str);
	while (token) {
		memset(xml_name, 0x00, sizeof(xml_name));
		strncat(xml_name, token, sizeof(xml_name) - 1);
		token = strtok_r(NULL, delims, &save_str);
	}
	_LOGD("csc-info : xml name = %s\n", xml_name);

	/* copy xml to /opt/share/packages */
	snprintf(dest_file, sizeof(dest_file), "%s/%s", OPT_SHARE_PACKAGES, xml_name);
	ret = __copy_file(src_file, dest_file);
	if (ret != 0) {
		_LOGE("csc-info : xml copy fail(%d)\n", ret);
	} else {
		_LOGE("csc-info : xml copy success to [%s] \n", dest_file);
	}

	/* remove old pkg info */
	ret = pkgmgr_parser_parse_manifest_for_uninstallation(pkgid, NULL);
	if (ret < 0) {
		_LOGD("csc-info : fail remove old pkg info\n");
	} else {
		_LOGD("csc-info : success remove old pkg info\n");
	}

	/* insert new pkg info */
	memset(argv, 0x00, sizeof(argv));
	snprintf(argv, sizeof(argv), "%s/%s", OPT_SHARE_PACKAGES, xml_name);
	ret = __ri_init_csc_xml(argv, remove_str);
	if (ret < 0) {
		_LOGD("csc-info : fail insert db\n");
	} else {
		_LOGD("csc-info : success xml name = %s\n", xml_name);
	}
	if (pkgid) {
		free(pkgid);
		pkgid = NULL;
	}

	return 0;
}

static int __ri_uninstall_csc(char *pkgid)
{
	/* remove old pkg info */
	int ret = pkgmgr_parser_parse_manifest_for_uninstallation(pkgid, NULL);
	if (ret < 0) {
		_LOGD("csc-info : fail remove old pkg info\n");
	} else {
		_LOGD("csc-info : success remove old pkg info\n");
	}

	return 0;
}

static int __get_size_from_xml(const char *manifest, int *size)
{
	const char *val = NULL;
	const xmlChar *node;
	xmlTextReaderPtr reader;
	int ret = PMINFO_R_OK;

	if (manifest == NULL) {
		_LOGE("Input argument is NULL\n");
		return PMINFO_R_ERROR;
	}

	if (size == NULL) {
		_LOGE("Argument supplied to hold return value is NULL\n");
		return PMINFO_R_ERROR;
	}

	reader = xmlReaderForFile(manifest, NULL, 0);

	if (reader) {
		if (_child_element(reader, -1)) {
			node = xmlTextReaderConstName(reader);
			if (!node) {
				_LOGE("xmlTextReaderConstName value is NULL\n");
				ret = PMINFO_R_ERROR;
				goto end;
			}

			if (!strcmp(ASCII(node), "manifest")) {
				ret = _ri_get_attribute(reader, "size", &val);
				if (ret != 0) {
					_LOGE("@Error in getting the attribute value");
					ret = PMINFO_R_ERROR;
					goto end;
				}
				if (val) {
					*size = atoi(val);
					free((void *)val);
				} else {
					*size = 0;
					_LOGE("package size is not specified\n");
					ret = PMINFO_R_ERROR;
					goto end;
				}
			} else {
				_LOGE("Unable to create xml reader\n");
				ret = PMINFO_R_ERROR;
				goto end;
			}
		}
	} else {
		_LOGE("xmlReaderForFile value is NULL\n");
		ret = PMINFO_R_ERROR;
	}

end:
	xmlFreeTextReader(reader);
	return ret;
}

static int __get_location_from_xml(const char *manifest, pkgmgrinfo_install_location * location)
{
	const char *val = NULL;
	const xmlChar *node;
	xmlTextReaderPtr reader;
	int ret = -1;

	if (manifest == NULL) {
		_LOGE("Input argument is NULL\n");
		return PMINFO_R_ERROR;
	}

	if (location == NULL) {
		_LOGE("Argument supplied to hold return value is NULL\n");
		return PMINFO_R_ERROR;
	}

	reader = xmlReaderForFile(manifest, NULL, 0);

	if (reader) {
		if (_child_element(reader, -1)) {
			node = xmlTextReaderConstName(reader);
			if (!node) {
				_LOGE("xmlTextReaderConstName value is NULL\n");
				xmlFreeTextReader(reader);
				return PMINFO_R_ERROR;
			}

			if (!strcmp(ASCII(node), "manifest")) {
				ret = _ri_get_attribute(reader, "install-location", &val);
				if (ret != 0) {
					_LOGE("@Error in getting the attribute value");
					xmlFreeTextReader(reader);
					return PMINFO_R_ERROR;
				}

				if (val) {
					if (strcmp(val, "internal-only") == 0)
						*location = PMINFO_INSTALL_LOCATION_INTERNAL_ONLY;
					else if (strcmp(val, "prefer-external") == 0)
						*location = PMINFO_INSTALL_LOCATION_PREFER_EXTERNAL;
					else
						*location = PMINFO_INSTALL_LOCATION_AUTO;
					free((void *)val);
				}
			} else {
				_LOGE("Unable to create xml reader\n");
				xmlFreeTextReader(reader);
				return PMINFO_R_ERROR;
			}
		}
	} else {
		_LOGE("xmlReaderForFile value is NULL\n");
		return PMINFO_R_ERROR;
	}

	xmlFreeTextReader(reader);

	return PMINFO_R_OK;
}

static char *__get_pkg_path(const char *pkg_path, const char *pkgid)
{
	int ret = 0;
	char buff[BUF_SIZE] = { '\0' };
	char *real_path = NULL;
	char buf[BUF_SIZE] = { 0, };

	snprintf(buff, BUF_SIZE, "%s/%s", pkg_path, pkgid);
	do {
		if (__is_dir(buff))
			break;
		memset(buff, '\0', BUF_SIZE);
		snprintf(buff, BUF_SIZE, "%s/%s", USR_APPS, pkgid);
		if (__is_dir(buff))
			break;
		memset(buff, '\0', BUF_SIZE);
		snprintf(buff, BUF_SIZE, "/opt/apps/%s", pkgid);
		if (__is_dir(buff))
			break;
		memset(buff, '\0', BUF_SIZE);
		snprintf(buff, BUF_SIZE, "%s/%s", OPT_USR_APPS, pkgid);
		if (__is_dir(buff))
			break;
	} while (0);

	ret = chdir(buff);
	if (ret != 0) {
		if( strerror_r(errno, buf, sizeof(buf)) == 0) {
			_LOGE("chdir(%s) failed. [%s]", buff, buf);
		}
		return NULL;
	}

	real_path = (char *)malloc(strlen(buff) + 1);
	if (real_path == NULL) {
		_LOGE("malloc() failed.");
		return NULL;
	}
	memset(real_path, '\0', strlen(buff) + 1);
	memcpy(real_path, buff, strlen(buff));

	return real_path;
}

void _ri_register_cert(const char *pkgid)
{
	int error = 0;
	pkgmgrinfo_instcertinfo_h handle = NULL;
	int i = 0;
	/* create Handle */
	error = pkgmgrinfo_create_certinfo_set_handle(&handle);
	if (error != 0) {
		_LOGE("Cert handle creation failed. Err:%d", error);
		__ri_free_cert_chain();
		return;
	}

	if (list[SIG_AUTH].cert_value == NULL) {
		_LOGE("pkgid[%s] dont have SIG_AUTH.cert_value ", pkgid);
		goto err;
	}

	for (i = 0; i < MAX_CERT_NUM; i++) {

		if (list[i].cert_value) {
			error = pkgmgrinfo_set_cert_value(handle, list[i].cert_type, list[i].cert_value);
			if (error != 0) {
				_LOGE("pkgmgrinfo_set_cert_value failed. cert type:%d. Err:%d", list[i].cert_type, error);
				goto err;
			}
		}
	}
	/* Save the certificates in cert DB */
	error = pkgmgrinfo_save_certinfo(pkgid, handle);
	if (error != 0) {
		_LOGE("pkgmgrinfo_save_certinfo failed. Err:%d", error);
		goto err;
	}
err:
	if (handle)
		pkgmgrinfo_destroy_certinfo_set_handle(handle);
	__ri_free_cert_chain();
}

void _ri_unregister_cert(const char *pkgid)
{
	int error = 0;
	/* Delete the certifictes from cert DB */
	error = pkgmgrinfo_delete_certinfo(pkgid);
	if (error != 0) {
		_LOGE("pkgmgrinfo_delete_certinfo failed. Err:%d", error);
		return;
	}
}

int _ri_get_visibility_from_signature_file(const char *sigfile, int *visibility, bool save_ca_path)
{
	char certval[BUF_SIZE] = { '\0' };
	int err = 0;
	int i = 0;
	int j = 0;
	int ret = RPM_INSTALLER_SUCCESS;
	signature_x *signx = NULL;
	struct keyinfo_x *keyinfo = NULL;
	struct x509data_x *x509data = NULL;
	CERT_CONTEXT *ctx = NULL;
	int validity = 0;

	if (sigfile == NULL) {
		return RPM_INSTALLER_ERR_WRONG_PARAM;
	}

	ctx = cert_svc_cert_context_init();
	if (ctx == NULL) {
		_LOGE("cert_svc_cert_context_init() failed.");
		return RPM_INSTALLER_ERR_INTERNAL;
	}

	if (!strstr(sigfile, SIGNATURE1_XML)) {
		_LOGE("Unsupported signature type! [%s]", sigfile);
		cert_svc_cert_context_final(ctx);
		return RPM_INSTALLER_ERR_INTERNAL;
	}

	signx = _ri_process_signature_xml(sigfile);
	if (signx == NULL) {
		_LOGE("_ri_process_signature_xml(%s) failed.", sigfile);
		ret = RPM_INSTALLER_ERR_INTERNAL;
		goto end;
	}

	keyinfo = signx->keyinfo;
	if ((keyinfo == NULL) || (keyinfo->x509data == NULL)
		|| (keyinfo->x509data->x509certificate == NULL)) {
		_LOGE("keyinfo is invalid. [%s]", sigfile);
		ret = RPM_INSTALLER_ERR_CERT_INVALID;
		goto end;
	}

	x509data = keyinfo->x509data;
	x509certificate_x *cert = x509data->x509certificate;

	/* First cert is Signer certificate */
	if (cert->text != NULL) {
		for (i = 0; i <= (int)strlen(cert->text); i++) {
			if (cert->text[i] != '\n') {
				certval[j++] = cert->text[i];
			}
		}
		certval[j] = '\0';

		err = cert_svc_load_buf_to_context(ctx, (unsigned char *)certval);
		if (err != 0) {
			_LOGE("cert_svc_load_buf_to_context() failed. err = [%d]", err);
			_SLOGE("cert_svc_load_buf_to_context() failed. cert = [%s]", certval);
			ret = RPM_INSTALLER_ERR_INTERNAL;
			goto end;
		}

		if (save_ca_path) {
			err = __ri_create_cert_chain(SIG_DIST1, SIG_SIGNER, certval);
			if (err) {
				_LOGE("__ri_create_cert_chain() failed. sigtype = [%d]", (int)SIG_DIST1);
				_SLOGE("__ri_create_cert_chain() failed. cert = [%s]", certval);
				__ri_free_cert_chain();
				ret = RPM_INSTALLER_ERR_INTERNAL;
				goto end;
			}
		}
	}

	/* Second cert is Intermediate certificate */
	cert = cert->next;
	if ((cert != NULL) && (cert->text != NULL)) {
		memset(certval, 0x00, BUF_SIZE);
		j = 0;
		for (i = 0; i <= (int)strlen(cert->text); i++) {
			if (cert->text[i] != '\n') {
				certval[j++] = cert->text[i];
			}
		}
		certval[j] = '\0';

		if (cert->text != NULL) {
			err = cert_svc_push_buf_into_context(ctx, (unsigned char *)certval);
			if (err != 0) {
				_LOGE("cert_svc_push_buf_into_context() failed. cert = [%s], err = [%d]", certval, err);
				ret = RPM_INSTALLER_ERR_INTERNAL;
				goto end;
			}
		}

		if (save_ca_path) {
			err = __ri_create_cert_chain(SIG_DIST1, SIG_INTERMEDIATE, certval);
			if (err) {
				_LOGE("__ri_create_cert_chain() failed. sigtype = [%d]", (int)SIG_DIST1);
				_SLOGE("__ri_create_cert_chain() failed. cert = [%s]", certval);
				__ri_free_cert_chain();
				ret = RPM_INSTALLER_ERR_INTERNAL;
				goto end;
			}
		}
	} else {
		_LOGE("Invalid CertChain! (cert->text is NULL.)");
		ret = RPM_INSTALLER_ERR_CERT_INVALID;
		goto end;
	}

	err = cert_svc_verify_package_certificate(ctx, &validity, sigfile);

	if (err != 0) {
		_LOGE("cert_svc_verify_package_certificate() failed.");
		ret = RPM_INSTALLER_ERR_INTERNAL;
		goto end;
	}
	if (validity == 0) {
		_LOGE("Certificate Invalid/Expired (validity == 0)");
		ret = RPM_INSTALLER_ERR_CERTCHAIN_VERIFICATION_FAILED;
		goto end;
	}
	_LOGD("cert_svc_verify() is done successfully. validity=[%d]", validity);

	err = cert_svc_get_visibility(ctx, visibility);
	if (err != 0) {
		_LOGE("cert_svc_get_visibility() failed. err = [%d]", err);
		ret = RPM_INSTALLER_ERR_SIG_VERIFICATION_FAILED;
		goto end;
	}
	ret = 0;

	if (save_ca_path && ctx->fileNames && ctx->fileNames->filename) {
		FREE_AND_NULL(sig1_capath);
		sig1_capath = strdup(ctx->fileNames->filename);
		sig1_visibility = *visibility;
	}

end:
	cert_svc_cert_context_final(ctx);
	ctx = NULL;
	_ri_free_signature_xml(signx);
	signx = NULL;
	return ret;
}

int _ri_verify_sig_and_cert(const char *sigfile, int *visibility, bool need_verify, char *ca_path)
{
	char certval[BUF_SIZE] = { '\0' };
	int err = 0;
	int validity = 0;
	int i = 0;
	int j = 0;
	int ret = RPM_INSTALLER_SUCCESS;
	char *crt = NULL;
	signature_x *signx = NULL;
	struct keyinfo_x *keyinfo = NULL;
	struct x509data_x *x509data = NULL;
	CERT_CONTEXT *ctx = NULL;
	int sigtype = 0;
	char *root_ca_path = NULL;

	ctx = cert_svc_cert_context_init();
	if (ctx == NULL) {
		_LOGE("cert_svc_cert_context_init() failed.");
		return RPM_INSTALLER_ERR_INTERNAL;
	}

	if (strstr(sigfile, AUTHOR_SIGNATURE_XML))
		sigtype = SIG_AUTH;
	else if (strstr(sigfile, SIGNATURE1_XML))
		sigtype = SIG_DIST1;
	else if (strstr(sigfile, SIGNATURE2_XML))
		sigtype = SIG_DIST2;
	else {
		_LOGE("Unsupported signature type! [%s]", sigfile);
		cert_svc_cert_context_final(ctx);
		return RPM_INSTALLER_ERR_SIG_INVALID;
	}

	if (sigtype == SIG_DIST1 && ca_path != NULL && strlen(ca_path) != 0) {
		root_ca_path = ca_path;
		*visibility = sig1_visibility;
		goto verify_sig;
	}

	signx = _ri_process_signature_xml(sigfile);
	if (signx == NULL) {
		_LOGE("_ri_process_signature_xml(%s) failed.", sigfile);
		ret = RPM_INSTALLER_ERR_SIG_INVALID;
		goto end;
	}

	keyinfo = signx->keyinfo;
	if ((keyinfo == NULL) || (keyinfo->x509data == NULL) || (keyinfo->x509data->x509certificate == NULL)) {
		_LOGE("keyinfo is invalid. [%s]", sigfile);
		ret = RPM_INSTALLER_ERR_CERT_INVALID;
		goto end;
	}

	x509data = keyinfo->x509data;
	x509certificate_x *cert = x509data->x509certificate;

	/* First cert is Signer certificate */
	if (cert->text != NULL) {
		for (i = 0; i <= (int)strlen(cert->text); i++) {
			if (cert->text[i] != '\n') {
				certval[j++] = cert->text[i];
			}
		}
		certval[j] = '\0';

		err = cert_svc_load_buf_to_context(ctx, (unsigned char *)certval);
		if (err != 0) {
			_LOGE("cert_svc_load_buf_to_context() failed. err = [%d]", err);
			_SLOGE("cert_svc_load_buf_to_context() failed. cert = [%s]", certval);
			ret = RPM_INSTALLER_ERR_CERT_INVALID;
			goto end;
		}

		err = __ri_create_cert_chain(sigtype, SIG_SIGNER, certval);
		if (err) {
			_LOGE("__ri_create_cert_chain() failed. sigtype = [%d]", sigtype);
			_SLOGE("__ri_create_cert_chain() failed. cert = [%s]", certval);
			__ri_free_cert_chain();
			ret = RPM_INSTALLER_ERR_CERT_INVALID;
			goto end;
		}
	} else {
		_LOGE("cert->text is NULL. [Signer]");
		ret = RPM_INSTALLER_ERR_CERT_INVALID;
		goto end;
	}

	/* Second cert is Intermediate certificate */
	cert = cert->next;
	if (cert == NULL) {
		_LOGE("cert is NULL. [Intermediate]");
		ret = RPM_INSTALLER_ERR_CERT_INVALID;
		goto end;
	}

	if (cert->text != NULL) {
		memset(certval, 0x00, BUF_SIZE);
		j = 0;
		for (i = 0; i <= (int)strlen(cert->text); i++) {
			if (cert->text[i] != '\n') {
				certval[j++] = cert->text[i];
			}
		}
		certval[j] = '\0';

		if (cert->text != NULL) {
			err = cert_svc_push_buf_into_context(ctx, (unsigned char *)certval);
			if (err != 0) {
				_LOGE("cert_svc_push_buf_into_context() failed. cert = [%s], err = [%d]", certval, err);
				ret = RPM_INSTALLER_ERR_CERT_INVALID;
				goto end;
			}
		}

		err = __ri_create_cert_chain(sigtype, SIG_INTERMEDIATE, certval);
		if (err) {
			_LOGE("__ri_create_cert_chain() failed. sigtype = [%d]", sigtype);
			_SLOGE("__ri_create_cert_chain() failed. cert = [%s]", certval);
			__ri_free_cert_chain();
			ret = RPM_INSTALLER_ERR_CERT_INVALID;
			goto end;
		}
	} else {
		_LOGE("Invalid CertChain! (cert->text is NULL.) [Intermediate]");
		ret = RPM_INSTALLER_ERR_CERT_INVALID;
		goto end;
	}

	err = cert_svc_verify_package_certificate(ctx, &validity, sigfile);
	if (err != 0 && (need_verify == true)) {
		_LOGE("cert_svc_verify_package_certificate() failed. err=[%d]", err);
		ret = err;
		goto end;
	}
	_LOGD("cert_svc_verify() is done successfully. validity=[%d]", validity);

	if (validity == 0) {
		_LOGE("Certificate Invalid/Expired (validity == 0)");
		ret = RPM_INSTALLER_ERR_CERTIFICATE_EXPIRED;
		goto end;
	}

	err = cert_svc_get_visibility(ctx, visibility);
	if (err != 0) {
		_LOGE("cert_svc_get_visibility() failed. err = [%d]", err);
		ret = RPM_INSTALLER_ERR_CERT_INVALID;
		goto end;
	}
	_LOGD("cert_svc_get_visibility() returns visibility=[%d]", *visibility);

	if (ctx->fileNames == NULL || ctx->fileNames->filename == NULL) {
		_LOGE("No Root CA cert found. Signature validation failed.");
		ret = RPM_INSTALLER_ERR_ROOT_CERT_NOT_FOUND;
		goto end;
	} else
		root_ca_path = ctx->fileNames->filename;

verify_sig:
	/* verify signature
	   For reference validation, we should be in TEMP_DIR/usr/apps/<pkgid> */
	if (root_ca_path != NULL && strlen(root_ca_path) != 0) {
		_LOGD("Root CA cert path=[%s]", root_ca_path);

		if (need_verify == true) {
			err = __ri_xmlsec_verify_signature(sigfile, root_ca_path);
			if (err < 0) {
				_LOGE("__ri_xmlsec_verify_signature(%s) failed.", sigfile);
				ret = RPM_INSTALLER_ERR_SIG_VERIFICATION_FAILED;
				goto end;
			}
		}

		crt = __ri_get_cert_from_file(root_ca_path);
		err = __ri_create_cert_chain(sigtype, SIG_ROOT, crt);
		if (err) {
			_LOGE("__ri_create_cert_chain() failed. sigtype = [%d]", sigtype);
			_SLOGE("__ri_create_cert_chain() failed. cert = [%s]", crt);
			__ri_free_cert_chain();
			ret = RPM_INSTALLER_ERR_CERT_INVALID;
			goto end;
		}

	}
	ret = 0;

end:
	cert_svc_cert_context_final(ctx);
	ctx = NULL;
	_ri_free_signature_xml(signx);
	signx = NULL;
	return ret;
}

int _ri_verify_signatures(const char *root_path, const char *pkgid, bool need_verify)
{
	int ret = 0;
	char buff[BUF_SIZE] = { '\0' };
	char *pkg_path = NULL;
	int visibility = 0;

	_LOGD("root_path=[%s], pkgid=[%s]", root_path, pkgid);

	/* check for signature and certificate */
	pkg_path = __get_pkg_path(root_path, pkgid);
	if (pkg_path == NULL) {
		_LOGE("__get_pkg_path(%s, %s) failed.", root_path, pkgid);
		return 0;
	}

	_LOGD("switched to pkg_path=[%s]", pkg_path);

	/* author-signature.xml is mandatory */
	snprintf(buff, BUF_SIZE, "%s/author-signature.xml", pkg_path);
	if (access(buff, F_OK) == 0) {
		_LOGD("author-signature.xml, path=[%s]", buff);
		ret = _ri_verify_sig_and_cert(buff, &visibility, need_verify, NULL);
		if (ret) {
			_LOGE("_ri_verify_sig_and_cert(%s) failed.", buff);
			ret = -1;
			goto end;
		}
		_LOGD("------------------------------------------------------");
		_LOGD("signature is verified successfully");
		_LOGD("path=[%s]", buff);
		_LOGD("------------------------------------------------------");
	}
	memset(buff, '\0', BUF_SIZE);

	/* signature2.xml is optional */
	snprintf(buff, BUF_SIZE, "%s/signature2.xml", pkg_path);
	if (access(buff, F_OK) == 0) {
		_LOGD("signature2.xml found. [%s]", pkg_path);
		ret = _ri_verify_sig_and_cert(buff, &visibility, need_verify, NULL);
		if (ret) {
			_LOGE("_ri_verify_sig_and_cert(%s) failed.", buff);
			ret = -1;
			goto end;
		}
		_LOGD("_ri_verify_sig_and_cert(%s) succeed.", buff);
	}
	memset(buff, '\0', BUF_SIZE);

	/* signature1.xml is mandatory */
	snprintf(buff, BUF_SIZE, "%s/signature1.xml", pkg_path);
	if (access(buff, F_OK) == 0) {
		_LOGD("signature1.xml, path=[%s]", buff);
		ret = _ri_verify_sig_and_cert(buff, &visibility, need_verify, NULL);
		if (ret) {
			_LOGE("_ri_verify_sig_and_cert(%s) failed.", buff);
			ret = -1;
			goto end;
		}
		_LOGD("------------------------------------------------------");
		_LOGD("signature is verified successfully");
		_LOGD("path=[%s]", buff);
		_LOGD("------------------------------------------------------");
	}
	memset(buff, '\0', BUF_SIZE);

	ret = 0;

end:
	if (pkg_path) {
		free(pkg_path);
		pkg_path = NULL;
	}

	if ((ret != 0) && (sig_enable == 0)) {
		_LOGD("_ri_verify_signatures(%s, %s) failed, but it's ok for config.", root_path, pkgid);
		ret = 0;
	}

	return ret;
}

void _ri_apply_smack(const char *pkgname, int flag, char *smack_label)
{
	__rpm_apply_smack(pkgname, flag, smack_label);
}

int _ri_apply_privilege(const char *pkgid, int visibility, char *smack_label)
{
	int ret = -1;
	pkgmgrinfo_pkginfo_h handle = NULL;
	privilegeinfo info;
	int apptype = PERM_APP_TYPE_EFL;
	int i = 0;
	char *privilege_fota[BUF_SIZE] = { NULL, };
	char *api_version = NULL;
	GList *list = NULL;

	if (smack_label == NULL || strlen(smack_label) == 0) {
		smack_label = (char *)pkgid;
	}

	memset(&info, '\0', sizeof(info));

	ret = pkgmgrinfo_pkginfo_get_pkginfo(pkgid, &handle);
	if (ret != PMINFO_R_OK) {
		_LOGE("pkgmgrinfo_pkginfo_get_pkginfo(%s) failed.", pkgid);
		return -1;
	}

	ret = pkgmgrinfo_pkginfo_get_api_version(handle, &api_version);
	if (ret != PMINFO_R_OK)
		_LOGE("failed to get api version (%s)", pkgid);

	if (api_version) {
		ret = _ri_privilege_set_package_version(smack_label, api_version);
		if (ret != 0) {
			_LOGE("failed to set api version for smack_label: %s, ret[%d]", smack_label, ret);
			pkgmgrinfo_pkginfo_destroy_pkginfo(handle);
			return -1;
		} else
			_LOGD("api-version[%s] fot privilege has done successfully.", api_version);
	}

	strncpy(info.package_id, pkgid, sizeof(info.package_id) - 1);
	info.visibility = visibility;

	ret = pkgmgrinfo_pkginfo_foreach_privilege(handle, __privilege_func, (void *)&info);
	if (ret != PMINFO_R_OK) {
		_LOGE("pkgmgrinfo_pkginfo_foreach_privilege(%s) failed.", pkgid);
		pkgmgrinfo_pkginfo_destroy_pkginfo(handle);
		return -1;
	}
	pkgmgrinfo_pkginfo_destroy_pkginfo(handle);

	if (visibility & CERT_SVC_VISIBILITY_PLATFORM) {
		_LOGD("VISIBILITY_PLATFORM!");
		apptype = PERM_APP_TYPE_EFL_PLATFORM;
	} else if ((visibility & CERT_SVC_VISIBILITY_PARTNER) ||
		(visibility & CERT_SVC_VISIBILITY_PARTNER_OPERATOR) ||
		(visibility & CERT_SVC_VISIBILITY_PARTNER_MANUFACTURER)) {
		_LOGD("VISIBILITY_PARTNER!");
		apptype = PERM_APP_TYPE_EFL_PARTNER;
	}

	list = g_list_first(info.privileges);

	while (list) {
		privilege_fota[i] = strdup((char *)list->data);
		i++;
		list = g_list_next(list);
	}

	privilege_fota[i] = NULL;

	ret = _ri_privilege_enable_permissions(smack_label, apptype, (const char **)privilege_fota, 1);
	for (i = 0; i < g_list_length(info.privileges); i++) {
		if (privilege_fota[i]) {
			free(privilege_fota[i]);
			privilege_fota[i] = NULL;
		}
	}

	if (info.privileges != NULL) {
		list = g_list_first(info.privileges);
		while (list) {
			if (list->data) {
				free(list->data);
			}
			list = g_list_next(list);
		}
		g_list_free(info.privileges);
		info.privileges = NULL;
	}

	if (ret < 0) {
		_LOGE("_ri_privilege_enable_permissions(%s, %d) failed.", smack_label, apptype);
		return -1;
	}

	return 0;
}

int _ri_set_group_id(const char *pkgid, const char *groupid)
{
	retvm_if(pkgid == NULL, PMINFO_R_EINVAL, "pkgid is NULL\n");
	retvm_if(groupid == NULL, PMINFO_R_EINVAL, "groupid is NULL\n");
	int ret = -1;
	sqlite3 *pkginfo_db = NULL;
	char *query = NULL;

	/* open db */
	ret = db_util_open(PKGMGR_DB, &pkginfo_db, 0);
	retvm_if(ret != SQLITE_OK, PMINFO_R_ERROR, "connect db [%s] failed!", PKGMGR_DB);

	/* Begin transaction */
	ret = sqlite3_exec(pkginfo_db, "BEGIN EXCLUSIVE", NULL, NULL, NULL);
	tryvm_if(ret != SQLITE_OK, ret = PMINFO_R_ERROR, "Failed to begin transaction\n");
	_LOGD("Transaction Begin\n");

	query = sqlite3_mprintf("update package_info set package_reserve3=%Q where package=%Q", groupid, pkgid);

	ret = sqlite3_exec(pkginfo_db, query, NULL, NULL, NULL);
	tryvm_if(ret != SQLITE_OK, ret = PMINFO_R_ERROR, "Don't execute query = %s\n", query);

	/* Commit transaction */
	ret = sqlite3_exec(pkginfo_db, "COMMIT", NULL, NULL, NULL);
	if (ret != SQLITE_OK) {
		_LOGE("Failed to commit transaction. Rollback now\n");
		ret = sqlite3_exec(pkginfo_db, "ROLLBACK", NULL, NULL, NULL);
		tryvm_if(ret != SQLITE_OK, ret = PMINFO_R_ERROR, "Don't execute query = %s\n", query);
	}
	_LOGD("Transaction Commit and End\n");

	ret = PMINFO_R_OK;
catch:
	sqlite3_free(query);
	sqlite3_close(pkginfo_db);

	return ret;
}

/**
 * callback for the pkgmgrinfo_appinfo_get_list used in _rpm_uninstall_pkg()
 */
int __ri_check_running_app(const pkgmgrinfo_appinfo_h handle, void *user_data)
{
	int ret = 0;
	bool isRunning = 0;
	char *appid = NULL;
	app_context_h appCtx = NULL;

	ret = pkgmgrinfo_appinfo_get_appid(handle, &appid);
	if (ret < 0) {
		_LOGE("Failed to execute pkgmgrinfo_appinfo_get_appid[%d].\n", ret);
		return ret;
	}

	if (user_data != NULL)
		*(GList **)user_data = g_list_append(*(GList **)user_data, strdup(appid));

	ret = app_manager_is_running(appid, &isRunning);
	if (ret < 0) {
		_LOGE("Failed to execute app_manager_is_running[%d].\n", ret);
		return ret;
	}
	_LOGE("app[%s] , running state[%d].\n", appid, isRunning);

	if (isRunning) {
		ret = app_manager_get_app_context(appid, &appCtx);
		if (ret < 0) {
			_LOGE("Failed to execute app_manager_get_app_context[%d].\n", ret);
			return ret;
		}

		ret = app_manager_terminate_app(appCtx);
		if (ret < 0) {
			_LOGE("Failed to execute app_manager_terminate_app[%d].\n", ret);
			app_context_destroy(appCtx);
			return ret;
		}

		int i = 0;
		for (i = 0; i < TERMINATE_RETRY_COUNT; i++) {
			ret = app_manager_is_running(appid, &isRunning);
			if (ret < 0) {
				_LOGE("Failed to execute app_manager_is_running[%d].\n", ret);
				app_context_destroy(appCtx);
				return ret;
			}

			if (!isRunning) {
				_LOGD("App(%s) is terminated.\n", appid);
				break;
			} else {
				_LOGD("App(%s) is not terminated yet. wait count=[%d].\n", appid, i);
				usleep(100000);
			}
		}

		ret = app_context_destroy(appCtx);
		if (ret < 0) {
			_LOGE("Failed to execute app_context_destroy[%d].\n", ret);
			return ret;
		}
	}

	return ret;
}

int __ri_change_dir(const char *dirname)
{
	int ret = 0;

	ret = mkdir(dirname, 0644);
	if (ret < 0) {
		if (access(dirname, F_OK) == 0) {
			_installer_util_delete_dir(dirname);
			ret = mkdir(dirname, 0644);
			if (ret < 0) {
				_LOGE("mkdir(%s) failed\n", dirname);
				return -1;
			}
		} else {
			_LOGE("can not access[%s]\n", dirname);
			return -1;
		}
	}

	ret = chdir(dirname);
	if (ret != 0) {
		char buf[BUF_SIZE] = { 0, };
		if( strerror_r(errno, buf, sizeof(buf)) == 0) {
			_LOGE("chdir(%s) failed [%s]\n", dirname, buf);
		}
		return -1;
	}
	return 0;
}

int _ri_smack_reload(const char *pkgid, rpm_request_type request_type)
{
	int ret = 0;
	char *op_type = NULL;

	switch (request_type) {
	case INSTALL_REQ:
		op_type = strdup("install");
		break;

	case UPGRADE_REQ:
		op_type = strdup("update");
		break;

	case UNINSTALL_REQ:
		op_type = strdup("uninstall");
		break;

	default:
		break;
	}

	if (op_type == NULL) {
		_LOGE("@Failed to reload smack. request_type not matched[pkgid=%s, op=%s]", pkgid, op_type);
		return -1;
	}

	const char *smack_argv[] = { "/usr/bin/smack_reload.sh", op_type, pkgid, NULL };
	ret = _ri_xsystem(smack_argv);
	if (ret != 0) {
		_LOGE("@Failed to reload smack[pkgid=%s, op=%s].", pkgid, op_type);
	} else {
		_LOGD("#success: smack reload[pkgid=%s, op=%s]", pkgid, op_type);
	}
	if (op_type) {
		free(op_type);
		op_type = NULL;
	}
	return ret;
}

int _ri_smack_reload_all(void)
{
	int ret = 0;

	const char *smack_argv[] = { "/usr/bin/smackload-fast", NULL };
	ret = _ri_xsystem(smack_argv);
	if (ret != 0) {
		_LOGE("@Failed to reload all smack : %d", errno);
	} else {
		_LOGD("#success: smack reload all");
	}

	return ret;
}

void __ri_remove_updated_dir(const char *pkgid)
{
	char path_buf[BUF_SIZE] = { '\0' };

	/* check pkgid */
	if (pkgid == NULL) {
		_LOGE("pkgid is NULL.");
		return;
	}

	/* remove bin dir */
	snprintf(path_buf, BUF_SIZE, "%s/%s/%s", OPT_USR_APPS, pkgid, BIN_DIR_STR);
	if (__is_dir(path_buf)) {
		_LOGE("@pkgid[%s] need to clean dir[%s]\n", pkgid, path_buf);
		_installer_util_delete_dir(path_buf);
	}

	/* remove res dir */
	memset(path_buf, '\0', BUF_SIZE);
	snprintf(path_buf, BUF_SIZE, "%s/%s/%s", OPT_USR_APPS, pkgid, RES_DIR_STR);
	if (__is_dir(path_buf)) {
		_LOGE("@pkgid[%s] need to clean dir[%s]\n", pkgid, path_buf);
		_installer_util_delete_dir(path_buf);
	}

	/* remove shared/res dir */
	memset(path_buf, '\0', BUF_SIZE);
	snprintf(path_buf, BUF_SIZE, "%s/%s/%s", OPT_USR_APPS, pkgid, SHARED_RES_DIR_STR);
	if (__is_dir(path_buf)) {
		_LOGE("@pkgid[%s] need to clean dir[%s]\n", pkgid, path_buf);
		_installer_util_delete_dir(path_buf);
	}
}

static int __metadata_func(const char *key, const char *value, void *user_data)
{
	int ret = 0;
	bool isRunning = 0;

	if (key == NULL) {
		_LOGE("key is null\n");
		return -1;
	}
	if (value == NULL) {
		_LOGE("value is null\n");
		return -1;
	}
	if (user_data == NULL) {
		_LOGE("user_data is null\n");
		return -1;
	}

	if ((strcmp(key, "launch-on-attach") == 0) && (strcmp(value, "true") == 0)) {
		_LOGE("consumer[%s] : launch-on-attach is true \n", (char *)user_data);

		ret = app_manager_is_running((char *)user_data, &isRunning);
		if (ret < 0) {
			_LOGE("Failed to execute app_manager_is_running[%s].\n", (char *)user_data);
			return ret;
		}

		if (isRunning) {
			_LOGE("consumer[%s] is already launched \n", (char *)user_data);
		} else {
			usleep(100 * 1000);	/* 100ms sleep for infomation ready */
			ret = aul_launch_app((char *)user_data, NULL);
			if (ret == AUL_R_ERROR) {
				_LOGE("consumer[%s] launch fail, sleep and retry  launch_app\n", (char *)user_data);
				usleep(100 * 1000);	/* 100ms sleep for infomation ready */
				aul_launch_app((char *)user_data, NULL);
			}
			_LOGE("consumer[%s] is launched !!!! \n", (char *)user_data);
		}
	}
	return 0;
}

static int __ri_find_svcapp(const pkgmgrinfo_appinfo_h handle, void *user_data)
{
	int ret = 0;
	char *appid = NULL;
	char *component_type = NULL;

	ret = pkgmgrinfo_appinfo_get_component_type(handle, &component_type);
	if (ret != PMINFO_R_OK) {
		_LOGE("@Failed to get component_type\n");
		return -1;
	}

	if (strcmp(component_type, "svcapp") == 0) {
		ret = pkgmgrinfo_appinfo_get_appid(handle, &appid);
		if (ret != PMINFO_R_OK) {
			_LOGE("@Failed to get appid\n");
			return -1;
		}
		_LOGE("@find consumer[%s], check metadata for launch\n", appid);

		ret = pkgmgrinfo_appinfo_foreach_metadata(handle, __metadata_func, (void *)appid);
		if (ret != PMINFO_R_OK) {
			_LOGE("@Failed to get foreach_metadata\n");
			return -1;
		}
	}

	return 0;
}

static void __ri_launch_consumer(const char *pkgid)
{
	int ret = 0;
	pkgmgrinfo_pkginfo_h pkghandle = NULL;

	ret = pkgmgrinfo_pkginfo_get_pkginfo(pkgid, &pkghandle);
	if (ret < 0) {
		_LOGE("@Failed to get pkginfo handle [%s]\n", pkgid);
		return;
	}

	ret = pkgmgrinfo_appinfo_get_list(pkghandle, PM_UI_APP, __ri_find_svcapp, NULL);
	if (ret < 0) {
		_LOGE("@Failed to get appinfo_get_list [%s]\n", pkgid);
		return;
	}
	pkgmgrinfo_pkginfo_destroy_pkginfo(pkghandle);
}

static int __child_list_cb(const pkgmgrinfo_pkginfo_h handle, void *user_data)
{
	int ret = 0;
	char *pkgid = NULL;

	ret = pkgmgrinfo_pkginfo_get_pkgid(handle, &pkgid);
	if (ret < 0) {
		_LOGE("get_pkgid failed\n");
		return ret;
	}

	_LOGD("@child pkgid is [%s] for uninstallation", pkgid);

	ret = _rpm_uninstall_pkg_with_dbpath(pkgid, 0);
	if (ret != 0) {
		_LOGE("uninstall pkg(%s) failed\n", pkgid);
	}

	return ret;
}

static void __uninstall_child_package_by_mother_pkgid(const char *pkgid)
{
	int ret = 0;
	pkgmgrinfo_pkginfo_filter_h handle = NULL;

	ret = pkgmgrinfo_pkginfo_filter_create(&handle);
	if (ret != 0) {
		_LOGE("filter_create failed for (%s)\n", pkgid);
		return;
	}

	ret = pkgmgrinfo_pkginfo_filter_add_string(handle, PMINFO_PKGINFO_PROP_PACKAGE_STORECLIENT_ID, pkgid);
	if (ret < 0) {
		_LOGE("PMINFO_PKGINFO_PROP_PACKAGE_STORECLIENT_ID add failed\n");
		goto end;
	}

	ret = pkgmgrinfo_pkginfo_filter_foreach_pkginfo(handle, __child_list_cb, NULL);
	if (ret < 0) {
		_LOGE("foreach_pkginfo failed\n");
	}

end:
	pkgmgrinfo_pkginfo_filter_destroy(handle);
}

int _rpm_install_pkg_with_dbpath(char *pkgfilepath, char *pkgid, char *clientid)
{
	int ret = 0;
	char manifest[BUF_SIZE] = { '\0' };
	char resultxml[BUF_SIZE] = { '\0' };
	char resxml[BUF_SIZE] = { '\0' };
	char cwd[BUF_SIZE] = { '\0' };
	int home_dir = 0;
	char *temp = NULL;
	char buf[BUF_SIZE] = { 0, };

#ifdef APP2EXT_ENABLE
	app2ext_handle *handle = NULL;
	GList *dir_list = NULL;
	pkgmgrinfo_install_location location = 1;
	int size = -1;
	unsigned long rpm_size = 0;
#endif
	char *smack_label = NULL;

	/* send event for start */
	_ri_broadcast_status_notification(pkgid, PKGTYPE_RPM, "start", "install");
	_LOGD("[#]start : _rpm_install_pkg_with_dbpath");

	/* getcwd */
	temp = getcwd(cwd, BUF_SIZE);
	if ((temp == NULL) || (cwd[0] == '\0')) {
		_LOGE("@failed to get the current directory info.");
		ret = RPM_INSTALLER_ERR_INTERNAL;
		goto err;
	}
	_LOGD("#current working directory is %s", cwd);

	/* change dir */
	ret = __ri_change_dir(TEMP_DIR);
	if (ret == -1) {
		_LOGE("@failed to change directory.");
		ret = RPM_INSTALLER_ERR_INTERNAL;
		goto err;
	}
	_LOGD("#switched to %s", TEMP_DIR);

	/* run cpio script */
	const char *cpio_argv[] = { CPIO_SCRIPT, pkgfilepath, NULL };
	ret = _ri_xsystem(cpio_argv);

	/* get manifext.xml path */
	snprintf(manifest, BUF_SIZE, "%s%s/%s.xml", TEMP_DIR, OPT_SHARE_PACKAGES, pkgid);
	_LOGD("#manifest name is %s", manifest);

	if (access(manifest, F_OK)) {
		_LOGD("#there is no RW manifest.xml. check RO manifest.xml.");

		memset(manifest, '\0', sizeof(manifest));
		snprintf(manifest, BUF_SIZE, "%s%s/%s.xml", TEMP_DIR, USR_SHARE_PACKAGES, pkgid);
		_LOGD("#manifest name is %s", manifest);

		if (access(manifest, F_OK)) {
			_LOGE("@can not find manifest.xml in the pkg.");
			ret = RPM_INSTALLER_ERR_NO_MANIFEST;
			goto err;
		} else {
			home_dir = 0;
		}

#if 0
		/* disable "copy ro-xml to rw-xml", because of some bug */
		snprintf(srcpath, BUF_SIZE, "%s", manifest);
		memset(manifest, '\0', sizeof(manifest));
		snprintf(manifest, BUF_SIZE, "%s/%s.xml", OPT_SHARE_PACKAGES, pkgid);

		const char *xml_update_argv[] = { CPIO_SCRIPT_UPDATE_XML, srcpath, manifest, NULL };
		ret = _ri_xsystem(xml_update_argv);
#endif
	} else {
		home_dir = 1;
	}

	/* send event for install_percent */
	_ri_broadcast_status_notification(pkgid, PKGTYPE_RPM, "install_percent", "30");

	/* check manifest.xml validation */
	ret = pkgmgr_parser_check_manifest_validation(manifest);
	if (ret < 0) {
		_LOGE("@invalid manifest");
		ret = RPM_INSTALLER_ERR_INVALID_MANIFEST;
		goto err;
	}

	/* check existance of res.xml for resource manager */
	snprintf(resxml, BUF_SIZE, "%s%s/%s/res/res.xml", TEMP_DIR, USR_APPS, pkgid);
	_LOGD("#path of res.xml is %s", resxml);
	if (access(resxml, F_OK) != 0) {
		_LOGE("file not found. try other paths");
		memset(resxml, '\0', sizeof(resxml));
		snprintf(resxml, BUF_SIZE, "%s%s/%s/res/res.xml", TEMP_DIR, OPT_USR_APPS, pkgid);
		if (access(resxml, F_OK) != 0) {
			_LOGE("file not found");
			memset(resxml, '\0', sizeof(resxml));
		}
	}

	if (resxml[0] != '\0') {
		if (access(resxml, R_OK) == 0) {
			/* validate it */
			ret = pkgmgr_resource_parser_check_xml_validation(resxml);
			if (ret < 0) {
				_LOGE("pkgmgr_resource_parser_check_xml_validation(%s) failed.", resxml);
				ret = RPM_INSTALLER_ERR_INTERNAL;
				goto err;
			}
		}
	}

	/* chdir */
	ret = chdir(cwd);
	if (ret != 0) {
		if( strerror_r(errno, buf, sizeof(buf)) == 0) {
			_LOGE("@failed to change directory(%s)(%s)", cwd, buf);
		}
		ret = RPM_INSTALLER_ERR_INTERNAL;
		goto err;
	}
#ifdef APP2EXT_ENABLE
	ret = __get_location_from_xml(manifest, &location);
	if (ret < 0) {
		_LOGE("@Failed to get install location\n");
		ret = RPM_INSTALLER_ERR_INTERNAL;
		goto err;
	} else {
		if (location == PMINFO_INSTALL_LOCATION_PREFER_EXTERNAL) {
			_LOGD("#Install: external storage location");

			/* Get the rpm's size from rpm header */
			rpm_size = _ri_calculate_rpm_size(pkgfilepath);
			if (rpm_size != 0) {
				rpm_size = rpm_size / (1024 * 1024);	/* rpm size in MB */
				_LOGD("#Rpm file(%s) size is %lu MB", pkgfilepath, rpm_size);

				/* Add margin to the rpm size */
				rpm_size = rpm_size + RPM_SIZE_MARGIN(rpm_size);
				_LOGD("#Rpm file (%s) size after margin is %lu MB", pkgfilepath, rpm_size);
			} else {
				_LOGE("@Failed to get size from rpm header\n");
				ret = RPM_INSTALLER_ERR_INTERNAL;
				goto err;
			}

			/* Get the size from the manifest file. */
			ret = __get_size_from_xml(manifest, &size);
			if (ret != PMINFO_R_OK) {
				size = rpm_size;
				_LOGD(" #rpm size is %d MB", size);
			} else {
				size = size > rpm_size ? size : rpm_size;
				_LOGD("#rpm size is %d MB", size);
			}
		}
	}

	if ((location == PMINFO_INSTALL_LOCATION_PREFER_EXTERNAL) && size > 0) {
		handle = app2ext_init(APP2EXT_SD_CARD);
		if (handle == NULL) {
			_LOGE("@app2ext init failed\n");
			ret = RPM_INSTALLER_ERR_INTERNAL;
			goto err;
		}
		if ((&(handle->interface) != NULL) && (handle->interface.pre_install != NULL)
			&& (handle->interface.post_install != NULL)) {
			dir_list = __rpm_populate_dir_list();
			if (dir_list == NULL) {
				_LOGE("@ \nError in populating the directory list\n");
				app2ext_deinit(handle);
				ret = RPM_INSTALLER_ERR_RPM_SCRIPT_WRONG_ARGS;
				goto err;
			}
			ret = handle->interface.pre_install(gpkgname, dir_list, size);
			if (ret == APP2EXT_ERROR_MMC_STATUS) {
				_LOGE("@app2xt MMC is not here, go internal\n");
			} else if (ret == APP2EXT_SUCCESS) {
				_LOGE("@pre_install done, go internal\n");
			} else {
				_LOGE("@app2xt pre install API failed (%d)\n", ret);
				__rpm_clear_dir_list(dir_list);
				handle->interface.post_install(gpkgname, APP2EXT_STATUS_FAILED);
				app2ext_deinit(handle);
				ret = RPM_INSTALLER_ERR_INTERNAL;
				goto err;
			}
		}
	}
#endif

	/* run script */
	if (home_dir == 0) {
#if 0
		/* disable "INSTALL_SCRIPT_WITH_DBPATH_RO", because of some bug */
		const char *argv[] = { INSTALL_SCRIPT_WITH_DBPATH_RO, pkgfilepath, NULL };
		ret = _ri_xsystem(argv);
#endif
		const char *argv[] = { INSTALL_SCRIPT, pkgfilepath, NULL };
		ret = _ri_xsystem(argv);
	} else {
		const char *argv[] = { INSTALL_SCRIPT_WITH_DBPATH_RW, pkgfilepath, NULL };
		ret = _ri_xsystem(argv);
	}
	if (ret != 0) {
		_LOGE("@failed to install the pkg(%d).", ret);
#ifdef APP2EXT_ENABLE
		if ((handle != NULL) && (handle->interface.post_install != NULL)) {
			__rpm_clear_dir_list(dir_list);
			handle->interface.post_install(gpkgname, APP2EXT_STATUS_FAILED);
			app2ext_deinit(handle);
		}
#endif
		goto err;
	}
	_LOGD("#install success.");

	/* check for signature and certificate */
	ret = _ri_verify_signatures(TEMP_DIR, pkgid, true);
	if (ret < 0) {
		_LOGE("@signature and certificate failed(%s).", pkgid);
		ret = RPM_INSTALLER_ERR_SIG_INVALID;
		goto err;
	}
	_LOGD("#_ri_verify_signatures success.");

	/* write the storeclient-id to manifest.xml */
	if (clientid != NULL) {
		if (home_dir == 0) {
			snprintf(resultxml, BUF_SIZE, "%s/%s.xml", USR_SHARE_PACKAGES, pkgid);
		} else {
			snprintf(resultxml, BUF_SIZE, "%s/%s.xml", OPT_SHARE_PACKAGES, pkgid);
		}

		const char *convert_argv[] = { RPM_UPDATE_XML, manifest, clientid, resultxml, NULL };
		ret = _ri_xsystem(convert_argv);
		if (ret != 0) {
			_LOGE("@Failed to convert the manifest.xml");
			goto err;
		}

		_LOGD("#client id[%s], input manifest:[%s], dest manifest:[%s]", clientid, manifest, resultxml);
	}

	/* send event for install_percent */
	_ri_broadcast_status_notification(pkgid, PKGTYPE_RPM, "install_percent", "60");

	/* Parse the manifest to get install location and size.
	   If installation fails, remove manifest info from DB */
	if (clientid != NULL) {
		ret = pkgmgr_parser_parse_manifest_for_installation(resultxml, NULL);
	} else {
		ret = pkgmgr_parser_parse_manifest_for_installation(manifest, NULL);
	}
	if (ret < 0) {
		_LOGE("@failed to parse the manifest.");
		ret = RPM_INSTALLER_ERR_INTERNAL;
		goto err;
	}
	_LOGD("#manifest parsing success");

#ifdef APP2EXT_ENABLE
	if ((handle != NULL) && (handle->interface.post_install != NULL)) {
		__rpm_clear_dir_list(dir_list);
		handle->interface.post_install(gpkgname, APP2EXT_STATUS_SUCCESS);
		app2ext_deinit(handle);
	}
#endif
	/* register cert info */
	_ri_register_cert(pkgid);

	/* search_ug_app */
	_coretpk_installer_search_ui_gadget(pkgid);

	/* apply smack to shared dir */
	ret = __get_smack_label_from_db(pkgid, &smack_label);
	_LOGD("smack_label[%s], ret[%d]\n", smack_label, ret);

	__rpm_apply_smack(pkgid, 1, smack_label);

	/* apply smack by privilege */
	ret = _ri_apply_privilege(pkgid, 0, smack_label);
	if (ret != 0) {
		_LOGE("@failed to apply permission(%d).", ret);
	}
	_LOGD("#permission applying success.");

	/* reload smack */
	ret = _ri_smack_reload_all();
	if (ret != 0) {
		_LOGD("@failed to reload_all the smack.");
	}

	/* send event for install_percent */
	_ri_broadcast_status_notification(pkgid, PKGTYPE_RPM, "install_percent", "100");

	ret = RPM_INSTALLER_SUCCESS;

err:
	_installer_util_delete_dir(TEMP_DIR);
	_installer_util_delete_dir(TEMP_DBPATH);

	if (ret == RPM_INSTALLER_SUCCESS) {
		_LOGD("[#]end : _rpm_install_pkg_with_dbpath");
		__ri_launch_consumer(pkgid);
		_ri_broadcast_status_notification(pkgid, PKGTYPE_RPM, "end", "ok");
		_ri_stat_cb(pkgid, "end", "ok");
	} else {
		_LOGE("[@]end : _rpm_install_pkg_with_dbpath");
		/* remove db info */
		ret = _coretpk_installer_remove_db_info(pkgid);
		if (ret < 0) {
			_LOGE("_coretpk_installer_remove_db_info is failed.");
		}

		char *errstr = NULL;
		_ri_error_no_to_string(ret, &errstr);
		_ri_broadcast_status_notification(pkgid, PKGTYPE_RPM, "error", errstr);
		_ri_stat_cb(pkgid, "error", errstr);
		_ri_broadcast_status_notification(pkgid, PKGTYPE_RPM, "end", "fail");
		sleep(2);
		_ri_stat_cb(pkgid, "end", "fail");
		_LOGE("install failed with err(%d) (%s)\n", ret, errstr);
	}

	FREE_AND_NULL(smack_label);

	return ret;
}

int _rpm_upgrade_pkg_with_dbpath(char *pkgfilepath, char *pkgid)
{
	int ret = 0;
	char manifest[BUF_SIZE] = { '\0' };
	char cwd[BUF_SIZE] = { '\0' };
	int home_dir = 0;
	pkgmgrinfo_pkginfo_h pkghandle;
	char *temp = NULL;
#ifdef APP2EXT_ENABLE
	app2ext_handle *handle = NULL;
	GList *dir_list = NULL;
	pkgmgrinfo_installed_storage location = 1;
	int size = -1;
	unsigned long rpm_size = 0;
#endif
	char *smack_label = NULL;
	char resxml[BUF_SIZE] = { '\0' };
	char buf[BUF_SIZE] = { 0, };

	_ri_broadcast_status_notification(pkgid, PKGTYPE_RPM, "start", "update");
	_LOGD("[#]start : _rpm_upgrade_pkg_with_dbpath");

	/* terminate running app */
	ret = pkgmgrinfo_pkginfo_get_pkginfo(pkgid, &pkghandle);
	if (ret < 0) {
		_LOGE("@failed to get pkginfo handle");
		ret = RPM_INSTALLER_ERR_PKG_NOT_FOUND;
		goto err;
	}
	pkgmgrinfo_appinfo_get_list(pkghandle, PM_UI_APP, __ri_check_running_app, NULL);
	pkgmgrinfo_pkginfo_destroy_pkginfo(pkghandle);

	/* getcwd */
	temp = getcwd(cwd, BUF_SIZE);
	if ((temp == NULL) || (cwd[0] == '\0')) {
		_LOGE("@getcwd() failed.");
		ret = RPM_INSTALLER_ERR_INTERNAL;
		goto err;
	}
	_LOGD("#current working directory is %s.", cwd);

	/* change dir */
	ret = __ri_change_dir(TEMP_DIR);
	if (ret == -1) {
		_LOGE("@change dir failed.");
		ret = RPM_INSTALLER_ERR_INTERNAL;
		goto err;
	}
	_LOGD("#switched to %s", TEMP_DIR);

	/* run cpio script */
	const char *cpio_argv[] = { CPIO_SCRIPT, pkgfilepath, NULL };
	ret = _ri_xsystem(cpio_argv);

	/* get manifext.xml path */
	snprintf(manifest, BUF_SIZE, "%s%s/%s.xml", TEMP_DIR, OPT_SHARE_PACKAGES, pkgid);
	_LOGD("#manifest name is %s.", manifest);

	if (access(manifest, F_OK)) {
		_LOGD("#there is no RW manifest.xml. check RO manifest.xml.");

		memset(manifest, '\0', sizeof(manifest));
		snprintf(manifest, BUF_SIZE, "%s%s/%s.xml", TEMP_DIR, USR_SHARE_PACKAGES, pkgid);
		_LOGD("#manifest name is %s.", manifest);

		if (access(manifest, F_OK)) {
			_LOGE("@can not find manifest.xml in the pkg.");
			ret = RPM_INSTALLER_ERR_NO_MANIFEST;
			goto err;
		} else {
			home_dir = 0;
		}

#if 0
		/* disable "copy ro-xml to rw-xml", because of some bug */
		snprintf(srcpath, BUF_SIZE, "%s", manifest);
		memset(manifest, '\0', sizeof(manifest));
		snprintf(manifest, BUF_SIZE, "%s/%s.xml", OPT_SHARE_PACKAGES, pkgid);

		const char *xml_update_argv[] = { CPIO_SCRIPT_UPDATE_XML, srcpath, manifest, NULL };
		ret = _ri_xsystem(xml_update_argv);
#endif
	} else {
		home_dir = 1;
	}

	/* check existance of res.xml for resource manager */
	snprintf(resxml, BUF_SIZE, "%s%s/%s/res/res.xml", TEMP_DIR, USR_APPS, pkgid);
	_LOGD("#path of res.xml is %s", resxml);
	if (access(resxml, F_OK) != 0) {
		_LOGE("file not found. try other paths");
		memset(resxml, '\0', sizeof(resxml));
		snprintf(resxml, BUF_SIZE, "%s%s/%s/res/res.xml", TEMP_DIR, OPT_USR_APPS, pkgid);
		if (access(resxml, F_OK) != 0) {
			_LOGE("file not found");
			memset(resxml, '\0', sizeof(resxml));
		}
	}

	if (resxml[0] != '\0') {
		if (access(resxml, R_OK) == 0) {
			/* validate it */
			ret = pkgmgr_resource_parser_check_xml_validation(resxml);
			if (ret < 0) {
				_LOGE("pkgmgr_resource_parser_check_xml_validation(%s) failed.", resxml);
				ret = RPM_INSTALLER_ERR_INTERNAL;
				goto err;
			}
		}
	}

	/* send event for install_percent */
	_ri_broadcast_status_notification(pkgid, PKGTYPE_RPM, "install_percent", "30");

	/* check manifest.xml validation */
	ret = pkgmgr_parser_check_manifest_validation(manifest);
	if (ret < 0) {
		_LOGE("@invalid manifest");
		ret = RPM_INSTALLER_ERR_INVALID_MANIFEST;
		goto err;
	}

	/* check for signature and certificate */
	ret = _ri_verify_signatures(TEMP_DIR, pkgid, true);
	if (ret < 0) {
		_LOGE("@signature and certificate failed(%s).", pkgid);
		ret = RPM_INSTALLER_ERR_SIG_INVALID;
		goto err;
	}
	_LOGD("#_ri_verify_signatures success.");

	/* chdir */
	ret = chdir(cwd);
	if (ret != 0) {
		if( strerror_r(errno, buf, sizeof(buf)) == 0) {
			_LOGE("@chdir(%s) failed(%s).", cwd, buf);
		}
		ret = RPM_INSTALLER_ERR_INTERNAL;
		goto err;
	}

	/* remove dir for clean */
	__ri_remove_updated_dir(pkgid);

	_LOGD("#Preserve the smack file");
	/* Preserve the smack rule file */
	ret = __ri_copy_smack_rule_file(UPGRADE_REQ, pkgid, 0);
	if (ret != RPM_INSTALLER_SUCCESS)
		goto err;

#ifdef APP2EXT_ENABLE
	ret = pkgmgrinfo_pkginfo_get_pkginfo(gpkgname, &pkghandle);
	if (ret < 0) {
		_LOGE("Failed to get pkginfo handle\n");
		ret = RPM_INSTALLER_ERR_PKG_NOT_FOUND;
		goto err;
	}

	ret = pkgmgrinfo_pkginfo_get_installed_storage(pkghandle, &location);
	if (ret < 0) {
		_LOGE("Failed to get install location\n");
		pkgmgrinfo_pkginfo_destroy_pkginfo(pkghandle);
		ret = RPM_INSTALLER_ERR_INTERNAL;
		goto err;
	}

	if (location == PMINFO_EXTERNAL_STORAGE) {
		/* Get the rpm's size from rpm header */
		rpm_size = _ri_calculate_rpm_size(pkgfilepath);
		if (rpm_size == 0) {
			_LOGE("@Failed to get size from rpm header\n");
			ret = RPM_INSTALLER_ERR_INTERNAL;
			goto err;
		}
		rpm_size = rpm_size / (1024 * 1024);	/* rpm size in MB */
		_LOGD("#Rpm file(%s) size is %lu MB", pkgfilepath, rpm_size);

		/* Add margin to the rpm size */
		rpm_size = rpm_size + RPM_SIZE_MARGIN(rpm_size);
		_LOGD("#Rpm file (%s) size after margin is %lu MB", pkgfilepath, rpm_size);

		/* Get the size from the manifest file. */
		ret = __get_size_from_xml(manifest, &size);
		if (ret != PMINFO_R_OK) {
			size = rpm_size;
			_LOGD(" #rpm size is %d", size);
		} else {
			size = size > rpm_size ? size : rpm_size;
			_LOGD("#rpm size is %d", size);
		}
	}

	pkgmgrinfo_pkginfo_destroy_pkginfo(pkghandle);

	if ((location == PMINFO_EXTERNAL_STORAGE) && size > 0) {
		handle = app2ext_init(APP2EXT_SD_CARD);
		if (handle == NULL) {
			_LOGE("app2ext init failed\n");
			ret = RPM_INSTALLER_ERR_INTERNAL;
			goto err;
		}

		if ((&(handle->interface) != NULL) && (handle->interface.pre_upgrade != NULL)
			&& (handle->interface.post_upgrade != NULL)) {
			dir_list = __rpm_populate_dir_list();
			if (dir_list == NULL) {
				_LOGE("\nError in populating the directory list\n");
				ret = RPM_INSTALLER_ERR_RPM_SCRIPT_WRONG_ARGS;
				app2ext_deinit(handle);
				goto err;
			}
			ret = handle->interface.pre_upgrade(gpkgname, dir_list, size);
			if (ret == APP2EXT_ERROR_MMC_STATUS) {
				_LOGE("app2xt MMC is not here, go internal (%d)\n", ret);
			} else if (ret == APP2EXT_SUCCESS) {
				_LOGE("pre upgrade done, go internal");
			} else {
				_LOGE("app2xt pre upgrade API failed (%d)\n", ret);
				__rpm_clear_dir_list(dir_list);
				handle->interface.post_upgrade(gpkgname, APP2EXT_STATUS_FAILED);
				ret = RPM_INSTALLER_ERR_INTERNAL;
				app2ext_deinit(handle);
				goto err;
			}
		}
	}
#endif

	/* run script */
	if (home_dir == 0) {
#if 0
		/* disable "UPGRADE_SCRIPT_WITH_DBPATH_RO", because of some bug */
		const char *argv[] = { UPGRADE_SCRIPT_WITH_DBPATH_RO, pkgfilepath, NULL };
		ret = _ri_xsystem(argv);
#endif
		const char *argv[] = { UPGRADE_SCRIPT, pkgfilepath, NULL };
		ret = _ri_xsystem(argv);
	} else {
		const char *argv[] = { UPGRADE_SCRIPT_WITH_DBPATH_RW, pkgfilepath, NULL };
		ret = _ri_xsystem(argv);
	}
	if (ret != 0) {
		_LOGE("@upgrade complete with error(%d)", ret);
#ifdef APP2EXT_ENABLE
		if ((handle != NULL) && (handle->interface.post_upgrade != NULL)) {
			__rpm_clear_dir_list(dir_list);
			handle->interface.post_upgrade(gpkgname, APP2EXT_STATUS_FAILED);
			app2ext_deinit(handle);
		}
#endif
		goto err;
	}
	_LOGD("#upgrade script success.");

	/* send event for install_percent */
	_ri_broadcast_status_notification(pkgid, PKGTYPE_RPM, "install_percent", "60");

	/* Parse the manifest to get install location and size.
	   If fails, remove manifest info from DB. */
	ret = pkgmgr_parser_parse_manifest_for_upgrade(manifest, NULL);
	if (ret < 0) {
		_LOGE("@parsing manifest failed.");
		ret = RPM_INSTALLER_ERR_INTERNAL;
		goto err;
	}
	_LOGD("#parsing manifest success.");

	/* unregister cert info */
	_ri_unregister_cert(pkgid);

	/* register cert info */
	_ri_register_cert(pkgid);

#ifdef APP2EXT_ENABLE
	if ((handle != NULL) && (handle->interface.post_upgrade != NULL)) {
		__rpm_clear_dir_list(dir_list);
		handle->interface.post_upgrade(gpkgname, APP2EXT_STATUS_SUCCESS);
		app2ext_deinit(handle);
	}
#endif

	/* search_ug_app */
	_coretpk_installer_search_ui_gadget(pkgid);

	/* apply smack to shared dir */
	ret = __get_smack_label_from_db(pkgid, &smack_label);
	_LOGD("smack_label[%s], ret[%d]\n", smack_label, ret);

	__rpm_apply_smack(pkgid, 1, smack_label);

	/* apply smack by privilege */
	ret = _ri_apply_privilege(pkgid, 0, smack_label);
	if (ret != 0) {
		_LOGE("@apply perm failed with err(%d)", ret);
	}
	_LOGD("#apply perm success.");

	/* reload smack */
	ret = _ri_smack_reload_all();
	if (ret != 0) {
		_LOGD("_ri_smack_reload_all failed.");
	}

	/* send event for install_percent */
	_ri_broadcast_status_notification(pkgid, PKGTYPE_RPM, "install_percent", "100");

	ret = RPM_INSTALLER_SUCCESS;

err:
	_installer_util_delete_dir(TEMP_DIR);
	_installer_util_delete_dir(TEMP_DBPATH);

	if (ret == RPM_INSTALLER_SUCCESS) {
		_LOGD("[#]end : _rpm_upgrade_pkg_with_dbpath");
		__ri_launch_consumer(pkgid);
		_ri_broadcast_status_notification(pkgid, PKGTYPE_RPM, "end", "ok");
		_ri_stat_cb(pkgid, "end", "ok");
	} else {
		_LOGE("[@]end : _rpm_upgrade_pkg_with_dbpath");
		char *errstr = NULL;
		_ri_error_no_to_string(ret, &errstr);
		_ri_broadcast_status_notification(pkgid, PKGTYPE_RPM, "error", errstr);
		_ri_stat_cb(pkgid, "error", errstr);
		_ri_broadcast_status_notification(pkgid, PKGTYPE_RPM, "end", "fail");
		sleep(2);
		_ri_stat_cb(pkgid, "end", "fail");
		_LOGE("install failed with err(%d) (%s)\n", ret, errstr);
	}

	FREE_AND_NULL(smack_label);

	return ret;
}

int _rpm_uninstall_pkg_with_dbpath(const char *pkgid, bool is_system)
{
	if (pkgid == NULL) {
		_LOGE("pkgid is NULL.");
		return RPM_INSTALLER_ERR_WRONG_PARAM;
	}

	int ret = 0;
	int tmp = 0;
	char buff[BUF_SIZE] = { '\0' };
	char extpath[BUF_SIZE] = { '\0' };
	char tizen_manifest[BUF_SIZE] = { '\0' };
	pkgmgrinfo_pkginfo_h pkghandle = NULL;
	bool mother_package = false;
	bool coretpk = false;
	GList *appid_list = NULL;

#ifdef APP2EXT_ENABLE
	app2ext_handle *handle = NULL;
	pkgmgrinfo_installed_storage location = 1;
#endif
	char *smack_label = NULL;

	_LOGD("pkgid=[%s], is_system=[%d]", pkgid, is_system);

	snprintf(tizen_manifest, BUF_SIZE, "%s/%s/tizen-manifest.xml", OPT_USR_APPS, pkgid);
	if (access(tizen_manifest, R_OK) == 0) {
		coretpk = true;
		_LOGD("[%s] is existing.", tizen_manifest);
	}

	/* send start event */
	if (is_system) {
		_ri_broadcast_status_notification(pkgid, coretpk ? PKGTYPE_TPK : PKGTYPE_RPM, "start", "update");
	} else {
		_ri_broadcast_status_notification(pkgid, coretpk ? PKGTYPE_TPK : PKGTYPE_RPM, "start", "uninstall");
	}

	/* terminate running app */
	ret = pkgmgrinfo_pkginfo_get_pkginfo(pkgid, &pkghandle);
	if (ret < 0) {
		_LOGE("pkgmgrinfo_pkginfo_get_pkginfo(%s) failed.", pkgid);
		ret = RPM_INSTALLER_ERR_PKG_NOT_FOUND;
		goto end;
	}
	pkgmgrinfo_appinfo_get_list(pkghandle, PM_UI_APP, __ri_check_running_app, &appid_list);

	while (appid_list != NULL) {
		_ri_broadcast_app_uninstall_notification(pkgid, coretpk ? PKGTYPE_TPK : PKGTYPE_RPM, (char *)appid_list->data);

		if (appid_list->next == NULL)
			break;
		else
			appid_list = g_list_next(appid_list);
	}

	/* If package is mother package, then uninstall child package */
	pkgmgrinfo_pkginfo_is_mother_package(pkghandle, &mother_package);
	if (mother_package == true) {
		_LOGD("[%s] is mother package", pkgid);
		__uninstall_child_package_by_mother_pkgid(pkgid);
	}
	pkgmgrinfo_pkginfo_destroy_pkginfo(pkghandle);

	ret = __get_smack_label_from_db(pkgid, &smack_label);
	_LOGD("smack_label[%s], ret[%d]\n", smack_label, ret);

	/* del root path dir */
	snprintf(buff, BUF_SIZE, "%s/%s", OPT_USR_APPS, pkgid);
	if (__is_dir(buff)) {
		_installer_util_delete_dir(buff);
	}

	/* del root path dir for ext */
	snprintf(extpath, BUF_SIZE, "%s/%s", OPT_STORAGE_SDCARD_APP_ROOT, pkgid);
	if (__is_dir(extpath)) {
		_installer_util_delete_dir(extpath);
	}

	/* del manifest */
	memset(buff, '\0', BUF_SIZE);
	snprintf(buff, BUF_SIZE, "%s/%s.xml", OPT_SHARE_PACKAGES, pkgid);
	(void)remove(buff);

	/* check system pkg, if pkg is system pkg, need to update xml on USR_SHARE_PACKAGES */
	if (is_system) {
		memset(buff, '\0', BUF_SIZE);
		snprintf(buff, BUF_SIZE, "%s/%s.xml", USR_SHARE_PACKAGES, pkgid);
		_LOGE("manifest for upgrade, path=[%s]", buff);

		ret = pkgmgr_parser_parse_manifest_for_upgrade(buff, NULL);
		if (ret < 0) {
			_LOGE("parsing manifest failed.");
		}
		goto end;
	} else {
#ifdef APP2EXT_ENABLE
		ret = pkgmgrinfo_pkginfo_get_pkginfo(pkgid, &pkghandle);
		if (ret < 0) {
			_LOGE("failed to get pkginfo handle");
			ret = RPM_INSTALLER_ERR_PKG_NOT_FOUND;
			goto end;
		}
		ret = pkgmgrinfo_pkginfo_get_installed_storage(pkghandle, &location);
		if (ret < 0) {
			_LOGE("failed to get install location\n");
			pkgmgrinfo_pkginfo_destroy_pkginfo(pkghandle);
			ret = RPM_INSTALLER_ERR_INTERNAL;
			goto end;
		}
		pkgmgrinfo_pkginfo_destroy_pkginfo(pkghandle);

		if (location == PMINFO_EXTERNAL_STORAGE) {
			handle = app2ext_init(APP2EXT_SD_CARD);
			if (handle == NULL) {
				_LOGE("app2ext init failed\n");
				ret = RPM_INSTALLER_ERR_INTERNAL;
				goto end;
			}
			if ((&(handle->interface) != NULL) && (handle->interface.pre_uninstall != NULL) &&
				(handle->interface.post_uninstall != NULL) &&
				(handle->interface.disable != NULL)) {
				ret = handle->interface.disable(pkgid);
				if (ret != APP2EXT_SUCCESS) {
					_LOGE("Unmount ret[%d]", ret);
				}
				ret = app2ext_get_app_location(pkgid);
				if (ret == APP2EXT_INTERNAL_MEM) {
					_LOGE("app2xt APP is not in MMC, go internal (%d)\n", ret);
				} else {
					ret = handle->interface.pre_uninstall(pkgid);
					if (ret == APP2EXT_ERROR_MMC_STATUS) {
						_LOGE("app2xt MMC is not here, go internal (%d)\n", ret);
					} else if (ret == APP2EXT_SUCCESS) {
						_LOGE("pre uninstall done, go to internal");
					} else {
						_LOGE("app2xt pre uninstall API failed (%d)\n", ret);
						handle->interface.post_uninstall(pkgid);
						app2ext_deinit(handle);
						ret = RPM_INSTALLER_ERR_INTERNAL;
						goto end;
					}
				}
			}
		}
#endif

		/* del db info */
		ret = pkgmgr_parser_parse_manifest_for_uninstallation(pkgid, NULL);
		if (ret < 0) {
			_LOGE("pkgmgr_parser_parse_manifest_for_uninstallation() failed, pkgid=[%s]", pkgid);
		}

#ifdef APP2EXT_ENABLE
		if ((handle != NULL) && (handle->interface.post_uninstall != NULL)) {
			handle->interface.post_uninstall(pkgid);
			app2ext_deinit(handle);
		}
#endif
	}

	/* execute privilege APIs */
	_ri_privilege_revoke_permissions(smack_label);
	_ri_privilege_unregister_package(smack_label);

	/* Unregister cert info */
	_ri_unregister_cert(pkgid);

	ret = RPM_INSTALLER_SUCCESS;

end:
	/* Free appid list */
	appid_list = g_list_first(appid_list);
	while (appid_list != NULL) {
		if (appid_list->data != NULL) {
			free(appid_list->data);
		}

		if (appid_list->next == NULL)
			break;
		else
			appid_list = g_list_next(appid_list);
	}
	g_list_free(appid_list);

	/* Restore the old smack file */
	if (coretpk == false) {
		tmp = __ri_copy_smack_rule_file(UNINSTALL_REQ, pkgid, is_system);
		if (tmp != RPM_INSTALLER_SUCCESS) {
			_LOGD("smack restore failed");
			ret = tmp;
		} else {
			/*reload smack */
			tmp = _ri_smack_reload_all();
			if (tmp != 0) {
				_LOGD("_ri_smack_reload_all failed.");
				ret = tmp;
			}
		}
	}

	if (ret != 0) {
		_LOGE("failed, ret=[%d]", ret);
		char *errstr = NULL;
		_ri_error_no_to_string(ret, &errstr);
		_ri_broadcast_status_notification(pkgid, coretpk ? PKGTYPE_TPK : PKGTYPE_RPM, "error", errstr);
		_ri_stat_cb(pkgid, "error", errstr);
		sleep(2);
		_ri_broadcast_status_notification(pkgid, coretpk ? PKGTYPE_TPK : PKGTYPE_RPM, "end", "fail");
		_ri_stat_cb(pkgid, "end", "fail");
		_LOGE("remove failed with err(%d) (%s)\n", ret, errstr);
	} else {
		_LOGE("success");
		_ri_broadcast_status_notification(pkgid, coretpk ? PKGTYPE_TPK : PKGTYPE_RPM, "end", "ok");
		_ri_stat_cb(pkgid, "end", "ok");
	}

	FREE_AND_NULL(smack_label);

	return ret;
}

int _rpm_uninstall_pkg(char *pkgid)
{
	int ret = 0;
	bool is_update = 0;
	bool is_system = 0;
	bool is_removable = 0;
	pkgmgrinfo_install_location location = 1;
#ifdef APP2EXT_ENABLE
	app2ext_handle *handle = NULL;
#endif
#ifdef PRE_CHECK_FOR_MANIFEST
	char *manifest = NULL;
	int err = 0;
#endif
	char *smack_label = NULL;

	pkgmgrinfo_pkginfo_h pkghandle;
	const char *argv[] = { UNINSTALL_SCRIPT, pkgid, NULL };

	_LOGD("start : _rpm_uninstall_pkg\n");

	ret = pkgmgrinfo_pkginfo_get_pkginfo(pkgid, &pkghandle);
	if (ret < 0) {
		_LOGE("Failed to get pkginfo handle\n");
		return RPM_INSTALLER_ERR_PKG_NOT_FOUND;
	}
	/* terminate running app */
	pkgmgrinfo_appinfo_get_list(pkghandle, PM_UI_APP, __ri_check_running_app, NULL);

	ret = pkgmgrinfo_pkginfo_is_system(pkghandle, &is_system);
	if (ret < 0) {
		_LOGE("pkgmgrinfo_pkginfo_is_system failed.\n");
		return RPM_INSTALLER_ERR_INTERNAL;
	}
	if (is_system) {
		ret = pkgmgrinfo_pkginfo_is_update(pkghandle, &is_update);
		if (ret < 0) {
			_LOGE("pkgmgrinfo_pkginfo_is_system failed.\n");
			return RPM_INSTALLER_ERR_INTERNAL;
		}
		if (is_update) {
			pkgmgrinfo_pkginfo_destroy_pkginfo(pkghandle);
			/* updated and system pkg need to "remove-update" */
			_LOGD("Remove Update[%s]", pkgid);
			ret = _rpm_uninstall_pkg_with_dbpath(pkgid, 1);
			if (ret < 0) {
				_LOGE("uninstall_pkg_with_dbpath for system, is_update fail\n");
			}
			return 0;
		}
	} else {
		pkgmgrinfo_pkginfo_is_removable(pkghandle, &is_removable);
		if (is_removable) {
			/* non-system and can be removable,  it should be deleted */
			_LOGD("Delete Package [%s]", pkgid);
			pkgmgrinfo_pkginfo_destroy_pkginfo(pkghandle);
			ret = _rpm_uninstall_pkg_with_dbpath(pkgid, 0);
			if (ret < 0) {
				_LOGE("uninstall_pkg_with_dbpath for non-system, is_remove fail\n");
			}
			return 0;
		}
	}

	_ri_broadcast_status_notification(pkgid, PKGTYPE_RPM, "start", "uninstall");

#ifdef APP2EXT_ENABLE
	ret = pkgmgrinfo_pkginfo_get_install_location(pkghandle, &location);
	if (ret < 0) {
		_LOGE("Failed to get install location\n");
		pkgmgrinfo_pkginfo_destroy_pkginfo(pkghandle);
		return RPM_INSTALLER_ERR_INTERNAL;
	}

	pkgmgrinfo_appinfo_get_list(pkghandle, PM_UI_APP, __ri_check_running_app, NULL);

	pkgmgrinfo_pkginfo_destroy_pkginfo(pkghandle);
	if (location == PMINFO_INSTALL_LOCATION_PREFER_EXTERNAL) {
		handle = app2ext_init(APP2EXT_SD_CARD);
		if (handle == NULL) {
			_LOGE("app2ext init failed\n");
			return RPM_INSTALLER_ERR_INTERNAL;
		}
		if ((&(handle->interface) != NULL) && (handle->interface.pre_uninstall != NULL) &&
			(handle->interface.post_uninstall != NULL)) {
			ret = app2ext_get_app_location(pkgid);
			if (ret == APP2EXT_INTERNAL_MEM) {
				_LOGE("app2xt APP is not in MMC, go internal (%d)\n", ret);
			} else {
				ret = handle->interface.pre_uninstall(pkgid);
				if (ret == APP2EXT_ERROR_MMC_STATUS || ret == APP2EXT_SUCCESS) {
					_LOGE("app2xt MMC is not here, go internal (%d)\n", ret);
				} else {
					_LOGE("app2xt pre uninstall API failed (%d)\n", ret);
					handle->interface.post_uninstall(pkgid);
					app2ext_deinit(handle);
					return RPM_INSTALLER_ERR_INTERNAL;
				}
			}
		}
	}
#endif

	ret = __get_smack_label_from_db(pkgid, &smack_label);
	_LOGD("smack_label[%s], ret[%d]\n", smack_label, ret);

#ifdef PRE_CHECK_FOR_MANIFEST
	/* Manifest info should be removed first because after installation manifest
	   file is uninstalled. If uninstallation fails, we need to re-insert manifest info for consistency */
	manifest = pkgmgr_parser_get_manifest_file(pkgid);
	if (manifest == NULL) {
		_LOGE("manifest name is NULL\n");
		app2ext_deinit(handle);
		FREE_AND_NULL(smack_label);
		return RPM_INSTALLER_ERR_NO_MANIFEST;
	}
	_LOGD("manifest name is %s\n", manifest);
	ret = pkgmgr_parser_parse_manifest_for_uninstallation(manifest, NULL);
	if (ret < 0) {
		_LOGE("pkgmgr_parser_parse_manifest_for_uninstallation failed.\n");
	}
#endif

	ret = _rpm_xsystem(argv);
	if (ret != 0) {
		_LOGE("uninstall failed with error(%d)\n", ret);
#ifdef PRE_CHECK_FOR_MANIFEST
		err = pkgmgr_parser_parse_manifest_for_installation(manifest, NULL);
		if (err < 0) {
			_LOGE("Parsing Manifest Failed\n");
		}

		FREE_AND_NULL(manifest);
#endif
#ifdef APP2EXT_ENABLE
		if ((handle != NULL) && (handle->interface.post_uninstall != NULL)) {
			handle->interface.post_uninstall(pkgid);
			app2ext_deinit(handle);
		}
#endif

		FREE_AND_NULL(smack_label);

		return ret;
	}
#ifdef APP2EXT_ENABLE
	if ((handle != NULL) && (handle->interface.post_uninstall != NULL)) {
		handle->interface.post_uninstall(pkgid);
		app2ext_deinit(handle);
	}
#endif

	/* execute privilege APIs */
	_ri_privilege_revoke_permissions(smack_label);
	_ri_privilege_unregister_package(smack_label);

	/* Unregister cert info */
	_ri_unregister_cert(gpkgname);

	FREE_AND_NULL(manifest);
	FREE_AND_NULL(smack_label);

	_LOGD("end : _rpm_uninstall_pkg(%d)\n", ret);

	return ret;
}

int _rpm_install_corexml(const char *pkgfilepath, char *pkgid)
{
	int ret = 0;

	/* validate signature and certifictae */
	ret = _ri_verify_signatures(USR_APPS, pkgid, true);
	if (ret < 0) {
		_LOGE("_ri_verify_signatures Failed : %s\n", pkgid);
		ret = RPM_INSTALLER_ERR_SIG_INVALID;
		goto err;
	}

	/* Parse and insert manifest in DB */
	ret = pkgmgr_parser_parse_manifest_for_installation(pkgfilepath, NULL);
	if (ret < 0) {
		_LOGD("Installing Manifest Failed : %s\n", pkgfilepath);
		ret = RPM_INSTALLER_ERR_PACKAGE_NOT_INSTALLED;
		goto err;
	}

	/* _ri_register_cert has __ri_free_cert_chain. */
	_ri_register_cert(pkgid);

	/* search_ug_app */
	_coretpk_installer_search_ui_gadget(pkgid);

	ret = RPM_INSTALLER_SUCCESS;

err:
	if (ret != 0) {
		__ri_free_cert_chain();
	}

	return ret;
}

int _rpm_move_pkg(char *pkgid, int move_type)
{
	app2ext_handle *hdl = NULL;
	int ret = 0;
	int movetype = -1;
	GList *dir_list = NULL;
	pkgmgrinfo_pkginfo_h pkghandle = NULL;

	if (move_type == PM_MOVE_TO_INTERNAL)
		movetype = APP2EXT_MOVE_TO_PHONE;
	else if (move_type == PM_MOVE_TO_SDCARD)
		movetype = APP2EXT_MOVE_TO_EXT;
	else
		return RPM_INSTALLER_ERR_WRONG_PARAM;

	ret = pkgmgrinfo_pkginfo_get_pkginfo(gpkgname, &pkghandle);
	if (ret < 0) {
		_LOGE("@failed to get the pkginfo handle!!");
		ret = RPM_INSTALLER_ERR_PKG_NOT_FOUND;
		return ret;
	}

	/* Terminate the running instance of app */
	pkgmgrinfo_appinfo_get_list(pkghandle, PM_UI_APP, __ri_check_running_app, NULL);
	pkgmgrinfo_pkginfo_destroy_pkginfo(pkghandle);
	hdl = app2ext_init(APP2EXT_SD_CARD);
	if ((hdl != NULL) && (hdl->interface.move != NULL)) {
		dir_list = __rpm_populate_dir_list();
		if (dir_list == NULL) {
			_LOGE("\nError in populating the directory list\n");
			return RPM_INSTALLER_ERR_RPM_SCRIPT_WRONG_ARGS;
		}
		ret = hdl->interface.move(pkgid, dir_list, movetype);
		__rpm_clear_dir_list(dir_list);
		if (ret != 0) {
			_LOGE("Failed to move app\n");
			return RPM_INSTALLER_ERR_INTERNAL;
		}
		app2ext_deinit(hdl);
		return RPM_INSTALLER_SUCCESS;
	} else {
		_LOGE("Failed to get app2ext handle\n");
		return RPM_INSTALLER_ERR_INTERNAL;
	}
}

int _rpm_process_cscxml(char *csc_script)
{
	int ret = 0;
	int op_type = 0;

	char *path_str = NULL;
	char *op_str = NULL;
	char *remove_str = NULL;
	char csc_str[BUF_SIZE] = { '\0' };
	snprintf(csc_str, BUF_SIZE - 1, "%s:", csc_script);

	/* get params from csc script */
	path_str = _installer_util_get_str(csc_str, TOKEN_PATH_STR);
	op_str = _installer_util_get_str(csc_str, TOKEN_OPERATION_STR);
	remove_str = _installer_util_get_str(csc_str, TOKEN_REMOVE_STR);
	if ((path_str == NULL) || (op_str == NULL) || (remove_str == NULL)) {
		_LOGE("csc-info : input param is null[%s, %s, %s]\n", path_str, op_str, remove_str);
		goto end;
	}
	_LOGD("csc-info : path=%s, op=%s, remove=%s\n", path_str, op_str, remove_str);

	/* get operation type */
	op_type = __ri_get_op_type(op_str);
	if (op_type < 0) {
		_LOGE("csc-info : operation error[%s, %s]\n", path_str, op_str);
		goto end;
	}

	switch (op_type) {
	case INSTALL_REQ:
		ret = __ri_install_csc(path_str, remove_str);
		break;

	case UPGRADE_REQ:
		ret = __ri_install_csc(path_str, remove_str);
		break;

	case UNINSTALL_REQ:
		ret = __ri_uninstall_csc(path_str);
		break;

	default:
		break;
	}

	if (ret < 0)
		_LOGE("fota-info : Fota fail [pkgid=%s, operation=%d]\n", path_str, op_type);

end:
	if (path_str)
		free(path_str);
	if (op_str)
		free(op_str);
	if (remove_str)
		free(remove_str);

	return ret;
}

int __ri_copy_smack_rule_file(int op, const char *pkgname, int is_system)
{
	mode_t mode = DIR_PERMS;
	int ret = RPM_INSTALLER_SUCCESS;
	char src[BUF_SIZE] = { 0 };
	char dest[BUF_SIZE] = { 0 };
	char buf[BUF_SIZE] = { 0, };

	switch (op) {
	case UNINSTALL_REQ:
		/* For downloadable native app, restore the smack file.
		   Otherwise, remove the stored smack file. */
		snprintf(dest, BUF_SIZE - 1, "%s/%s.rule", SMACK_RULES_ALT_PATH, pkgname);
		snprintf(src, BUF_SIZE - 1, "%s%s.rule", DIR_RPM_WGT_SMACK_RULE_OPT, pkgname);
		_LOGD("#src:[%s] dest:[%s]", src, dest);

		if (!is_system) {
			if (!access(src, F_OK)) {
				ret = remove(src);
				if (!ret) {
					_LOGD("#File [%s] deleted.", src);
				} else {
					if( strerror_r(errno, buf, sizeof(buf)) == 0) {
						_LOGE("@Unable to delete the file [%s], error:(%s)", src, buf);
					}
					ret = RPM_INSTALLER_ERR_INTERNAL;
					goto end;
				}
			}
			if (!access(dest, F_OK)) {
				ret = remove(dest);
				if (!ret) {
					_LOGD("#File [%s] deleted.", dest);
				} else {
					if( strerror_r(errno, buf, sizeof(buf)) == 0) {
						_LOGE("@Unable to delete the file [%s], error:(%s)", dest, buf);
					}
					ret = RPM_INSTALLER_ERR_INTERNAL;
					goto end;
				}
			}
		} else {
			_LOGD("#Restore smack files for uninstallation [%s]", pkgname);
			if (!access(src, F_OK)) {
				_LOGD("#Copying [%s] to [%s]", src, dest);
				ret = __copy_file(src, dest);
				if (!ret) {
					ret = remove(src);
					if (!ret) {
						_LOGD("#File [%s] deleted.", src);
					} else {
						if( strerror_r(errno, buf, sizeof(buf)) == 0) {
							_LOGE("@Unable to delete the file [%s], error:(%s)", src, buf);
						}
						ret = RPM_INSTALLER_ERR_INTERNAL;
						goto end;
					}
				} else {
					_LOGE("@Copy Failed!!");
					ret = RPM_INSTALLER_ERR_INTERNAL;
					goto end;
				}
			} else {
				_LOGE("@ %s.rule file is not preserved", pkgname);
			}
		}
		break;
	case UPGRADE_REQ:
		_LOGD("#Preserve the smack file for upgrade [%s]", pkgname);

		/* Apply the new smack file and preserve the old smack rule file
		   if it is not preserved. */
		snprintf(src, BUF_SIZE - 1, "%s/%s.rule", SMACK_RULES_ALT_PATH, pkgname);
		snprintf(dest, BUF_SIZE - 1, "%s%s.rule", DIR_RPM_WGT_SMACK_RULE_OPT, pkgname);

		_LOGD("#src[%s] dest[%s]", src, dest);

		/* Create the directory if not exist to preserve the smack files */
		if (mkdir(DIR_RPM_WGT_SMACK_RULE_OPT, mode) == 0 || errno == EEXIST) {
			if ((access(src, F_OK) == 0) && (access(dest, F_OK) != 0)) {
				ret = __copy_file(src, dest);
			} else {
				_LOGD("#Smack file is already preserved");
			}
		} else {
			_LOGE("@Temporary folder creation failed");
			ret = RPM_INSTALLER_ERR_INTERNAL;
		}
		break;
	default:
		_LOGE("@Unsupported Operation\n");
		ret = RPM_INSTALLER_ERR_INTERNAL;
	}
 end:
	return ret;
}

int __get_smack_label_from_xml(const char *manifest, const char *pkgid, char **label)
{
	const char *val = NULL;
	char pkgpath[BUF_SIZE] = { '\0' };
	const xmlChar *node;
	xmlTextReaderPtr reader;
	int ret = PMINFO_R_OK;

	if (label == NULL) {
		_LOGE("space for label is NULL\n");
		return PMINFO_R_ERROR;
	}

	*label = NULL;

	if (pkgid == NULL) {
		_LOGE("pkgid is NULL\n");
		return PMINFO_R_ERROR;
	}

	if (manifest == NULL) {
		_LOGE("manifest is NULL\n");
		*label = strdup(pkgid);
		return PMINFO_R_ERROR;
	}

	snprintf(pkgpath, BUF_SIZE, "%s/%s/tizen-manifest.xml", OPT_USR_APPS, pkgid);
	if (access(pkgpath, R_OK) == 0) {
		_LOGE("This is a core tpk package");
		*label = strdup(pkgid);
		return 0;
	}

	reader = xmlReaderForFile(manifest, NULL, 0);

	if (reader) {
		if (_child_element(reader, -1)) {
			node = xmlTextReaderConstName(reader);
			if (!node) {
				_LOGE("xmlTextReaderConstName value is NULL\n");
				ret = PMINFO_R_ERROR;
				goto end;
			}

			if (!strcmp(ASCII(node), "manifest")) {
				ret = _ri_get_attribute(reader, "smack-label", &val);
				if (ret != 0) {
					_LOGE("@Error in getting the attribute value");
					ret = PMINFO_R_ERROR;
					goto end;
				}
				if (val) {
					*label = strdup(val);
					if (*label == NULL) {
						_LOGE("Out of memeory\n");
						ret = PMINFO_R_ERROR;
					}
					free((void *)val);
				} else {
					*label = NULL;
					_LOGE("package smack-label is not specified\n");
					goto end;
				}
			} else {
				_LOGE("Unable to create xml reader\n");
				ret = PMINFO_R_ERROR;
				goto end;
			}
		}
	} else {
		_LOGE("xmlReaderForFile value is NULL\n");
		ret = PMINFO_R_ERROR;
	}

 end:

	xmlFreeTextReader(reader);

	if (*label == NULL) {
		*label = strdup(pkgid);
	}

	return ret;
}

int __get_smack_label_from_db(const char *pkgid, char **label)
{
	char *smack_label = NULL;
	pkgmgrinfo_pkginfo_h handle = NULL;
	int ret = PMINFO_R_OK;

	if (label == NULL) {
		_LOGE("space for label is NULL\n");
		return PMINFO_R_ERROR;
	}

	*label = NULL;

	if (pkgid == NULL) {
		_LOGE("pkgid is NULL\n");
		return PMINFO_R_ERROR;
	}

	ret = pkgmgrinfo_pkginfo_get_pkginfo(pkgid, &handle);
	if (ret != PMINFO_R_OK) {
		_LOGE("failed to get pkginfo\n");
		ret = PMINFO_R_ERROR;
		goto end;
	}
	ret = pkgmgrinfo_pkginfo_get_custom_smack_label(handle, &smack_label);
	if (ret != PMINFO_R_OK) {
		_LOGE("failed to get custom smack_label\n");
		ret = PMINFO_R_ERROR;
		goto end;
	}

	_LOGD("smack_label(%s)\n", smack_label);
	if (smack_label) {
		*label = strdup(smack_label);
	}

 end:
	pkgmgrinfo_pkginfo_destroy_pkginfo(handle);

	if (*label == NULL) {
		*label = strdup(pkgid);
	}

	return ret;
}
