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
#include <glib.h>
#include <ctype.h>		/* for isspace () */
#include <vconf.h>
#include <cert-service.h>
#include <libxml/parser.h>
#include <libxml/tree.h>
#include <libxml/xmlmemory.h>
#ifndef XMLSEC_NO_XSLT
#include <libxslt/xslt.h>
#include <libxslt/security.h>
#endif
#include <xmlsec/xmlsec.h>
#include <xmlsec/xmltree.h>
#include <xmlsec/xmldsig.h>
#include <xmlsec/crypto.h>
#include <pkgmgr-info.h>
#include <pkgmgr_parser.h>
#include <package-manager.h>
#include <privilege-control.h>
#include <app_manager.h>
#include <aul.h>
#include <dlfcn.h>

#include "rpm-installer-util.h"
#include "rpm-installer-signature.h"
#include "rpm-installer.h"
#include "rpm-frontend.h"
#include "rpm-installer-type.h"

#define PRE_CHECK_FOR_MANIFEST
#define POST_SCRIPT	"/usr/bin/post_script_rpm.sh"
#define INSTALL_SCRIPT	"/usr/bin/install_rpm_package.sh"
#define INSTALL_SCRIPT_WITH_DBPATH_RO		"/usr/bin/install_rpm_package_with_dbpath_ro.sh"
#define INSTALL_SCRIPT_WITH_DBPATH_RW		"/usr/bin/install_rpm_package_with_dbpath_rw.sh"
#define UNINSTALL_SCRIPT	"/usr/bin/uninstall_rpm_package.sh"
#define UPGRADE_SCRIPT	"/usr/bin/upgrade_rpm_package.sh"
#define UPGRADE_SCRIPT_WITH_DBPATH_RO		"/usr/bin/upgrade_rpm_package_with_dbpath_ro.sh"
#define UPGRADE_SCRIPT_WITH_DBPATH_RW		"/usr/bin/upgrade_rpm_package_with_dbpath_rw.sh"
#define TEMP_DBPATH "/opt/usr/rpmdb_tmp"

#define RPM2CPIO	"/usr/bin/rpm2cpio"
#define SIGNATURE1_XML		"signature1.xml"
#define SIGNATURE2_XML		"signature2.xml"
#define AUTHOR_SIGNATURE_XML		"author-signature.xml"
#define USR_APPS			"/usr/apps"
#define OPT_USR_APPS			"/opt/usr/apps"
#define OPT_SHARE_PACKAGES "/opt/share/packages"
#define USR_SHARE_PACKAGES "/usr/share/packages"
#define DEACTIVATION_PKGID_LIST "/opt/share/packages/.pkgmgr/rpm-installer/rpm_installer_deactvation_list.txt"

#define OPT_ZIP_FILE	 		"/usr/system/RestoreDir/opt.zip"

#define EFLWGT_TYPE_STR			"eflwgt"

#define TOKEN_PACKAGE_STR	"package="
#define TOKEN_PKGID_STR		"pkgid="
#define TOKEN_STATE_STR		"state="
#define TOKEN_PATH_STR		"path="
#define TOKEN_OPERATION_STR	"op="
#define TOKEN_REMOVE_STR	"removable="
#define SEPERATOR_END		':'
#define SEPERATOR_START		'"'

#define APP_OWNER_ID		5000
#define APP_GROUP_ID		5000
#define MAX_BUFF_LEN		4096
#define MAX_CERT_NUM		9
#define TERMINATE_RETRY_COUNT 100

#define ASC_CHAR(s) (const char *)s
#define XML_CHAR(s) (const xmlChar *)s

#define BIN_DIR_STR			"bin"
#define RES_DIR_STR			"res"
#define SHARED_RES_DIR_STR	"shared/res"
#define LIBAIL_PATH "/usr/lib/libail.so.0"

enum rpm_request_type {
	INSTALL_REQ,
	UNINSTALL_REQ,
	UPGRADE_REQ,
};

enum rpm_sig_type {
	SIG_AUTH,
	SIG_DIST1,
	SIG_DIST2,
};

enum rpm_sig_sub_type {
	SIG_SIGNER,
	SIG_INTERMEDIATE,
	SIG_ROOT,
};

typedef struct cert_chain_t {
	int cert_type;
	char *cert_value;
} cert_chain;

cert_chain list[MAX_CERT_NUM];

#define APP2EXT_ENABLE
#ifdef APP2EXT_ENABLE
#include <app2ext_interface.h>
#endif

typedef enum rpm_request_type rpm_request_type;
extern char *gpkgname;
extern int sig_enable;

static int __rpm_xsystem(const char *argv[]);
static void __rpm_process_line(char *line);
static void __rpm_perform_read(int fd);
static void __rpm_clear_dir_list(GList* dir_list);
static GList * __rpm_populate_dir_list();
static int __rpm_delete_dir(char *dirname);
static int __is_dir(char *dirname);
static void __rpm_apply_shared_privileges(char *pkgname, int flag);
static int __ri_xmlsec_verify_signature(const char *sigxmlfile, char *rootca);
static xmlSecKeysMngrPtr __ri_load_trusted_certs(char *files, int files_size);
static int __ri_verify_file(xmlSecKeysMngrPtr mngr, const char *sigxmlfile);
static int __ri_create_cert_chain(int sigtype, int sigsubtype, char *value);
static void __ri_free_cert_chain(void);
static char *__ri_get_cert_from_file(const char *file);
static int __privilege_func(const char *name, void *user_data);
static char *__ri_get_str(const char* str, const char* pKey);
static void __ri_xmlsec_debug_print(const char* file, int line, const char* func,
									const char* errorObject, const char* errorSubject, int reason, const char* msg);


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

static int __ri_check_pkgid_for_deactivation(const char *pkgid)
{
	FILE *fp = NULL;
	char deactivation_str[FILENAME_MAX] = { 0 };
	char *deactivation_pkgid = NULL;
	char *deactivation_state = NULL;

	fp = fopen(DEACTIVATION_PKGID_LIST, "r");
	if (fp == NULL) {
		_d_msg(DEBUG_ERR, "fopen fail\n");
		return 0;
	}

	while (fgets(deactivation_str, sizeof(deactivation_str), fp) != NULL) {
		__str_trim(deactivation_str);

		deactivation_pkgid = __ri_get_str(deactivation_str, TOKEN_PKGID_STR);
		if(deactivation_pkgid == NULL)
			continue;

		deactivation_state = __ri_get_str(deactivation_str, TOKEN_STATE_STR);
		if(deactivation_state == NULL) {
			free(deactivation_pkgid);
			continue;
		}

		if ((strcmp(deactivation_pkgid, pkgid) == 0) && (strcmp(deactivation_state, "off") == 0)) {
			fclose(fp);
			free(deactivation_pkgid);
			free(deactivation_state);
			_d_msg(DEBUG_ERR, "Find pkgid[%s] form deactivation list.\n", pkgid);
			return -1;
		}

		free(deactivation_pkgid);
		free(deactivation_state);
		memset(deactivation_str, 0x00, sizeof(deactivation_str));
	}

	if (fp != NULL)
		fclose(fp);

	return 0;

}

static int __ri_get_op_type(char *op_str)
{
	if (strcmp(op_str,"install")==0)
		return INSTALL_REQ;
	else if (strcmp(op_str,"update")==0)
		return UPGRADE_REQ;
	else if (strcmp(op_str,"uninstall")==0)
		return UNINSTALL_REQ;
	else
		return -1;
}

static char *__ri_get_str(const char* str, const char* pKey)
{
	const char* p = NULL;
	const char* pStart = NULL;
	const char* pEnd = NULL;

	if (str == NULL)
		return NULL;

	char *pBuf = strdup(str);

	p = strstr(pBuf, pKey);
	if (p == NULL)
		return NULL;

	pStart = p + strlen(pKey);
	pEnd = strchr(pStart, SEPERATOR_END);
	if (pEnd == NULL)
		return false;

	size_t len = pEnd - pStart;
	if (len <= 0)
		return false;

	char *pRes = (char*)malloc(len + 1);
	strncpy(pRes, pStart, len);
	pRes[len] = 0;

	return pRes;
}

static int __ri_init_csc_xml(char *xml_path, char *removable)
{
	int ret = 0;
	char* csc_tags[3] = {NULL, };

	if (strcmp(removable,"true")==0)
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
	_d_msg(DEBUG_INFO, "Push in list [%d] [%d] [%s]", sigtype, sigsubtype, value);
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
			/*value is already a mallocd pointer*/
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
			/*value is already a mallocd pointer*/
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
			/*value is already a mallocd pointer*/
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
		if (list[i].cert_value)
			free(list[i].cert_value);
	}
}

static void __ri_xmlsec_debug_print(const char* file, int line, const char* func,
				   const char* errorObject, const char* errorSubject, int reason, const char* msg)
{
	char total[BUF_SIZE];
	snprintf(total, sizeof(total), "[%s(%d)] : [%s] : [%s] : [%s]", func, line, errorObject, errorSubject, msg);
	if(reason != 256) {
		fprintf(stderr, "## [validate error]: %s\n", total);
		_d_msg(DEBUG_ERR,"%s",total);
	} else {
		_d_msg(DEBUG_ERR,"%s",total);
	}
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
		_d_msg(DEBUG_ERR, "unable to parse file \"%s\"\n", sigxmlfile);
		goto err;
	}
	/* find start node */
	node = xmlSecFindNode(xmlDocGetRootElement(doc), xmlSecNodeSignature, xmlSecDSigNs);
	if (node == NULL) {
		_d_msg(DEBUG_ERR, "start node not found in \"%s\"\n", sigxmlfile);
		goto err;
	}
	/* create signature context */
	dsigCtx = xmlSecDSigCtxCreate(sec_key_mngr);
	if (dsigCtx == NULL) {
		_d_msg(DEBUG_ERR, "failed to create signature context\n");
		goto err;
	}
	/* Verify signature */
	if (xmlSecDSigCtxVerify(dsigCtx, node) < 0) {
		_d_msg(DEBUG_ERR, "failed to verify signature\n");
		goto err;
	}
	/* print verification result to stdout */
	if (dsigCtx->status == xmlSecDSigStatusSucceeded) {
		res = 0;
		_d_msg(DEBUG_INFO, "Signature VALID");
	} else {
		res = -1;
		_d_msg(DEBUG_INFO, "Signature INVALID");
	}

err:
	/* cleanup */
	if(dsigCtx != NULL) {
		xmlSecDSigCtxDestroy(dsigCtx);
	}
	if(doc != NULL) {
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
		_d_msg(DEBUG_ERR, "failed to create keys manager.\n");
		return NULL;
	}
	if (xmlSecCryptoAppDefaultKeysMngrInit(sec_key_mngr) < 0) {
		_d_msg(DEBUG_ERR, "failed to initialize keys manager.\n");
		xmlSecKeysMngrDestroy(sec_key_mngr);
		return NULL;
	}
	/* load trusted cert */
	if (xmlSecCryptoAppKeysMngrCertLoad(sec_key_mngr, files, xmlSecKeyDataFormatPem, xmlSecKeyDataTypeTrusted) < 0) {
		_d_msg(DEBUG_ERR, "failed to load pem certificate from \"%s\"\n", files);
		xmlSecKeysMngrDestroy(sec_key_mngr);
		return NULL;
	}
	return sec_key_mngr;
}

static int __ri_xmlsec_verify_signature(const char *sigxmlfile, char *rootca)
{
	int ret = 0;
	xmlSecKeysMngrPtr sec_key_mngr = NULL;
	xmlInitParser();
	xmlLoadExtDtdDefaultValue = XML_DETECT_IDS | XML_COMPLETE_ATTRS;
	xmlSubstituteEntitiesDefault(1);

#ifndef XMLSEC_NO_XSLT
	xmlIndentTreeOutput = 1;
	xsltSecurityPrefsPtr sec_prefs = xsltNewSecurityPrefs();
	xsltSetSecurityPrefs(sec_prefs,  XSLT_SECPREF_WRITE_FILE, xsltSecurityForbid);
	xsltSetSecurityPrefs(sec_prefs,  XSLT_SECPREF_READ_FILE, xsltSecurityForbid);
	xsltSetSecurityPrefs(sec_prefs,  XSLT_SECPREF_CREATE_DIRECTORY, xsltSecurityForbid);
	xsltSetSecurityPrefs(sec_prefs,  XSLT_SECPREF_WRITE_NETWORK, xsltSecurityForbid);
	xsltSetSecurityPrefs(sec_prefs,  XSLT_SECPREF_READ_NETWORK, xsltSecurityForbid);
	xsltSetDefaultSecurityPrefs(sec_prefs);
#endif

	ret = xmlSecInit();
	if (ret < 0) {
		_d_msg(DEBUG_ERR, "xmlsec initialization failed [%d]\n", ret);
		goto end;
	}
	ret = xmlSecCheckVersion();
	if (ret != 1) {
		_d_msg(DEBUG_ERR, "Incompatible version of loaded xmlsec library [%d]\n", ret);
		goto end;
	}
#ifdef XMLSEC_CRYPTO_DYNAMIC_LOADING
	ret = xmlSecCryptoDLLoadLibrary(BAD_CAST "openssl");
	if (ret < 0) {
		_d_msg(DEBUG_ERR, "unable to load openssl library [%d]\n", ret);
		goto end;
	}
#endif

	ret = xmlSecCryptoAppInit(NULL);
	if (ret < 0) {
		_d_msg(DEBUG_ERR, "crypto initialization failed [%d]\n", ret);
		goto end;
	}
	ret = xmlSecCryptoInit();
	if (ret < 0) {
		_d_msg(DEBUG_ERR, "xmlsec-crypto initialization failed [%d]\n", ret);
		goto end;
	}

	sec_key_mngr = __ri_load_trusted_certs(rootca, 1);
	if (sec_key_mngr == NULL) {
		_d_msg(DEBUG_ERR, "loading of trusted certs failed\n");
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
	xmlCleanupParser();
	return ret;
}

static void __rpm_apply_shared_privileges(char *pkgname, int flag)
{
	int ret = -1;
	char buf[BUF_SIZE] = {'\0'};
	char dirpath[BUF_SIZE] = {'\0'};
	/*execute privilege APIs. The APIs should not fail*/
	_ri_privilege_register_package(pkgname);

	/*home dir. Dont setup path but change smack access to "_" */
	snprintf(dirpath, BUF_SIZE, "/usr/apps/%s", pkgname);
	if (__is_dir(dirpath))
		_ri_privilege_change_smack_label(dirpath, "_", 0);/*0 is SMACK_LABEL_ACCESS*/
	memset(dirpath, '\0', BUF_SIZE);
	snprintf(dirpath, BUF_SIZE, "/opt/usr/apps/%s", pkgname);
	if (__is_dir(dirpath))
		_ri_privilege_change_smack_label(dirpath, "_", 0);/*0 is SMACK_LABEL_ACCESS*/
	memset(dirpath, '\0', BUF_SIZE);

	/*/shared dir. Dont setup path but change smack access to "_" */
	snprintf(dirpath, BUF_SIZE, "/usr/apps/%s/shared", pkgname);
	if (__is_dir(dirpath))
		_ri_privilege_change_smack_label(dirpath, "_", 0);/*0 is SMACK_LABEL_ACCESS*/
	memset(dirpath, '\0', BUF_SIZE);
	snprintf(dirpath, BUF_SIZE, "/opt/usr/apps/%s/shared", pkgname);
	if (__is_dir(dirpath))
		_ri_privilege_change_smack_label(dirpath, "_", 0);/*0 is SMACK_LABEL_ACCESS*/
	memset(dirpath, '\0', BUF_SIZE);

	/*/shared/res dir. setup path and change smack access to "_" */
	snprintf(dirpath, BUF_SIZE, "/usr/apps/%s/shared/res", pkgname);
	if (__is_dir(dirpath))
		_ri_privilege_setup_path(pkgname, dirpath, PERM_APP_PATH_ANY_LABEL, "_");
	memset(dirpath, '\0', BUF_SIZE);

	snprintf(dirpath, BUF_SIZE, "/opt/usr/apps/%s/shared/res", pkgname);
	if (__is_dir(dirpath))
		_ri_privilege_setup_path(pkgname, dirpath, PERM_APP_PATH_ANY_LABEL, "_");
	memset(dirpath, '\0', BUF_SIZE);

	/*/shared/data dir. setup path and change group to 'app'*/
	snprintf(dirpath, BUF_SIZE, "/usr/apps/%s/shared/data", pkgname);
	if (__is_dir(dirpath)) {
		(void)chown(dirpath, APP_OWNER_ID, APP_GROUP_ID);
		_ri_privilege_setup_path(pkgname, dirpath, PERM_APP_PATH_PUBLIC, NULL);
	}
	memset(dirpath, '\0', BUF_SIZE);

	snprintf(dirpath, BUF_SIZE, "/opt/usr/apps/%s/shared/data", pkgname);
	if (__is_dir(dirpath)) {
		(void)chown(dirpath, APP_OWNER_ID, APP_GROUP_ID);
		_ri_privilege_setup_path(pkgname, dirpath, PERM_APP_PATH_PUBLIC, NULL);
	}
}

static int __is_dir(char *dirname)
{
	struct stat stFileInfo;
	if(dirname == NULL) {
		_d_msg(DEBUG_ERR, "dirname is null\n");
		return -1;
	}

	(void)stat(dirname, &stFileInfo);

	if (S_ISDIR(stFileInfo.st_mode)) {
		return 1;
	}
	return 0;
}

static int __rpm_delete_dir(char *dirname)
{
	int ret = 0;
	DIR *dp;
	struct dirent *ep;
	char abs_filename[FILENAME_MAX];
	struct stat stFileInfo;
	dp = opendir(dirname);

	_d_msg(DEBUG_INFO, "__rpm_delete_dir(%s)\n", dirname);

	if (dp != NULL) {
		while ((ep = readdir(dp))) {
			snprintf(abs_filename, FILENAME_MAX, "%s/%s", dirname,
				 ep->d_name);
			if (lstat(abs_filename, &stFileInfo) < 0)
				perror(abs_filename);
			if (S_ISDIR(stFileInfo.st_mode)) {
				if (strcmp(ep->d_name, ".") &&
				    strcmp(ep->d_name, "..")) {
					__rpm_delete_dir(abs_filename);
					(void)remove(abs_filename);
				}
			} else {
				(void)remove(abs_filename);
			}
		}
		(void)closedir(dp);
	} else {
		_d_msg(DEBUG_ERR, "Couldn't open the directory\n");
		return -1;
	}
	ret = remove(dirname);
	if (ret < 0)
		_d_msg(DEBUG_ERR, "remove fail dirname[%s]\n", dirname);

	return 0;
}


static void __rpm_process_line(char *line)
{
	char *tok = NULL;
	tok = strtok(line, " ");
	if (tok) {
		if (!strncmp(tok, "%%", 2)) {
			tok = strtok(NULL, " ");
			if (tok) {
				_d_msg(DEBUG_INFO, "Install percentage is %s\n",
				       tok);
				_ri_broadcast_status_notification(gpkgname,
								  "install_percent",
								  tok);
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

	size = read(fd, &buffer[buffer_position],
		    sizeof(buffer) - buffer_position);
	buffer_position += size;
	if (size <= 0)
		return;

	/* Process each line of the recieved buffer */
	buf_ptr = tmp_ptr = buffer;
	while ((tmp_ptr = (char *)memchr(buf_ptr, '\n',
					 buffer + buffer_position - buf_ptr)) !=
	       NULL) {
		*tmp_ptr = 0;
		__rpm_process_line(buf_ptr);
		/* move to next line and continue */
		buf_ptr = tmp_ptr + 1;
	}

	/*move the remaining bits at the start of the buffer
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

static int __ri_xsystem(const char *argv[])
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

static int __rpm_xsystem(const char *argv[])
{
	int err = 0;
	int status = 0;
	pid_t pid;
	int pipefd[2];
	int result = 0;
	int fd = 0;

	if (pipe(pipefd) == -1) {
		_d_msg(DEBUG_ERR, "pipe creation failed\n");
		return -1;
	}
	/*Read progress info via pipe */
	pid = fork();

	switch (pid) {
	case -1:
		_d_msg(DEBUG_ERR, "fork failed\n");
		return -1;
	case 0:
		/* child */
		{
			close(pipefd[0]);
			close(1);
			close(2);
			fd = dup(pipefd[1]);
			if (fd < 0) {
				_d_msg(DEBUG_ERR, "dup failed\n");
				_exit(100);
			}

			result = dup(pipefd[1]);
			if (result < 0) {
				_d_msg(DEBUG_ERR, "dup failed\n");
				_exit(100);
			}

			if (execvp(argv[0], (char *const *)argv) == -1) {
				_d_msg(DEBUG_ERR, "execvp failed\n");
			}
			_exit(100);
		}
	default:
		/* parent */
		break;
	}

	close(pipefd[1]);

	while ((err = waitpid(pid, &status, WNOHANG)) != pid) {
		if (err < 0) {
			if (errno == EINTR)
				continue;
			_d_msg(DEBUG_ERR, "waitpid failed\n");
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
		select_ret =
		    pselect(pipefd[0] + 1, &rfds, NULL, NULL, &tv, NULL);
		if (select_ret == 0)
			continue;

		else if (select_ret < 0 && errno == EINTR)
			continue;
		else if (select_ret < 0) {
			_d_msg(DEBUG_ERR, "select() returned error\n");
			continue;
		}
		if (FD_ISSET(pipefd[0], &rfds))
			__rpm_perform_read(pipefd[0]);
	}

	close(pipefd[0]);
	/* Check for an error code. */
	if (WIFEXITED(status) == 0 || WEXITSTATUS(status) != 0) {

		if (WIFSIGNALED(status) != 0 && WTERMSIG(status) == SIGSEGV) {
			printf
			    ("Sub-process %s received a segmentation fault. \n",
			     argv[0]);
		} else if (WIFEXITED(status) != 0) {
			printf("Sub-process %s returned an error code (%u)\n",
			       argv[0], WEXITSTATUS(status));
		} else {
			printf("Sub-process %s exited unexpectedly\n", argv[0]);
		}
	}
	return WEXITSTATUS(status);
}

static void __rpm_clear_dir_list(GList* dir_list)
{
	GList *list = NULL;
	app2ext_dir_details* dir_detail = NULL;
	if (dir_list) {
		list = g_list_first(dir_list);
		while (list) {
			dir_detail = (app2ext_dir_details *)list->data;
			if (dir_detail && dir_detail->name) {
				free(dir_detail->name);
			}
			list = g_list_next(list);
		}
		g_list_free(dir_list);
	}
}

static GList * __rpm_populate_dir_list()
{
	GList *dir_list = NULL;
	GList *list = NULL;
	app2ext_dir_details* dir_detail = NULL;
	int i;
	char pkg_ro_content_rpm[3][5] = { "bin", "res", "lib" };


	for (i=0; i<3; i++) {
		dir_detail = (app2ext_dir_details*) calloc(1, sizeof(app2ext_dir_details));
		if (dir_detail == NULL) {
			printf("\nMemory allocation failed\n");
			goto FINISH_OFF;
		}
		dir_detail->name = (char*) calloc(1, sizeof(char)*(strlen(pkg_ro_content_rpm[i])+2));
		if (dir_detail->name == NULL) {
			printf("\nMemory allocation failed\n");
			free(dir_detail);
			goto FINISH_OFF;
		}
		snprintf(dir_detail->name, (strlen(pkg_ro_content_rpm[i])+1), "%s", pkg_ro_content_rpm[i]);
		dir_detail->type = APP2EXT_DIR_RO;
		dir_list = g_list_append(dir_list, dir_detail);
	}
	if (dir_list) {
		list = g_list_first(dir_list);
		while (list) {
			dir_detail = (app2ext_dir_details *)list->data;
			list = g_list_next(list);
		}
	}
	return dir_list;
FINISH_OFF:
	if (dir_list) {
		list = g_list_first(dir_list);
		while (list) {
			dir_detail = (app2ext_dir_details *)list->data;
			if (dir_detail && dir_detail->name) {
				free(dir_detail->name);
			}
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

	if(!(fp_cert = fopen(file, "r"))) {
		_d_msg(DEBUG_ERR, "[ERR][%s] Fail to open file, [%s]\n", __func__, file);
		return NULL;
	}

	fseek(fp_cert, 0L, SEEK_END);

	if(ftell(fp_cert) < 0) {
		_d_msg(DEBUG_ERR, "[ERR][%s] Fail to find EOF\n", __func__);
		error = 1;
		goto err;
	}

	certlen = ftell(fp_cert);
	fseek(fp_cert, 0L, SEEK_SET);

	if(!(certbuf = (char*)malloc(sizeof(char) * (int)certlen))) {
		_d_msg(DEBUG_ERR, "[ERR][%s] Fail to allocate memory\n", __func__);
		error = 1;
		goto err;
	}
	memset(certbuf, 0x00, (int)certlen);

	i = 0;
	while((ch = fgetc(fp_cert)) != EOF) {
		if(ch != '\n') {
			certbuf[i] = ch;
			i++;
		}
	}
	certbuf[i] = '\0';

	startcert = strstr(certbuf, "-----BEGIN CERTIFICATE-----") + strlen("-----BEGIN CERTIFICATE-----");
	endcert = strstr(certbuf, "-----END CERTIFICATE-----");
	certwrite = (int)endcert - (int)startcert;

	cert = (char*)malloc(sizeof(char) * (certwrite+2));
	if (cert == NULL) {
		_d_msg(DEBUG_ERR, "[ERR][%s] Fail to allocate memory\n", __func__);
		error = 1;
		goto err;
	}
	memset(cert, 0x00, certwrite+2);
	snprintf(cert, certwrite+1, "%s", startcert);
	_d_msg(DEBUG_INFO, "Root CA : %s", cert);

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
	const char *perm[] = {NULL, NULL};
	perm[0] = name;

	ret = _ri_privilege_enable_permissions((char *)user_data, 7, perm, 1);
	if(ret < 0) {
		_d_msg(DEBUG_ERR, "%s enable_permissions[%s] fail \n", user_data, perm);
	}

	return ret;
}

char* __manifest_to_package(const char* manifest)
{
	char *package;

	if(manifest == NULL)
		return NULL;

	package = strdup(manifest);
	if(package == NULL)
		return NULL;

	if (!strstr(package, ".xml")) {
		_d_msg(DEBUG_ERR, "%s is not a manifest file", manifest);
		free(package);
		return NULL;
	}

	return package;
}

char *__strlwr(char *str)
{
	int i = 0;

	while(*(str+i) != NULL){
		if(*(str+i) >= 65 || *(str+i)<= 90) {
			*(str+i) = towlower(*(str+i));
		}
		i++;
	}
	return str;
}

static int __ri_find_xml(char *pkgid, char **rpm_xml)
{
	DIR *dir;
	struct dirent entry, *result;
	int ret = 0;
	char buf[BUF_SIZE];

	dir = opendir(USR_SHARE_PACKAGES);
	if (!dir) {
		if (strerror_r(errno, buf, sizeof(buf)) == 0)
			_d_msg(DEBUG_ERR, "fota-info : Failed to access the [%s] because %s", USR_SHARE_PACKAGES, buf);
		return -1;
	}

	for (ret = readdir_r(dir, &entry, &result);
			ret == 0 && result != NULL;
			ret = readdir_r(dir, &entry, &result)) {
		char *manifest;

		if (entry.d_name[0] == '.') continue;

		manifest = __manifest_to_package(entry.d_name);
		if (!manifest) {
			_d_msg(DEBUG_ERR, "fota-info : Failed to convert file to xml[%s]", entry.d_name);
			continue;
		}

		if (strstr(manifest, __strlwr(pkgid))) {
			snprintf(buf, sizeof(buf), "%s/%s", USR_SHARE_PACKAGES, manifest);
			_d_msg(DEBUG_INFO, "fota-info : pkgid[%s] find xml[%s]\n", pkgid, buf);
			*rpm_xml = strdup(buf);
			closedir(dir);
			return 0;
		}
	}

	_d_msg(DEBUG_ERR, "fota-info : Failed to find xml for pkgid[%s]", pkgid);
	closedir(dir);
	return 0;
}

static int __ri_install_fota(char *pkgid)
{
	int ret = 0;
	char *manifest = NULL;

	_d_msg(DEBUG_INFO, "fota-info : pkgid[%s] start installation\n", pkgid);

	/*if pkgid is one of deactivation, it does not need to install*/
	ret = __ri_check_pkgid_for_deactivation(pkgid);
	if (ret < 0) {
		_d_msg(DEBUG_ERR, "fota-info : pkgid[%s] for deactivation dont need to install.\n", pkgid);
		return ret;
	}

	/*get manifest*/
	manifest = pkgmgr_parser_get_manifest_file(pkgid);
	if (manifest == NULL) {
		_d_msg(DEBUG_ERR, "fota-info : dont have manefest[pkgid=%s]\n", pkgid);
		ret = -1;
		goto end;
	}
	_d_msg(DEBUG_INFO, "fota-info : pkgid[%s] has manefest[%s]\n", pkgid, manifest);

	ret = pkgmgr_parser_parse_manifest_for_installation(manifest, NULL);
	if (ret < 0) {
		_d_msg(DEBUG_ERR, "fota-info : installation fail[manifest=%s]\n", manifest);
		ret = -1;
		goto end;
	}
	_d_msg(DEBUG_INFO, "fota-info : pkgid[%s] installation success\n", pkgid);

	__rpm_apply_shared_privileges(pkgid,0);

	ret = _ri_apply_perm(pkgid);
	if (ret < 0) {
		_d_msg(DEBUG_ERR, "fota-info : _ri_apply_perm fail[pkgid=%s]\n", pkgid);
		ret = -1;
		goto end;
	}
	_d_msg(DEBUG_INFO, "fota-info : pkgid[%s] apply smack success\n", pkgid);

end:
	if (manifest)
		free(manifest);

	return ret;
}

static int __ri_upgrade_fota(char *pkgid)
{
	_d_msg(DEBUG_INFO, "fota-info : pkgid[%s] start upgrade\n", pkgid);

	int ret = 0;
	char *manifest = NULL;

	/*if pkgid is one of deactivation, it does not need to upgrade*/
	ret = __ri_check_pkgid_for_deactivation(pkgid);
	if (ret < 0) {
		_d_msg(DEBUG_ERR, "fota-info : pkgid[%s] for deactivation dont need to install.\n", pkgid);
		return ret;
	}

	/*get manifest*/
	manifest = pkgmgr_parser_get_manifest_file(pkgid);
	if (manifest == NULL) {
		_d_msg(DEBUG_ERR, "fota-info : dont have manefest[pkgid=%s]\n", pkgid);
		ret = -1;
		goto end;
	}
	_d_msg(DEBUG_INFO, "fota-info : pkgid[%s] has manefest[%s]\n", pkgid, manifest);
	if (access(manifest, F_OK) != 0) {
		_d_msg(DEBUG_ERR, "fota-info : can not access[manifest=%s]\n", manifest);
		free(manifest);
		manifest = NULL;

		/*find xml*/
		ret = __ri_find_xml(pkgid, &manifest);
		if (ret < 0) {
			_d_msg(DEBUG_ERR, "fota-info : can not find xml[pkgid=%s]\n", pkgid);
			ret = -1;
			goto end;
		}
	}

	if (manifest == NULL) {
		return -1;
	}

	ret = pkgmgr_parser_parse_manifest_for_upgrade(manifest, NULL);
	if (ret < 0) {
		_d_msg(DEBUG_ERR, "fota-info : upgrade fail[manifest=%s]\n", manifest);
		ret = -1;
		goto end;
	}
	_d_msg(DEBUG_INFO, "fota-info : pkgid[%s] upgrade success\n", pkgid);

end:
	if (manifest)
		free(manifest);

	return ret;
}

static int __ri_uninstall_fota(char *pkgid)
{
	_d_msg(DEBUG_INFO, "fota-info : pkgid[%s] start uninstallation\n", pkgid);

	int ret = 0;

	ret = _ri_privilege_unregister_package(pkgid);
	if (ret < 0) {
		_d_msg(DEBUG_ERR, "fota-info : _ri_privilege_unregister_package fail[pkgid=%s]\n", pkgid);
	}

	ret = pkgmgr_parser_parse_manifest_for_uninstallation(pkgid, NULL);
	if (ret < 0) {
		_d_msg(DEBUG_ERR, "fota-info : uninstall fail[manifest=%s]\n", pkgid);
	}

	_d_msg(DEBUG_INFO, "fota-info : pkgid[%s] uninstall success\n", pkgid);

	return ret;
}

static char * __getvalue(const char* pBuf, const char* pKey)
{
	const char* p = NULL;
	const char* pStart = NULL;
	const char* pEnd = NULL;

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

	char *pRes = (char*)malloc(len + 1);
	strncpy(pRes, pStart, len);
	pRes[len] = 0;

	return pRes;
}

static char *__find_rpm_pkgid(const char* manifest)
{
	FILE *fp = NULL;
	char buf[BUF_SIZE] = {0};
	char *pkgid = NULL;

	fp = fopen(manifest, "r");
	if (fp == NULL)	{
		_d_msg(DEBUG_ERR, "csc-info : Fail get : %s\n", manifest);
		return NULL;
	}

	while (fgets(buf, BUF_SIZE, fp) != NULL) {
		__str_trim(buf);
		pkgid = __getvalue(buf, TOKEN_PACKAGE_STR);
		if (pkgid !=  NULL) {
			fclose(fp);
			return pkgid;
		}
		memset(buf, 0x00, BUF_SIZE);
	}

	if (fp != NULL)
		fclose(fp);

	return NULL;
}

static int __copy_file( const char *src_path, const char *dst_path)
{
	FILE            *src, *dst;
	int             rc = 0;
	unsigned char   temp_buf[8192] = {'\0',};
	size_t          size_of_uchar = sizeof( unsigned char);
	size_t          size_of_temp_buf = sizeof( temp_buf);

    src = fopen(src_path, "r");
    if( src == NULL) {
		_d_msg(DEBUG_ERR, "Failed to open(). path=%s, E:%d(%s)", src_path, errno, strerror(errno));
        return  -1;
    }

    dst = fopen(dst_path, "w");
    if( dst == NULL) {
		_d_msg(DEBUG_ERR, "Failed to open dst file. file=%s, E:%d(%s)", dst_path, errno, strerror(errno));
        fclose(src);
        return  -1;
    }

    while(!feof(src)) {
        rc = fread( temp_buf, size_of_uchar, size_of_temp_buf, src);
        fwrite( temp_buf, size_of_uchar, rc, dst);
    }

    fclose( src);
    fclose( dst);
    return  0;
}

static int __ri_install_csc(char *path_str, char *remove_str)
{
	int ret = 0;

	char *pkgid = NULL;
	char delims[] = "/";
	char* token = NULL;
	char argv[BUF_SIZE] = {'\0'};
	char xml_name[BUF_SIZE] = {'\0'};
	char src_file[BUF_SIZE] = {'\0'};
	char dest_file[BUF_SIZE] = {'\0'};

	snprintf(src_file, sizeof(src_file), "%s", path_str);

	/*get pkgid from path str*/
	pkgid = __find_rpm_pkgid(path_str);
	if (pkgid == NULL) {
		_d_msg(DEBUG_ERR, "csc-info : fail to find pkgid\n");
		return -1;
	}
	_d_msg(DEBUG_INFO, "csc-info : find pkgid=[%s] for installation\n", pkgid);

	/*find xml name*/
	token = strtok(path_str, delims);
	while(token)
	{
		memset(xml_name, 0x00, sizeof(xml_name));
		strncat(xml_name, token, strlen(token));
		token = strtok(NULL, delims);
	}
	_d_msg(DEBUG_INFO, "csc-info : xml name = %s\n", xml_name);

	/*copy xml to /opt/share/packages*/
	snprintf(dest_file, sizeof(dest_file), "%s/%s", OPT_SHARE_PACKAGES, xml_name);
	ret = __copy_file(src_file, dest_file);
	if (ret != 0) {
		_d_msg(DEBUG_ERR, "csc-info : xml copy fail(%d)\n", ret);
	} else {
		_d_msg(DEBUG_ERR, "csc-info : xml copy success to [%s] \n", dest_file);
	}

	/*remove old pkg info*/
	ret = pkgmgr_parser_parse_manifest_for_uninstallation(pkgid, NULL);
	if (ret < 0) {
		_d_msg(DEBUG_INFO, "csc-info : fail remove old pkg info\n");
	} else {
		_d_msg(DEBUG_INFO, "csc-info : success remove old pkg info\n");
	}

	/*insert new pkg info*/
	memset(argv, 0x00, sizeof(argv));
	snprintf(argv, sizeof(argv), "%s/%s", OPT_SHARE_PACKAGES, xml_name);
	ret = __ri_init_csc_xml(argv, remove_str);
	if (ret < 0) {
		_d_msg(DEBUG_INFO, "csc-info : fail insert db\n");
	} else {
		_d_msg(DEBUG_INFO, "csc-info : success xml name = %s\n", xml_name);
	}

	free(pkgid);

	return 0;
}

static int __ri_uninstall_csc(char *pkgid)
{
	/*remove old pkg info*/
	int ret = pkgmgr_parser_parse_manifest_for_uninstallation(pkgid, NULL);
	if (ret < 0) {
		_d_msg(DEBUG_INFO, "csc-info : fail remove old pkg info\n");
	} else {
		_d_msg(DEBUG_INFO, "csc-info : success remove old pkg info\n");
	}

	return 0;
}

static int __child_element(xmlTextReaderPtr reader, int depth)
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

static int __get_size_from_xml(const char *manifest, int *size)
{
	const char *val = NULL;
	const xmlChar *node;
	xmlTextReaderPtr reader;

	if(manifest == NULL) {
		_d_msg(DEBUG_ERR, "Input argument is NULL\n");
		return PMINFO_R_ERROR;
	}

	if(size == NULL) {
		_d_msg(DEBUG_ERR, "Argument supplied to hold return value is NULL\n");
		return PMINFO_R_ERROR;
	}

	xmlInitParser();
	reader = xmlReaderForFile(manifest, NULL, 0);

	if (reader){
		if (__child_element(reader, -1)) {
			node = xmlTextReaderConstName(reader);
			if (!node) {
				_d_msg(DEBUG_ERR, "xmlTextReaderConstName value is NULL\n");
				xmlFreeTextReader(reader);
				xmlCleanupParser();
				return PMINFO_R_ERROR;
			}

			if (!strcmp(ASC_CHAR(node), "manifest")) {
				if (xmlTextReaderGetAttribute(reader, XML_CHAR("size")))
					val = ASC_CHAR(xmlTextReaderGetAttribute(reader, XML_CHAR("size")));

				if (val) {
					*size = atoi(val);
				} else {
					*size = 0;
					_d_msg(DEBUG_ERR, "package size is not specified\n");
					xmlFreeTextReader(reader);
					xmlCleanupParser();
					return PMINFO_R_ERROR;
				}
			} else {
				_d_msg(DEBUG_ERR, "Unable to create xml reader\n");
				xmlFreeTextReader(reader);
				xmlCleanupParser();
				return PMINFO_R_ERROR;
			}
		}
	} else {
		_d_msg(DEBUG_ERR, "xmlReaderForFile value is NULL\n");
		xmlCleanupParser();
		return PMINFO_R_ERROR;
	}

	xmlFreeTextReader(reader);
	xmlCleanupParser();

	return PMINFO_R_OK;
}

static int __get_location_from_xml(const char *manifest, pkgmgrinfo_install_location *location)
{
	const char *val = NULL;
	const xmlChar *node;
	xmlTextReaderPtr reader;

	if(manifest == NULL) {
		_d_msg(DEBUG_ERR, "Input argument is NULL\n");
		return PMINFO_R_ERROR;
	}

	if(location == NULL) {
		_d_msg(DEBUG_ERR, "Argument supplied to hold return value is NULL\n");
		return PMINFO_R_ERROR;
	}

	xmlInitParser();
	reader = xmlReaderForFile(manifest, NULL, 0);

	if (reader){
		if ( __child_element(reader, -1)) {
			node = xmlTextReaderConstName(reader);
			if (!node) {
				_d_msg(DEBUG_ERR, "xmlTextReaderConstName value is NULL\n");
				xmlFreeTextReader(reader);
				xmlCleanupParser();
				return PMINFO_R_ERROR;
			}

			if (!strcmp(ASC_CHAR(node), "manifest")) {
				if (xmlTextReaderGetAttribute(reader, XML_CHAR("install-location")))
					val = ASC_CHAR(xmlTextReaderGetAttribute(reader, XML_CHAR("install-location")));

				if (val) {
					if (strcmp(val, "internal-only") == 0)
						*location = PMINFO_INSTALL_LOCATION_INTERNAL_ONLY;
					else if (strcmp(val, "prefer-external") == 0)
						*location = PMINFO_INSTALL_LOCATION_PREFER_EXTERNAL;
					else
						*location = PMINFO_INSTALL_LOCATION_AUTO;
				}
			} else {
				_d_msg(DEBUG_ERR, "Unable to create xml reader\n");
				xmlFreeTextReader(reader);
				xmlCleanupParser();
				return PMINFO_R_ERROR;
			}
		}
	} else {
		_d_msg(DEBUG_ERR, "xmlReaderForFile value is NULL\n");
		xmlCleanupParser();
		return PMINFO_R_ERROR;
	}

	xmlFreeTextReader(reader);
	xmlCleanupParser();

	return PMINFO_R_OK;
}

static char * __get_pkg_path(const char *pkg_path, const char *pkgid)
{
	int ret = 0;
	char buff[BUF_SIZE] = {'\0'};
	char *real_path = NULL;

	snprintf(buff, BUF_SIZE, "%s/%s", pkg_path, pkgid);
	do {
		if (__is_dir(buff)) break;
		memset(buff, '\0', BUF_SIZE);
		snprintf(buff, BUF_SIZE, "/usr/apps/%s", pkgid);
		if (__is_dir(buff)) break;
		memset(buff, '\0', BUF_SIZE);
		snprintf(buff, BUF_SIZE, "/opt/apps/%s", pkgid);
		if (__is_dir(buff)) break;
		memset(buff, '\0', BUF_SIZE);
		snprintf(buff, BUF_SIZE, "/opt/usr/apps/%s", pkgid);
		if (__is_dir(buff)) break;
	} while (0);

	ret = chdir(buff);
	if (ret != 0) {
		_d_msg(DEBUG_ERR, "chdir() failed [%s]\n", strerror(errno));
		return NULL;
	}

	real_path = (char *)malloc(strlen(buff) + 1);
	if (real_path == NULL) {
		_d_msg(DEBUG_ERR, "Malloc failed!\n");
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
	/* create Handle*/
	error = pkgmgrinfo_create_certinfo_set_handle(&handle);
	if (error != 0) {
		_d_msg(DEBUG_ERR, "Cert handle creation failed. Err:%d", error);
		__ri_free_cert_chain();
		return;
	}

	if (list[SIG_AUTH].cert_value == NULL) {
		_d_msg(DEBUG_ERR, "pkgid[%s] dont have SIG_AUTH.cert_value ", pkgid);
		goto err;
	}

	for (i = 0; i < MAX_CERT_NUM; i++) {

		if (list[i].cert_value) {
			error = pkgmgrinfo_set_cert_value(handle, list[i].cert_type, list[i].cert_value);
			if (error != 0) {
				_d_msg(DEBUG_ERR, "pkgmgrinfo_set_cert_value failed. cert type:%d. Err:%d", list[i].cert_type, error);
				goto err;
			}
		}
	}
	/* Save the certificates in cert DB*/
	error = pkgmgrinfo_save_certinfo(pkgid, handle);
	if (error != 0) {
		_d_msg(DEBUG_ERR, "pkgmgrinfo_save_certinfo failed. Err:%d", error);
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
	/* Delete the certifictes from cert DB*/
	error = pkgmgrinfo_delete_certinfo(pkgid);
	if (error != 0) {
		_d_msg(DEBUG_ERR, "pkgmgrinfo_delete_certinfo failed. Err:%d", error);
		return;
	}
}


int _ri_verify_sig_and_cert(const char *sigfile)
{
	char certval[MAX_BUFF_LEN] = { '\0'};
	int err = 0;
	int validity = 0;
	int i = 0;
	int j= 0;
	int ret = RPM_INSTALLER_SUCCESS;
	char *crt = NULL;
	signature_x *signx = NULL;
	struct keyinfo_x *keyinfo = NULL;
	struct x509data_x *x509data = NULL;
	CERT_CONTEXT *ctx = NULL;
	int sigtype = 0;

	ctx = cert_svc_cert_context_init();
	if (ctx == NULL) {
		_d_msg(DEBUG_ERR, "cert_svc_cert_context_init() failed");
		return RPM_INSTALLER_ERR_INTERNAL;
	}
	if (strstr(sigfile, AUTHOR_SIGNATURE_XML))
		sigtype = SIG_AUTH;
	else if (strstr(sigfile, SIGNATURE1_XML))
		sigtype = SIG_DIST1;
	else if (strstr(sigfile, SIGNATURE2_XML))
		sigtype = SIG_DIST2;
	else {
		_d_msg(DEBUG_ERR, "Unsupported Signature type\n");
		cert_svc_cert_context_final(ctx);
		return RPM_INSTALLER_ERR_INTERNAL;
	}
	signx = _ri_process_signature_xml(sigfile);
	if (signx == NULL) {
		_d_msg(DEBUG_ERR, "Parsing %s failed", sigfile);
		ret = RPM_INSTALLER_ERR_INTERNAL;
		goto end;
	}
	keyinfo = signx->keyinfo;
	if ((keyinfo == NULL) || (keyinfo->x509data == NULL) || (keyinfo->x509data->x509certificate == NULL)) {
		_d_msg(DEBUG_ERR, "Certificates missing in %s", sigfile);
		ret = RPM_INSTALLER_ERR_CERT_INVALID;
		goto end;
	}
	x509data = keyinfo->x509data;
	x509certificate_x *cert = x509data->x509certificate;
	/*First cert is Signer certificate*/
	if (cert->text != NULL) {
		for (i = 0; i <= (int)strlen(cert->text); i++) {
			if (cert->text[i] != '\n') {
				certval[j++] = cert->text[i];
			}
		}
		certval[j] = '\0';
		_d_msg(DEBUG_INFO, " strlen[%d] cert_svc_load_buf_to_context() load %s", strlen(certval), certval);
		err = cert_svc_load_buf_to_context(ctx, (unsigned char*)certval);
		if (err != 0) {
			_d_msg(DEBUG_ERR, "cert_svc_load_buf_to_context() failed. cert:%s err:%d", certval, err);
			ret = RPM_INSTALLER_ERR_INTERNAL;
			goto end;
		}
		err = __ri_create_cert_chain(sigtype, SIG_SIGNER, certval);
		if (err) {
			_d_msg(DEBUG_ERR, "Failed to push cert info in list\n");
			__ri_free_cert_chain();
			ret = RPM_INSTALLER_ERR_INTERNAL;
			goto end;
		}
	}
	/*Second cert is Intermediate certificate*/
	cert = cert->next;
	if (cert->text != NULL) {
		memset(certval, 0x00, MAX_BUFF_LEN);
		j = 0;
		for (i = 0; i <= (int)strlen(cert->text); i++) {
			if (cert->text[i] != '\n') {
				certval[j++] = cert->text[i];
			}
		}
		certval[j] = '\0';
		_d_msg(DEBUG_INFO, " strlen[%d] cert_svc_push_file_into_context() load %s", strlen(certval), certval);
		if (cert->text != NULL) {
			err = cert_svc_push_buf_into_context(ctx, (unsigned char*)certval);
			if (err != 0) {
				_d_msg(DEBUG_ERR, "cert_svc_push_file_into_context() failed. cert:%s err:%d", certval, err);
				ret = RPM_INSTALLER_ERR_INTERNAL;
				goto end;
			}
		}
		err = __ri_create_cert_chain(sigtype, SIG_INTERMEDIATE, certval);
		if (err) {
			_d_msg(DEBUG_ERR, "Failed to push cert info in list\n");
			__ri_free_cert_chain();
			ret = RPM_INSTALLER_ERR_INTERNAL;
			goto end;
		}
	} else {
		_d_msg(DEBUG_ERR, "Invalid CertChain");
		ret = RPM_INSTALLER_ERR_CERT_INVALID;
		goto end;
	}
	err = cert_svc_verify_certificate(ctx, &validity);
	if (err != 0) {
		_d_msg(DEBUG_ERR, "cert_svc_verify_certificate() failed");
		ret = RPM_INSTALLER_ERR_INTERNAL;
		goto end;
	}
	_d_msg(DEBUG_INFO, "Certificate verification completed. [%d]", validity);
	if (validity == 0) {
		_d_msg(DEBUG_ERR, "Certificate Invalid/Expired");
		ret = RPM_INSTALLER_ERR_CERTCHAIN_VERIFICATION_FAILED;
		goto end;
	}
	/*verify signature*/
	/*For reference validation, we should be in TEMP_DIR/usr/apps/<pkgid>*/
	if (ctx->fileNames && ctx->fileNames->filename) {
		_d_msg(DEBUG_INFO, "Root CA cert is: %s\n", ctx->fileNames->filename);
		err = __ri_xmlsec_verify_signature(sigfile, ctx->fileNames->filename);
		if (err < 0) {
			_d_msg(DEBUG_ERR, "signature validation failed\n");
			ret = RPM_INSTALLER_ERR_SIG_VERIFICATION_FAILED;
			goto end;
		}
		crt = __ri_get_cert_from_file(ctx->fileNames->filename);
		err = __ri_create_cert_chain(sigtype, SIG_ROOT, crt);
		if (err) {
			_d_msg(DEBUG_ERR, "Failed to push cert info in list\n");
			__ri_free_cert_chain();
			ret = RPM_INSTALLER_ERR_INTERNAL;
			goto end;
		}
	} else {
		_d_msg(DEBUG_ERR, "No Root CA certificate found. Signature validation failed");
		ret = RPM_INSTALLER_ERR_ROOT_CERT_NOT_FOUND;
		goto end;
	}
	ret = 0;
end:
	cert_svc_cert_context_final(ctx);
	ctx = NULL;
	_ri_free_signature_xml(signx);
	signx = NULL;
	return ret;
}

static int _ri_verify_signatures(const char *root_path, const char *pkgid)
{
	int ret = 0;
	char buff[BUF_SIZE] = {'\0'};
	char *pkg_path = NULL;

	/*check for signature and certificate*/
	if (sig_enable) {
		pkg_path = __get_pkg_path(root_path, pkgid);
		if (pkg_path == NULL) {
			return 0;
		}

		_d_msg(DEBUG_ERR, "Switched to %s\n", pkg_path);

		/*signature2.xml is optional*/
		snprintf(buff, BUF_SIZE, "%s/signature2.xml", pkg_path);
		if (access(buff, F_OK) == 0) {
			_d_msg(DEBUG_INFO, "signature2.xml found in %s\n", pkg_path);
			ret = _ri_verify_sig_and_cert(buff);
			if (ret) {
				_d_msg(DEBUG_ERR, "Failed to verify [%s]\n", buff);
				ret = -1;
				goto end;
			}
			_d_msg(DEBUG_INFO, "Successfully verified [%s]\n", buff);
		}
		memset(buff, '\0', BUF_SIZE);

		/*signature1.xml is mandatory*/
		snprintf(buff, BUF_SIZE, "%s/signature1.xml", pkg_path);
		if (access(buff, F_OK) == 0) {
			_d_msg(DEBUG_INFO, "signature1.xml found in %s\n", pkg_path);
			ret = _ri_verify_sig_and_cert(buff);
			if (ret) {
				_d_msg(DEBUG_ERR, "Failed to verify [%s]\n", buff);
				ret = -1;
				goto end;
			}
			_d_msg(DEBUG_INFO, "Successfully verified [%s]\n", buff);
		}
		memset(buff, '\0', BUF_SIZE);

		/*author-signature.xml is mandatory*/
		snprintf(buff, BUF_SIZE, "%s/author-signature.xml", pkg_path);
		if (access(buff, F_OK) == 0) {
			_d_msg(DEBUG_INFO, "author-signature.xml found in %s\n", pkg_path);
			ret = _ri_verify_sig_and_cert(buff);
			if (ret) {
				_d_msg(DEBUG_ERR, "Failed to verify [%s]\n", buff);
				ret = -1;
				goto end;
			}
			_d_msg(DEBUG_INFO, "Successfully verified [%s]\n", buff);
		}
		memset(buff, '\0', BUF_SIZE);
		ret = 0;
	}

end :
	free(pkg_path);
	return ret;
}

void _ri_apply_smack(char *pkgname, int flag)
{
	__rpm_apply_shared_privileges(pkgname, flag);
}

int _ri_apply_perm(char *pkgid)
{
	int ret = -1;
	pkgmgrinfo_pkginfo_h handle = NULL;

	ret = pkgmgrinfo_pkginfo_get_pkginfo(pkgid, &handle);
	if (ret != PMINFO_R_OK)
		return -1;

	ret = pkgmgrinfo_pkginfo_foreach_privilege(handle, __privilege_func, (void *)pkgid);
	if (ret != PMINFO_R_OK) {
		_d_msg(DEBUG_ERR, "pkgmgrinfo_pkginfo_get_pkgid failed\n");
		pkgmgrinfo_pkginfo_destroy_pkginfo(handle);
		return -1;
	}
	pkgmgrinfo_pkginfo_destroy_pkginfo(handle);

	return 0;
}

static int __ri_install_fota_for_rw(char *pkgid)
{
	int ret = 0;
	int home_dir = 1;
	char buff[BUF_SIZE] = {'\0'};

	_d_msg(DEBUG_INFO, "fota-info : pkgid[%s] start installation\n", pkgid);

	/*unzip pkg path from factoryrest data*/
	snprintf(buff, BUF_SIZE, "opt/usr/apps/%s/*", pkgid);
	const char *pkg_argv[] = { "/usr/bin/unzip", "-oX", OPT_ZIP_FILE, buff, "-d", "/", NULL };
	ret = __ri_xsystem(pkg_argv);
	if (ret != 0) {
		_d_msg(DEBUG_ERR, "fota-info : unzip root path[%s] is fail .\n", buff);
		return ret;
	}

	_d_msg(DEBUG_INFO, "fota-info : unzip root path[%s] is success\n", buff);

	/*unzip manifest from factoryrest data*/
	memset(buff, '\0', BUF_SIZE);
	snprintf(buff, BUF_SIZE, "opt/share/packages/%s.xml", pkgid);

	const char *xml_argv[] = { "/usr/bin/unzip", "-oX", OPT_ZIP_FILE, buff, "-d", "/", NULL };
	ret = __ri_xsystem(xml_argv);
	if (ret != 0) {
		_d_msg(DEBUG_ERR, "fota-info : xml_argv fail for pkgid[%s] .\n", pkgid);
		return ret;
	}

	_d_msg(DEBUG_INFO, "fota-info : xml_argv is success\n", pkgid);

	/*get updated manifest path*/
	memset(buff, '\0', BUF_SIZE);
	snprintf(buff, BUF_SIZE, "%s/%s.xml", OPT_SHARE_PACKAGES, pkgid);
	_d_msg(DEBUG_ERR, "Manifest name is %s\n", buff);

	/*apply smack for manifest*/
	_ri_privilege_change_smack_label(buff, pkgid, 0);/*0 is SMACK_LABEL_ACCESS*/

	/*register manifest*/
	char* fota_tags[3] = {NULL, };
	fota_tags[0] = "removable=true";
	fota_tags[1] = "preload=true";
	fota_tags[2] = NULL;

	ret = pkgmgr_parser_parse_manifest_for_installation(buff, fota_tags);
	if (ret < 0) {
		_d_msg(DEBUG_ERR, "Parsing Manifest Failed\n");
		ret = -1;
		goto err;
	} else {
		_d_msg(DEBUG_INFO, "Parsing Manifest Success\n");
	}

	/*apply smack for pkg root path*/
	memset(buff, '\0', BUF_SIZE);
	snprintf(buff, BUF_SIZE, "%s/%s", OPT_USR_APPS, pkgid);
	_ri_privilege_setup_path(pkgid, buff, PERM_APP_PATH_ANY_LABEL, pkgid);

	/*apply smack for defined directory*/
	__rpm_apply_shared_privileges(pkgid, home_dir);

	/*apply privilege*/
	ret = _ri_apply_perm(pkgid);
	if (ret != 0) {
		_d_msg(DEBUG_ERR, "apply perm failed with err(%d)\n", ret);
	} else {
		_d_msg(DEBUG_INFO, "apply perm success\n");
	}

	/*Register cert info*/
	_ri_register_cert(pkgid);

err:

	return ret;
}

static int __ri_upgrade_fota_for_rw(char *pkgid)
{
	int ret = 0;
	int home_dir = 1;
	char buff[BUF_SIZE] = {'\0'};

	_d_msg(DEBUG_INFO, "fota-info : pkgid[%s] start upgrade\n", pkgid);

	/*unzip pkg dir from factoryrest data*/
	snprintf(buff, BUF_SIZE, "opt/usr/apps/%s/*", pkgid);
	const char *pkg_argv[] = { "/usr/bin/unzip", "-oX", OPT_ZIP_FILE, buff, "-d", "/", NULL };
	ret = __ri_xsystem(pkg_argv);
	if (ret != 0) {
		_d_msg(DEBUG_ERR, "fota-info : unzip root path[%s] is fail .\n", buff);
		return ret;
	}

	_d_msg(DEBUG_INFO, "fota-info : unzip root path[%s] is success\n", buff);

	/*unzip manifest from factoryrest data*/
	memset(buff, '\0', BUF_SIZE);
	snprintf(buff, BUF_SIZE, "opt/share/packages/%s.xml", pkgid);
	const char *xml_argv[] = { "/usr/bin/unzip", "-oX", OPT_ZIP_FILE, buff, "-d", "/", NULL };
	ret = __ri_xsystem(xml_argv);
	if (ret != 0) {
		_d_msg(DEBUG_ERR, "fota-info : unzip manifest[%s] is fail .\n", buff);
		return ret;
	}

	_d_msg(DEBUG_INFO, "fota-info : unzip manifest[%s] is success\n", buff);

	/*get updated manifest path*/
	memset(buff, '\0', BUF_SIZE);
	snprintf(buff, BUF_SIZE, "%s/%s.xml", OPT_SHARE_PACKAGES, pkgid);
	_d_msg(DEBUG_ERR, "Manifest name is %s\n", buff);

	/*apply smack for manifest*/
	_ri_privilege_change_smack_label(buff, pkgid, 0);/*0 is SMACK_LABEL_ACCESS*/

	/*register manifest*/
	ret = pkgmgr_parser_parse_manifest_for_upgrade(buff, NULL);
	if (ret < 0) {
		_d_msg(DEBUG_ERR, "Parsing Manifest Failed\n");
		ret = -1;
		goto err;
	} else {
		_d_msg(DEBUG_INFO, "Parsing Manifest Success\n");
	}

	/*apply smack for pkg root path*/
	memset(buff, '\0', BUF_SIZE);
	snprintf(buff, BUF_SIZE, "%s/%s", OPT_USR_APPS, pkgid);
	_ri_privilege_setup_path(pkgid, buff, PERM_APP_PATH_ANY_LABEL, pkgid);

	/*apply smack for defined directory*/
	__rpm_apply_shared_privileges(pkgid, home_dir);

	/*apply privilege*/
	ret = _ri_apply_perm(pkgid);
	if (ret != 0) {
		_d_msg(DEBUG_ERR, "apply perm failed with err(%d)\n", ret);
	} else {
		_d_msg(DEBUG_INFO, "apply perm success\n");
	}

	/*Register new cert info*/
	_ri_unregister_cert(pkgid);
	_ri_register_cert(pkgid);

err:
	return ret;
}

static int __ri_uninstall_fota_for_rw(char *pkgid)
{
	int ret = 0;
	char buff[BUF_SIZE] = {'\0'};

	_d_msg(DEBUG_INFO, "fota-info : pkgid[%s] start uninstall\n", pkgid);

	/*del root path dir*/
	snprintf(buff, BUF_SIZE, "%s/%s", OPT_USR_APPS, pkgid);

	if (__is_dir(buff)) {
		__rpm_delete_dir(buff);
	}

	/*del manifest*/
	memset(buff, '\0', BUF_SIZE);
	snprintf(buff, BUF_SIZE, "%s/%s.xml", OPT_SHARE_PACKAGES, pkgid);
	(void)remove(buff);

	/*del db info*/
	ret = pkgmgr_parser_parse_manifest_for_uninstallation(pkgid, NULL);
	if (ret < 0) {
		_d_msg(DEBUG_ERR, "Parsing Manifest Failed\n");
	}

	/*execute privilege APIs*/
	_ri_privilege_revoke_permissions(pkgid);
	_ri_privilege_unregister_package(pkgid);

	/*Unregister cert info*/
	_ri_unregister_cert(pkgid);

	return 0;
}

/**
 * callback for the pkgmgrinfo_appinfo_get_list used in _rpm_uninstall_pkg()
 */
static int __ri_check_running_app(const pkgmgrinfo_appinfo_h handle, void *user_data)
{
	int ret = 0;
	bool isRunning = 0;
	char *appid = NULL;
	app_context_h appCtx = NULL;

	ret = pkgmgrinfo_appinfo_get_appid(handle, &appid);
	if (ret < 0) {
		_d_msg(DEBUG_ERR, "Failed to execute pkgmgrinfo_appinfo_get_appid[%d].\n", ret);
		return ret;
	}

	ret = app_manager_is_running(appid, &isRunning);
	if (ret < 0) {
		_d_msg(DEBUG_ERR, "Failed to execute app_manager_is_running[%d].\n", ret);
		return ret;
	}
	_d_msg(DEBUG_ERR, "app[%s] , running state[%d].\n", appid, isRunning);

	if (isRunning) {
		ret = app_manager_get_app_context(appid, &appCtx);
		if (ret < 0) {
			_d_msg(DEBUG_ERR, "Failed to execute app_manager_get_app_context[%d].\n", ret);
			return ret;
		}

		ret = app_manager_terminate_app(appCtx);
		if (ret < 0) {
			_d_msg(DEBUG_ERR, "Failed to execute app_manager_terminate_app[%d].\n", ret);
			app_context_destroy(appCtx);
			return ret;
		}

		int i = 0;
		for (i = 0; i < TERMINATE_RETRY_COUNT; i++) {
			ret = app_manager_is_running(appid, &isRunning);
			if (ret < 0) {
				_d_msg(DEBUG_ERR, "Failed to execute app_manager_is_running[%d].\n", ret);
				app_context_destroy(appCtx);
				return ret;
			}

			if (!isRunning) {
				_d_msg(DEBUG_INFO, "App(%s) is terminated.\n", appid);
				break;
			} else {
				_d_msg(DEBUG_INFO, "App(%s) is not terminated yet. wait count = [%d].\n", appid, i);
				usleep(100000);
			}
		}

		ret = app_context_destroy(appCtx);
		if (ret < 0) {
			_d_msg(DEBUG_ERR, "Failed to execute app_context_destroy[%d].\n", ret);
			return ret;
		}
	}

	return ret;
}

static int __ri_change_dir(char *dirname)
{
	int ret = 0;

	ret = mkdir(dirname, 0644);
	if (ret < 0) {
		if (access(dirname, F_OK) == 0) {
			__rpm_delete_dir(dirname);
			ret = mkdir(dirname, 0644);
			if (ret < 0) {
				_d_msg(DEBUG_ERR, "mkdir(%s) failed\n", dirname);
				return -1;
			}
		} else {
			_d_msg(DEBUG_ERR, "can not access[%s]\n", dirname);
			return -1;
		}
	}

	ret = chdir(dirname);
	if (ret != 0) {
		_d_msg(DEBUG_ERR, "chdir(%s) failed [%s]\n", dirname, strerror(errno));
		return -1;
	}
	return 0;
}

int __ri_smack_reload(const char *pkgid, rpm_request_type request_type)
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

	if(op_type == NULL) {
		_d_msg(DEBUG_ERR, "@Failed to reload smack. request_type not matched[pkgid=%s, op=%s]", pkgid, op_type);
		return -1;
	}

	const char *smack_argv[] = { "/usr/bin/smack_reload.sh", op_type, pkgid, NULL };
	ret = __ri_xsystem(smack_argv);
	if (ret != 0) {
		_d_msg(DEBUG_ERR, "@Failed to reload smack[pkgid=%s, op=%s].", pkgid, op_type);
	} else {
		_d_msg(DEBUG_INFO, "#success: smack reload[pkgid=%s, op=%s]", pkgid, op_type);
	}
	free(op_type);
	return ret;
}

static void __ri_post_script(const char *pkgfilepath, const char *pkgid)
{
	char path_buf[BUF_SIZE] = {'\0'};

	snprintf(path_buf, BUF_SIZE, "%s/rpm_post_tmp.sh", TEMP_DIR);

	/*pkgfilepath=source rpm file, script_path=post script file from spec*/
	const char *post_argv[] = { POST_SCRIPT, pkgfilepath, path_buf, NULL };
	(void)__ri_xsystem(post_argv);

	(void)chmod(path_buf, 0700);

	/*run post script*/
	const char *script_argv[] = {path_buf, NULL };
	(void)__ri_xsystem(script_argv);

	(void)remove(path_buf);

	/*if data dir is on root path, apply owner ship as a app, smack label*/
	memset(path_buf, '\0', BUF_SIZE);
	snprintf(path_buf, BUF_SIZE, "%s/%s/data", OPT_USR_APPS, pkgid);
	if (__is_dir(path_buf)) {
		const char *chown_argv[] = { "/bin/chown", "-cR", "5000:5000", path_buf, NULL };
		(void)__ri_xsystem(chown_argv);
		_ri_privilege_change_smack_label(path_buf, pkgid, 0);
	}

	_d_msg(DEBUG_INFO, "#success: post_script");
}

static void __ri_remove_updated_dir(const char *pkgid)
{
	char path_buf[BUF_SIZE] = {'\0'};

	/*check pkgid is null*/
	if (pkgid == NULL) {
		_d_msg(DEBUG_ERR, "@pkgid is null\n");
		return;
	}

	/*remove bin dir*/
	snprintf(path_buf, BUF_SIZE, "%s/%s/%s", OPT_USR_APPS, pkgid, BIN_DIR_STR);
	if (__is_dir(path_buf)) {
		_d_msg(DEBUG_ERR, "@pkgid[%s] need to clean dir[%s]\n", pkgid, path_buf);
		__rpm_delete_dir(path_buf);
	}

	/*remove res dir*/
	memset(path_buf, '\0', BUF_SIZE);
	snprintf(path_buf, BUF_SIZE, "%s/%s/%s", OPT_USR_APPS, pkgid, RES_DIR_STR);
	if (__is_dir(path_buf)) {
		_d_msg(DEBUG_ERR, "@pkgid[%s] need to clean dir[%s]\n", pkgid, path_buf);
		__rpm_delete_dir(path_buf);
	}

	/*remove shared/res dir*/
	memset(path_buf, '\0', BUF_SIZE);
	snprintf(path_buf, BUF_SIZE, "%s/%s/%s", OPT_USR_APPS, pkgid, SHARED_RES_DIR_STR);
	if (__is_dir(path_buf)) {
		_d_msg(DEBUG_ERR, "@pkgid[%s] need to clean dir[%s]\n", pkgid, path_buf);
		__rpm_delete_dir(path_buf);
	}
}

static int __metadata_func(const char *key, const char *value, void *user_data)
{
	int ret = 0;
	bool isRunning = 0;

	if (key == NULL) {
		_d_msg(DEBUG_ERR, "key is null\n");
		return -1;
	}
	if (value == NULL) {
		_d_msg(DEBUG_ERR, "value is null\n");
		return -1;
	}
	if (user_data == NULL) {
		_d_msg(DEBUG_ERR, "user_data is null\n");
		return -1;
	}

	if ((strcmp(key, "launch-on-attach") == 0) && (strcmp(value, "true") == 0)) {
		_d_msg(DEBUG_ERR, "consumer[%s] : launch-on-attach is true \n", (char *)user_data);

		ret = app_manager_is_running((char *)user_data, &isRunning);
		if (ret < 0) {
			_d_msg(DEBUG_ERR, "Failed to execute app_manager_is_running[%s].\n", (char *)user_data);
			return ret;
		}

		if (isRunning) {
			_d_msg(DEBUG_ERR, "consumer[%s] is already launched \n", (char *)user_data);
		} else {
			usleep(100 * 1000); /* 100ms sleep for infomation ready*/
			ret = aul_launch_app((char *)user_data, NULL);
			if (ret == AUL_R_ERROR) {
				_d_msg(DEBUG_ERR, "consumer[%s] launch fail, sleep and retry  launch_app\n", (char *)user_data);
				usleep(100 * 1000);	/* 100ms sleep for infomation ready*/
				aul_launch_app((char *)user_data, NULL);
			}
			_d_msg(DEBUG_ERR, "consumer[%s] is launched !!!! \n", (char *)user_data);
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
		_d_msg(DEBUG_ERR, "@Failed to get component_type\n");
		return -1;
	}

	if (strcmp(component_type, "svcapp") == NULL) {
		ret = pkgmgrinfo_appinfo_get_appid(handle, &appid);
		if (ret != PMINFO_R_OK) {
			_d_msg(DEBUG_ERR, "@Failed to get appid\n");
			return -1;
		}
		_d_msg(DEBUG_ERR, "@find consumer[%s], check metadata for launch\n", appid);

		ret = pkgmgrinfo_appinfo_foreach_metadata(handle, __metadata_func, (void *)appid);
		if (ret != PMINFO_R_OK) {
			_d_msg(DEBUG_ERR, "@Failed to get foreach_metadata\n");
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
		_d_msg(DEBUG_ERR, "@Failed to get pkginfo handle [%s]\n", pkgid);
		return;
	}

	ret = pkgmgrinfo_appinfo_get_list(pkghandle, PM_UI_APP, __ri_find_svcapp, NULL);
	if (ret < 0) {
		_d_msg(DEBUG_ERR, "@Failed to get appinfo_get_list [%s]\n", pkgid);
		return;
	}
	pkgmgrinfo_pkginfo_destroy_pkginfo(pkghandle);
	if (ret < 0) {
		_d_msg(DEBUG_ERR, "@Failed to get destroy_pkginfo [%s]\n", pkgid);
	}
}

static int __ail_change_info(int op, const char *appid)
{
	void *lib_handle = NULL;
	int (*ail_desktop_operation) (const char *);
	char *aop = NULL;
	int ret = 0;

	if ((lib_handle = dlopen(LIBAIL_PATH, RTLD_LAZY)) == NULL) {
		_d_msg(DEBUG_ERR, "dlopen is failed LIBAIL_PATH[%s]\n", LIBAIL_PATH);
		goto END;
	}


	switch (op) {
		case 0:
			aop  = "ail_desktop_add";
			break;
		case 1:
			aop  = "ail_desktop_update";
			break;
		case 2:
			aop  = "ail_desktop_remove";
			break;
		case 3:
			aop  = "ail_desktop_clean";
			break;
		case 4:
			aop  = "ail_desktop_fota";
			break;
		default:
			goto END;
			break;
	}

	if ((ail_desktop_operation =
	     dlsym(lib_handle, aop)) == NULL || dlerror() != NULL) {
		_d_msg(DEBUG_ERR, "can not find symbol \n");

		goto END;
	}

	ret = ail_desktop_operation(appid);

END:
	if (lib_handle)
		dlclose(lib_handle);

	return ret;
}

static int __ri_update_ail_info(const pkgmgrinfo_appinfo_h handle, void *user_data)
{
	int ret = 0;
	char *appid = NULL;

	ret = pkgmgrinfo_appinfo_get_appid(handle, &appid);
	if (ret < 0) {
		_d_msg(DEBUG_ERR, "Failed to execute pkgmgrinfo_appinfo_get_appid[%d].\n", ret);
		return ret;
	}

	ret = __ail_change_info(AIL_INSTALL, appid);
	if (ret < 0) {
		_d_msg(DEBUG_ERR, "Failed to execute __ail_change_info[%s].\n", appid);
	}

	return ret;
}

int _rpm_install_pkg_with_dbpath(char *pkgfilepath, char *pkgid)
{
	int ret = 0;
	char buff[BUF_SIZE] = {'\0'};
	char manifest[BUF_SIZE] = { '\0'};
	char srcpath[BUF_SIZE] = {'\0'};
	pkgmgrinfo_install_location location = 1;
	int size = -1;
	char cwd[BUF_SIZE] = {'\0'};
	int home_dir = 0;

	/*send event for start*/
	_ri_broadcast_status_notification(pkgid, "start", "install");

	_d_msg(DEBUG_INFO, "[#]start : _rpm_install_pkg_with_dbpath\n");

	/*getcwd*/
	getcwd(cwd, BUF_SIZE);
	if (cwd[0] == '\0') {
		_d_msg(DEBUG_ERR, "@getcwd() failed.\n");
		ret = RPM_INSTALLER_ERR_INTERNAL;
		goto err;
	}
	_d_msg(DEBUG_INFO, "#Current working directory is %s\n", cwd);

	/*change dir*/
	ret = __ri_change_dir(TEMP_DIR);
	if (ret == -1) {
		_d_msg(DEBUG_ERR, "@change dir failed.\n");
		ret = RPM_INSTALLER_ERR_INTERNAL;
		goto err;
	}
	_d_msg(DEBUG_INFO, "#Switched to %s\n", TEMP_DIR);

	/*run cpio script*/
	const char *cpio_argv[] = { CPIO_SCRIPT, pkgfilepath, NULL };
	ret = __ri_xsystem(cpio_argv);

	/*get manifext.xml path*/
	snprintf(manifest, BUF_SIZE, "%s/opt/share/packages/%s.xml", TEMP_DIR, pkgid);
	_d_msg(DEBUG_INFO, "#Manifest name is %s\n", manifest);

	if (access(manifest, F_OK)) {
		_d_msg(DEBUG_INFO, "#There is no RW manifest.xml. check RO manifest.xml.\n");

		memset(manifest, '\0', sizeof(manifest));
		snprintf(manifest, BUF_SIZE, "%s/usr/share/packages/%s.xml", TEMP_DIR, pkgid);
		_d_msg(DEBUG_INFO, "#Manifest name is %s\n", manifest);

		if (access(manifest, F_OK)) {
			_d_msg(DEBUG_ERR, "@Can not find manifest.xml in the pkg.\n");
			ret = RPM_INSTALLER_ERR_NO_MANIFEST;
			goto err;
		} else {
			home_dir = 0;
		}

		snprintf(srcpath, BUF_SIZE, "%s", manifest);
		memset(manifest, '\0', sizeof(manifest));
		snprintf(manifest, BUF_SIZE, "%s/%s.xml", MANIFEST_RW_DIRECTORY, pkgid);

		const char *xml_update_argv[] = { CPIO_SCRIPT_UPDATE_XML, srcpath, manifest, NULL };
		ret = __ri_xsystem(xml_update_argv);

	} else {
		home_dir = 1;
	}
	/*send event for install_percent*/
	_ri_broadcast_status_notification(pkgid, "install_percent", "30");

	/*check manifest.xml validation*/
	ret = pkgmgr_parser_check_manifest_validation(manifest);
	if(ret < 0) {
		_d_msg(DEBUG_ERR, "@invalid manifest\n");
		ret = RPM_INSTALLER_ERR_INVALID_MANIFEST;
		goto err;
	}

	/*check for signature and certificate*/
	_ri_verify_signatures(TEMP_DIR, pkgid);
    if (ret < 0) {
    	_d_msg(DEBUG_ERR, "@signature and certificate failed(%s).\n", pkgid);
		ret = RPM_INSTALLER_ERR_SIG_INVALID;
		goto err;
    }
    _d_msg(DEBUG_INFO, "#_ri_verify_signatures success.\n");

    /*chdir*/
	ret = chdir(cwd);
	if (ret != 0) {
		_d_msg(DEBUG_ERR, "@chdir(%s) failed [%s]\n", cwd, strerror(errno));
		ret = RPM_INSTALLER_ERR_INTERNAL;
		goto err;
	}

	/*run script*/
	if (home_dir == 0) {
		const char *argv[] = { INSTALL_SCRIPT_WITH_DBPATH_RO, pkgfilepath, NULL };
		ret = __ri_xsystem(argv);
	} else {
		const char *argv[] = { INSTALL_SCRIPT_WITH_DBPATH_RW, pkgfilepath, NULL };
		ret = __ri_xsystem(argv);
	}
	if (ret != 0) {
		_d_msg(DEBUG_ERR, "@install complete with error(%d)\n", ret);
		goto err;
	}
	_d_msg(DEBUG_INFO, "#install script success.\n");

	/*send event for install_percent*/
	_ri_broadcast_status_notification(pkgid, "install_percent", "60");

	/*if post is in rpm-spec, execute post as a script*/
	//__ri_post_script(pkgfilepath, pkgid);

	/*Parse the manifest to get install location and size. If installation fails, remove manifest info from DB*/
	ret = pkgmgr_parser_parse_manifest_for_installation(manifest, NULL);
	if (ret < 0) {
		_d_msg(DEBUG_ERR, "@Parsing Manifest Failed\n");
		ret = RPM_INSTALLER_ERR_INTERNAL;
		goto err;
	}
	_d_msg(DEBUG_INFO, "#Parsing Manifest Success\n");

	/*apply smack to shared dir*/
	__rpm_apply_shared_privileges(pkgid, 1);

	/*apply smack by privilege*/
	ret = _ri_apply_perm(pkgid);
	if (ret != 0) {
		_d_msg(DEBUG_ERR, "@apply perm failed with err(%d)\n", ret);
	}
	_d_msg(DEBUG_INFO, "#apply perm success\n");

	/*register cert info*/
	_ri_register_cert(pkgid);

	/*reload smack*/
	ret = __ri_smack_reload(pkgid, INSTALL_REQ);
	if (ret != 0) {
		_d_msg(DEBUG_INFO, "__ri_smack_reload failed.\n");
	}
	/*send event for install_percent*/
	_ri_broadcast_status_notification(pkgid, "install_percent", "100");

err:
	__rpm_delete_dir(TEMP_DIR);
	__rpm_delete_dir(TEMP_DBPATH);

	if (ret == 0) {
		_d_msg(DEBUG_INFO, "[#]end : _rpm_install_pkg_with_dbpath\n");
		_ri_broadcast_status_notification(pkgid, "end", "ok");
		__ri_launch_consumer(pkgid);
	} else {
		_d_msg(DEBUG_ERR, "[@]end : _rpm_install_pkg_with_dbpath\n");
		_ri_broadcast_status_notification(pkgid, "end", "fail");
	}

	return ret;
}

int _rpm_upgrade_pkg_with_dbpath(char *pkgfilepath, char *pkgid)
{
	int ret = 0;
	char manifest[BUF_SIZE] = { '\0'};
	char buff[BUF_SIZE] = { '\0' };
	char srcpath[BUF_SIZE] = {'\0'};
	pkgmgr_install_location location = 1;
	int size = -1;
	char cwd[BUF_SIZE] = {'\0'};
	int home_dir = 0;
	pkgmgrinfo_pkginfo_h pkghandle;

	_ri_broadcast_status_notification(pkgid, "start", "update");

	_d_msg(DEBUG_INFO, "[#]start : _rpm_upgrade_pkg_with_dbpath\n");

	/*terminate running app*/
	ret = pkgmgrinfo_pkginfo_get_pkginfo(pkgid, &pkghandle);
	if (ret < 0) {
		_d_msg(DEBUG_ERR, "@Failed to get pkginfo handle\n");
		ret = RPM_INSTALLER_ERR_PKG_NOT_FOUND;
		goto err;
	}
	pkgmgrinfo_appinfo_get_list(pkghandle, PM_UI_APP, __ri_check_running_app, NULL);
	pkgmgrinfo_pkginfo_destroy_pkginfo(pkghandle);

	/*getcwd*/
	getcwd(cwd, BUF_SIZE);
	if (cwd[0] == '\0') {
		_d_msg(DEBUG_ERR, "@getcwd() failed.\n");
		ret = RPM_INSTALLER_ERR_INTERNAL;
		goto err;
	}
	_d_msg(DEBUG_INFO, "#Current working directory is %s.\n", cwd);

	/*change dir*/
	ret = __ri_change_dir(TEMP_DIR);
	if (ret == -1) {
		_d_msg(DEBUG_ERR, "@change dir failed.\n");
		ret = RPM_INSTALLER_ERR_INTERNAL;
		goto err;
	}
	_d_msg(DEBUG_INFO, "#Switched to %s\n", TEMP_DIR);

	/*run cpio script*/
	const char *cpio_argv[] = { CPIO_SCRIPT, pkgfilepath, NULL };
	ret = __ri_xsystem(cpio_argv);

	/*get manifext.xml path*/
	snprintf(manifest, BUF_SIZE, "%s/opt/share/packages/%s.xml", TEMP_DIR, pkgid);
	_d_msg(DEBUG_INFO, "#Manifest name is %s.\n", manifest);

	if (access(manifest, F_OK)) {
		_d_msg(DEBUG_INFO, "#There is no RW manifest.xml. check RO manifest.xml.\n");

		memset(manifest, '\0', sizeof(manifest));
		snprintf(manifest, BUF_SIZE, "%s/usr/share/packages/%s.xml", TEMP_DIR, pkgid);
		_d_msg(DEBUG_INFO, "#Manifest name is %s.\n", manifest);

		if (access(manifest, F_OK)) {
			_d_msg(DEBUG_ERR, "@Can not find manifest.xml in the pkg.\n");
			ret = RPM_INSTALLER_ERR_NO_MANIFEST;
			goto err;
		} else {
			home_dir = 0;
		}

		snprintf(srcpath, BUF_SIZE, "%s", manifest);
		memset(manifest, '\0', sizeof(manifest));
		snprintf(manifest, BUF_SIZE, "%s/%s.xml", MANIFEST_RW_DIRECTORY, pkgid);

		const char *xml_update_argv[] = { CPIO_SCRIPT_UPDATE_XML, srcpath, manifest, NULL };
		ret = __ri_xsystem(xml_update_argv);

	} else {
		home_dir = 1;
	}

	/*send event for install_percent*/
	_ri_broadcast_status_notification(pkgid, "install_percent", "30");

	/*check manifest.xml validation*/
	ret = pkgmgr_parser_check_manifest_validation(manifest);
	if(ret < 0) {
		_d_msg(DEBUG_ERR, "@invalid manifest\n");
		ret = RPM_INSTALLER_ERR_INVALID_MANIFEST;
		goto err;
	}

	/*check for signature and certificate*/
	_ri_verify_signatures(TEMP_DIR, pkgid);
    if (ret < 0) {
		_d_msg(DEBUG_ERR, "@signature and certificate failed(%s).\n", pkgid);
		ret = RPM_INSTALLER_ERR_SIG_INVALID;
		goto err;
    }
    _d_msg(DEBUG_INFO, "#_ri_verify_signatures success.\n");

    /*chdir*/
	ret = chdir(cwd);
	if (ret != 0) {
		_d_msg(DEBUG_ERR, "@chdir(%s) failed(%s).\n", cwd, strerror(errno));
		ret = RPM_INSTALLER_ERR_INTERNAL;
		goto err;
	}

    /*remove dir for clean*/
	__ri_remove_updated_dir(pkgid);

	/*run script*/
	if (home_dir == 0) {
		const char *argv[] = { UPGRADE_SCRIPT_WITH_DBPATH_RO, pkgfilepath, NULL };
		ret = __ri_xsystem(argv);
	} else {
		const char *argv[] = { UPGRADE_SCRIPT_WITH_DBPATH_RW, pkgfilepath, NULL };
		ret = __ri_xsystem(argv);
	}
	if (ret != 0) {
		_d_msg(DEBUG_ERR, "@upgrade complete with error(%d)\n", ret);
		goto err;
	}
	_d_msg(DEBUG_INFO, "#upgrade script success.\n");

	/*send event for install_percent*/
	_ri_broadcast_status_notification(pkgid, "install_percent", "60");

	/*if post is in rpm-spec, execute post as a script*/
	//__ri_post_script(pkgfilepath, pkgid);

	/*Parse the manifest to get install location and size. If fails, remove manifest info from DB.*/
	ret = pkgmgr_parser_parse_manifest_for_upgrade(manifest, NULL);
	if (ret < 0) {
		_d_msg(DEBUG_ERR, "@Parsing manifest failed.\n");
		ret = RPM_INSTALLER_ERR_INTERNAL;
		goto err;
	}
	_d_msg(DEBUG_INFO, "#Parsing manifest success.\n");

	/*apply smack to shared dir*/
	__rpm_apply_shared_privileges(pkgid, 1);

	/*apply smack by privilege*/
	ret = _ri_apply_perm(pkgid);
	if (ret != 0) {
		_d_msg(DEBUG_ERR, "@apply perm failed with err(%d)\n", ret);
	}
	_d_msg(DEBUG_INFO, "#apply perm success.\n");

	/*unregister cert info*/
	_ri_unregister_cert(pkgid);

	/*register cert info*/
	_ri_register_cert(pkgid);

	/*reload smack*/
	ret = __ri_smack_reload(pkgid, UPGRADE_REQ);
	if (ret != 0) {
		_d_msg(DEBUG_INFO, "__ri_smack_reload failed.\n");
	}

	/*send event for install_percent*/
	_ri_broadcast_status_notification(pkgid, "install_percent", "100");

err:
	__rpm_delete_dir(TEMP_DIR);
	__rpm_delete_dir(TEMP_DBPATH);

	if (ret == 0) {
		_d_msg(DEBUG_INFO, "[#]end : _rpm_upgrade_pkg_with_dbpath\n");
		_ri_broadcast_status_notification(pkgid, "end", "ok");
		__ri_launch_consumer(pkgid);
	} else {
		_d_msg(DEBUG_ERR, "[@]end : _rpm_upgrade_pkg_with_dbpath\n");
		_ri_broadcast_status_notification(pkgid, "end", "fail");
	}

	return ret;
}

int _rpm_uninstall_pkg_with_dbpath(char *pkgid, bool is_system)
{
	int ret = 0;
	char buff[BUF_SIZE] = {'\0'};
	pkgmgrinfo_pkginfo_h pkghandle = NULL;

	if(pkgid == NULL) {
		_d_msg(DEBUG_INFO, "pkgid is null\n");
		return -1;
	}

	_d_msg(DEBUG_INFO, "[#]start : _rpm_uninstall_pkg_with_dbpath(%s)\n", pkgid);

	/*send start event*/
	if (is_system)
		_ri_broadcast_status_notification(pkgid, "start", "update");
	else
		_ri_broadcast_status_notification(pkgid, "start", "uninstall");

	/*terminate running app*/
	ret = pkgmgrinfo_pkginfo_get_pkginfo(pkgid, &pkghandle);
	if (ret < 0) {
		_d_msg(DEBUG_ERR, "@Failed to get pkginfo handle\n");
		ret = RPM_INSTALLER_ERR_PKG_NOT_FOUND;
		goto end;
	}
	pkgmgrinfo_appinfo_get_list(pkghandle, PM_UI_APP, __ri_check_running_app, NULL);
	pkgmgrinfo_pkginfo_destroy_pkginfo(pkghandle);

	/*del root path dir*/
	snprintf(buff, BUF_SIZE, "%s/%s", OPT_USR_APPS, pkgid);
	if (__is_dir(buff)) {
		__rpm_delete_dir(buff);
	}

	/*del manifest*/
	memset(buff, '\0', BUF_SIZE);
	snprintf(buff, BUF_SIZE, "%s/%s.xml", OPT_SHARE_PACKAGES, pkgid);
	(void)remove(buff);

	/*check system pkg, if pkg is system pkg,  need to update xml on USR_SHARE_PACKAGES*/
	if (is_system) {
		memset(buff, '\0', BUF_SIZE);
		snprintf(buff, BUF_SIZE, "%s/%s.xml", USR_SHARE_PACKAGES, pkgid);
		ret = pkgmgr_parser_parse_manifest_for_upgrade(buff, NULL);
		if (ret < 0) {
			_d_msg(DEBUG_ERR, "@Parsing manifest failed.\n");
		}
		goto end;
	} else {
		/*del db info*/
		ret = pkgmgr_parser_parse_manifest_for_uninstallation(pkgid, NULL);
		if (ret < 0) {
			_d_msg(DEBUG_ERR, "@Parsing Manifest Failed\n");
		}
	}

	/*execute privilege APIs*/
	_ri_privilege_revoke_permissions(pkgid);
	_ri_privilege_unregister_package(pkgid);

	/*Unregister cert info*/
	_ri_unregister_cert(pkgid);

	/*reload smack*/
	ret = __ri_smack_reload(pkgid, UNINSTALL_REQ);
	if (ret != 0) {
		_d_msg(DEBUG_INFO, "__ri_smack_reload failed.\n");
	}

end:
	if (ret != 0) {
		_d_msg(DEBUG_ERR, "[@]end : _rpm_uninstall_pkg_with_dbpath\n");
		_ri_broadcast_status_notification(pkgid, "end", "fail");
	} else {
		_d_msg(DEBUG_INFO, "[#]end : _rpm_uninstall_pkg_with_dbpath\n");
		_ri_broadcast_status_notification(pkgid, "end", "ok");
	}

	return ret;
}

int _rpm_uninstall_pkg(char *pkgid)
{
	int ret = 0;
	int err = 0;
	bool is_update = 0;
	bool is_system = 0;
	bool is_removable = 0;
	char buff[BUF_SIZE] = {'\0'};
	pkgmgr_install_location location = 1;
#ifdef APP2EXT_ENABLE
	app2ext_handle *handle = NULL;
#endif
	char *manifest = NULL;
	pkgmgrinfo_pkginfo_h pkghandle;
	const char *argv[] = { UNINSTALL_SCRIPT, pkgid, NULL };

	_d_msg(DEBUG_INFO, "start : _rpm_uninstall_pkg\n");

	ret = pkgmgrinfo_pkginfo_get_pkginfo(pkgid, &pkghandle);
	if (ret < 0) {
		_d_msg(DEBUG_ERR, "Failed to get pkginfo handle\n");
		return RPM_INSTALLER_ERR_PKG_NOT_FOUND;
	}

	ret = pkgmgrinfo_pkginfo_is_system(pkghandle, &is_system);
	if (ret < 0) {
		_d_msg(DEBUG_ERR, "pkgmgrinfo_pkginfo_is_system failed.\n");
		return RPM_INSTALLER_ERR_INTERNAL;
	}
	if (is_system) {
		ret = pkgmgrinfo_pkginfo_is_update(pkghandle, &is_update);
		if (ret < 0) {
			_d_msg(DEBUG_ERR, "pkgmgrinfo_pkginfo_is_system failed.\n");
			return RPM_INSTALLER_ERR_INTERNAL;
		}
		if (is_update) {
			pkgmgrinfo_pkginfo_destroy_pkginfo(pkghandle);
			/*updated and system pkg need to "remove-update"*/
			ret = _rpm_uninstall_pkg_with_dbpath(pkgid, 1);
			if (ret < 0) {
				_d_msg(DEBUG_ERR, "uninstall_pkg_with_dbpath for system, is_update fail\n");
			}
			return 0;
		}
	} else {
		pkgmgrinfo_pkginfo_is_removable(pkghandle, &is_removable);
		if (is_removable) {
			/*non-system and can be removable,  it should be deleted*/
			pkgmgrinfo_pkginfo_destroy_pkginfo(pkghandle);
			ret = _rpm_uninstall_pkg_with_dbpath(pkgid, 0);
			if (ret < 0) {
				_d_msg(DEBUG_ERR, "uninstall_pkg_with_dbpath for non-system, is_remove fail\n");
			}
			return 0;
		}
	}

	_ri_broadcast_status_notification(pkgid, "start", "uninstall");

#ifdef APP2EXT_ENABLE
	ret = pkgmgrinfo_pkginfo_get_install_location(pkghandle, &location);
	if (ret < 0) {
		_d_msg(DEBUG_ERR, "Failed to get install location\n");
		pkgmgr_pkginfo_destroy_pkginfo(pkghandle);
		return RPM_INSTALLER_ERR_INTERNAL;
	}

	pkgmgrinfo_appinfo_get_list(pkghandle, PM_UI_APP, __ri_check_running_app, NULL);

	pkgmgrinfo_pkginfo_destroy_pkginfo(pkghandle);
	if (location == PM_INSTALL_LOCATION_PREFER_EXTERNAL) {
		handle = app2ext_init(APP2EXT_SD_CARD);
		if (handle == NULL) {
			_d_msg(DEBUG_ERR, "app2ext init failed\n");
			return RPM_INSTALLER_ERR_INTERNAL;
		}
		if ((&(handle->interface) != NULL) && (handle->interface.pre_uninstall != NULL) && (handle->interface.post_uninstall != NULL)){
			ret = app2ext_get_app_location(pkgid);
			if (ret == APP2EXT_INTERNAL_MEM){
					_d_msg(DEBUG_ERR, "app2xt APP is not in MMC, go internal (%d)\n", ret);
			}
			else {
				ret = handle->interface.pre_uninstall(pkgid);
				if (ret == APP2EXT_ERROR_MMC_STATUS || ret == APP2EXT_SUCCESS ) {
					_d_msg(DEBUG_ERR, "app2xt MMC is not here, go internal (%d)\n", ret);
				}
				else {
					_d_msg(DEBUG_ERR, "app2xt pre uninstall API failed (%d)\n", ret);
					handle->interface.post_uninstall(pkgid);
					app2ext_deinit(handle);
					return RPM_INSTALLER_ERR_INTERNAL;
				}
			}
		}
	}
#endif

#ifdef PRE_CHECK_FOR_MANIFEST
	/*Manifest info should be removed first because after installation manifest
	file is uninstalled. If uninstallation fails, we need to re-insert manifest info for consistency*/
	manifest = pkgmgr_parser_get_manifest_file(pkgid);
	if (manifest == NULL) {
		_d_msg(DEBUG_ERR, "manifest name is NULL\n");
		app2ext_deinit(handle);
		return RPM_INSTALLER_ERR_NO_MANIFEST;
	}
	_d_msg(DEBUG_INFO, "manifest name is %s\n", manifest);
	ret = pkgmgr_parser_parse_manifest_for_uninstallation(manifest, NULL);
	if (ret < 0) {
		_d_msg(DEBUG_ERR, "pkgmgr_parser_parse_manifest_for_uninstallation failed.\n");
	}

#endif

	ret = __rpm_xsystem(argv);
	if (ret != 0) {
		_d_msg(DEBUG_ERR, "uninstall failed with error(%d)\n", ret);
		#ifdef PRE_CHECK_FOR_MANIFEST
		err = pkgmgr_parser_parse_manifest_for_installation(manifest, NULL);
		if (err < 0) {
			_d_msg(DEBUG_ERR, "Parsing Manifest Failed\n");
		}
		if (manifest) {
			free(manifest);
			manifest = NULL;
		}
		#endif
		#ifdef APP2EXT_ENABLE
		if ((handle != NULL) && (handle->interface.post_uninstall != NULL)){
			handle->interface.post_uninstall(pkgid);
			app2ext_deinit(handle);
		}
		#endif
		return ret;
	}

#ifdef APP2EXT_ENABLE
	if ((handle != NULL) && (handle->interface.post_uninstall != NULL)){
		handle->interface.post_uninstall(pkgid);
		app2ext_deinit(handle);
	}
#endif

#ifdef PRE_CHECK_FOR_MANIFEST
	if (manifest) {
		free(manifest);
		manifest = NULL;
	}
#endif
	/* Uninstallation Success. Remove the installation time key from vconf*/
	snprintf(buff, BUF_SIZE, "db/app-info/%s/installed-time", pkgid);
	err = vconf_unset(buff);
	if (err) {
		_d_msg(DEBUG_ERR, "unset installation time failed\n");
	}
	/*execute privilege APIs*/
	_ri_privilege_revoke_permissions(pkgid);
	_ri_privilege_unregister_package(pkgid);
	/*Unregister cert info*/
	_ri_unregister_cert(gpkgname);

	_d_msg(DEBUG_INFO, "end : _rpm_uninstall_pkg(%d)\n", ret);
	return ret;
}

int _rpm_install_corexml(char *pkgfilepath, char *pkgid)
{
	/*validate signature and certifictae*/
	char buff[BUF_SIZE] = {'\0'};
	int ret = 0;

	ret = _ri_verify_signatures(USR_APPS, pkgid);
    if (ret < 0) {
		_d_msg(DEBUG_ERR, "_ri_verify_signatures Failed : %s\n", pkgid);
		ret = RPM_INSTALLER_ERR_SIG_INVALID;
		goto err;
    }

	/* check : given pkgid is deactivation*/
	ret = __ri_check_pkgid_for_deactivation(pkgid);
	if (ret < 0) {
		_d_msg(DEBUG_ERR, "pkgid[%s] for deactivation dont need to install.\n", pkgid);
		goto err;
	}

	/* Parse and insert manifest in DB*/
    ret = pkgmgr_parser_parse_manifest_for_installation(pkgfilepath, NULL);
    if (ret < 0) {
		_d_msg(DEBUG_RESULT, "Installing Manifest Failed : %s\n", pkgfilepath);
		ret = RPM_INSTALLER_ERR_PACKAGE_NOT_INSTALLED;
		goto err;
    }

    // _ri_register_cert has __ri_free_cert_chain.
    _ri_register_cert(pkgid);

	ret = RPM_INSTALLER_SUCCESS;

err:
	if (ret != 0) {
		__ri_free_cert_chain();
	}

	return ret;

}

int _rpm_install_pkg(char *pkgfilepath, char *installoptions)
{
	int ret = 0;
	time_t cur_time;
	char buff[BUF_SIZE] = {'\0'};
	char manifest[BUF_SIZE] = { '\0'};
	manifest_x *mfx = NULL;
	pkgmgrinfo_install_location location = 1;
	int size = -1;
#ifdef APP2EXT_ENABLE
	app2ext_handle *handle = NULL;
	GList *dir_list = NULL;
#endif
	const char *argv[] = {
		INSTALL_SCRIPT, pkgfilepath, installoptions, NULL
	};

#ifdef PRE_CHECK_FOR_MANIFEST
	char cwd[BUF_SIZE] = {'\0'};
	int m_exist = 0;
	/*flag to test whether app home dir is /usr or /opt*/
	int home_dir = 0;
	getcwd(cwd, BUF_SIZE);
	if (cwd[0] == '\0') {
		_d_msg(DEBUG_ERR, "getcwd() Failed\n");
		return RPM_INSTALLER_ERR_INTERNAL;
	}
	_d_msg(DEBUG_ERR, "Current working directory is %s\n", cwd);
	ret = mkdir(TEMP_DIR, 0644);
	if (ret < 0) {
		if (access(TEMP_DIR, F_OK) == 0) {
			__rpm_delete_dir(TEMP_DIR);
			ret = mkdir(TEMP_DIR, 0644);
			if (ret < 0) {
				_d_msg(DEBUG_ERR, "mkdir() failed\n");
				return RPM_INSTALLER_ERR_INTERNAL;
			}
		} else {
			_d_msg(DEBUG_ERR, "mkdir() failed\n");
			return RPM_INSTALLER_ERR_INTERNAL;
		}
	}

	ret = chdir(TEMP_DIR);
	if (ret != 0) {
		_d_msg(DEBUG_ERR, "chdir(%s) failed [%s]\n", TEMP_DIR, strerror(errno));
		ret = RPM_INSTALLER_ERR_INTERNAL;
		goto err;
	}
	_d_msg(DEBUG_ERR, "Switched to %s\n", TEMP_DIR);

	const char *cpio_argv[] = { CPIO_SCRIPT, pkgfilepath, NULL };
	ret = __rpm_xsystem(cpio_argv);

	snprintf(manifest, BUF_SIZE, "%s/opt/share/packages/%s.xml", TEMP_DIR, gpkgname);
	_d_msg(DEBUG_ERR, "Manifest name is %s\n", manifest);
	if (access(manifest, F_OK)) {
		_d_msg(DEBUG_ERR, "No rw Manifest File Found\n");

		snprintf(manifest, BUF_SIZE, "%s/usr/share/packages/%s.xml", TEMP_DIR, gpkgname);
		_d_msg(DEBUG_ERR, "Manifest ro name is %s\n", manifest);

		if (access(manifest, F_OK)) {
			_d_msg(DEBUG_ERR, "No ro Manifest File Found\n");
			ret = RPM_INSTALLER_ERR_NO_MANIFEST;
			goto err;
		} else {
			m_exist = 1;
			home_dir = 0;
		}
	} else {
		m_exist = 1;
		home_dir = 1;
	}
	if (m_exist) {
		ret = pkgmgr_parser_check_manifest_validation(manifest);
		if(ret < 0) {
			_d_msg(DEBUG_ERR, "Invalid manifest\n");
			ret = RPM_INSTALLER_ERR_INVALID_MANIFEST;
			goto err;
		}
		/*get package name from xml*/
		mfx = pkgmgr_parser_process_manifest_xml(manifest);
		if (mfx) {
			if (gpkgname) {
				free(gpkgname);
				gpkgname = strdup(mfx->package);
			}
		}
		pkgmgr_parser_free_manifest_xml(mfx);
	}
	/*check for signature and certificate*/
	_ri_verify_signatures(TEMP_DIR, gpkgname);
    if (ret < 0) {
		_d_msg(DEBUG_ERR, "_ri_verify_signatures Failed : %s\n", gpkgname);
		ret = RPM_INSTALLER_ERR_SIG_INVALID;
		goto err;
    }

	ret = chdir(cwd);
	if (ret != 0) {
		_d_msg(DEBUG_ERR, "chdir(%s) failed [%s]\n", cwd, strerror(errno));
		ret = RPM_INSTALLER_ERR_INTERNAL;
		goto err;
	}

#endif

#ifdef APP2EXT_ENABLE
	ret = __get_location_from_xml(manifest, &location);
	if (ret < 0) {
		_d_msg(DEBUG_ERR, "Failed to get install location\n");
		ret = RPM_INSTALLER_ERR_INTERNAL;
		goto err;
	} else {
		if (location == PMINFO_INSTALL_LOCATION_PREFER_EXTERNAL) {
			ret = __get_size_from_xml(manifest, &size);
			if (ret < 0) {
				_d_msg(DEBUG_ERR, "Failed to get package size\n");
				ret = RPM_INSTALLER_ERR_INTERNAL;
				goto err;
			}
		}
	}

	if ((location == PMINFO_INSTALL_LOCATION_PREFER_EXTERNAL) && size > 0) {
		handle = app2ext_init(APP2EXT_SD_CARD);
		if (handle == NULL) {
			_d_msg(DEBUG_ERR, "app2ext init failed\n");
			ret = RPM_INSTALLER_ERR_INTERNAL;
			goto err;
		}
		if ((&(handle->interface) != NULL) && (handle->interface.pre_install != NULL) && (handle->interface.post_install != NULL)){
			dir_list = __rpm_populate_dir_list();
			if (dir_list == NULL) {
				_d_msg(DEBUG_ERR, "\nError in populating the directory list\n");
				app2ext_deinit(handle);
				ret = RPM_INSTALLER_ERR_RPM_SCRIPT_WRONG_ARGS;
				goto err;
			}
			ret = handle->interface.pre_install(gpkgname, dir_list, size);
			if (ret == APP2EXT_ERROR_MMC_STATUS) {
				_d_msg(DEBUG_ERR, "app2xt MMC is not here, go internal\n");
			} else if (ret == APP2EXT_SUCCESS){
				_d_msg(DEBUG_ERR, "pre_install done, go internal\n");
			}
			else {
				_d_msg(DEBUG_ERR, "app2xt pre install API failed (%d)\n", ret);
				__rpm_clear_dir_list(dir_list);
				handle->interface.post_install(gpkgname, APP2EXT_STATUS_FAILED);
				app2ext_deinit(handle);
				ret = RPM_INSTALLER_ERR_INTERNAL;
				goto err;
			}
		}
	}
#endif

	ret = __rpm_xsystem(argv);

	if (ret != 0) {
		_d_msg(DEBUG_ERR, "install complete with error(%d)\n", ret);

		#ifdef APP2EXT_ENABLE
		if ((handle != NULL) && (handle->interface.post_install != NULL)){
			__rpm_clear_dir_list(dir_list);
			handle->interface.post_install(gpkgname, APP2EXT_STATUS_FAILED);
			app2ext_deinit(handle);
		}
		#endif
		goto err;
	}

#ifdef APP2EXT_ENABLE
	if ((handle != NULL) && (handle->interface.post_install != NULL)){
		__rpm_clear_dir_list(dir_list);
		handle->interface.post_install(gpkgname, APP2EXT_STATUS_SUCCESS);
		app2ext_deinit(handle);
	}
#endif

	/*Parse the manifest to get install location and size. If installation fails, remove manifest info from DB*/
        ret = pkgmgr_parser_parse_manifest_for_installation(manifest, NULL);
        if (ret < 0) {
                _d_msg(DEBUG_ERR, "Parsing Manifest Failed\n");
        } else {
                _d_msg(DEBUG_ERR, "Parsing Manifest Success\n");
        }

	/* Install Success. Store the installation time*/
	cur_time = time(NULL);
	snprintf(buff, BUF_SIZE, "db/app-info/%s/installed-time", gpkgname);
	/* The time is stored in time_t format. It can be converted to
	local time or GMT time as per the need by the apps*/
	if(vconf_set_int(buff, cur_time)) {
		_d_msg(DEBUG_ERR, "setting installation time failed\n");
		vconf_unset(buff);
	}
	__rpm_apply_shared_privileges(gpkgname, home_dir);
	ret = _ri_apply_perm(gpkgname);
	if (ret != 0) {
		_d_msg(DEBUG_ERR, "apply perm failed with err(%d)\n", ret);
	} else {
		_d_msg(DEBUG_INFO, "apply perm success\n");
	}

	/*Register cert info*/
	_ri_register_cert(gpkgname);
err:
	__rpm_delete_dir(TEMP_DIR);
	return ret;
}

int _rpm_upgrade_pkg(char *pkgfilepath, char *installoptions)
{
	int ret = 0;
	char manifest[BUF_SIZE] = { '\0'};
	manifest_x *mfx = NULL;
	char buff[BUF_SIZE] = { '\0' };
	pkgmgr_install_location location = 1;
	int size = -1;
#ifdef APP2EXT_ENABLE
	app2ext_handle *handle = NULL;
	GList *dir_list = NULL;
#endif
	pkgmgr_pkginfo_h pkghandle;

#ifdef PRE_CHECK_FOR_MANIFEST
	char cwd[BUF_SIZE] = {'\0'};
	int m_exist = 0;
	int home_dir = 0;
	getcwd(cwd, BUF_SIZE);
	if (cwd[0] == '\0') {
		_d_msg(DEBUG_ERR, "getcwd() Failed\n");
		return RPM_INSTALLER_ERR_INTERNAL;
	}
	_d_msg(DEBUG_ERR, "Current working directory is %s\n", cwd);
	ret = mkdir(TEMP_DIR, 0644);
	if (ret < 0) {
		if (access(TEMP_DIR, F_OK) == 0) {
			__rpm_delete_dir(TEMP_DIR);
			ret = mkdir(TEMP_DIR, 0644);
			if (ret < 0) {
				_d_msg(DEBUG_ERR, "mkdir() failed\n");
				return RPM_INSTALLER_ERR_INTERNAL;
			}
		} else {
			_d_msg(DEBUG_ERR, "mkdir() failed\n");
			return RPM_INSTALLER_ERR_INTERNAL;
		}
	}
	ret = chdir(TEMP_DIR);
	if (ret != 0) {
		_d_msg(DEBUG_ERR, "chdir(%s) failed [%s]\n", TEMP_DIR, strerror(errno));
		ret = RPM_INSTALLER_ERR_INTERNAL;
		goto err;
	}
	_d_msg(DEBUG_ERR, "Switched to %s\n", TEMP_DIR);

	const char *cpio_argv[] = { CPIO_SCRIPT, pkgfilepath, NULL };
	ret = __rpm_xsystem(cpio_argv);

	snprintf(manifest, BUF_SIZE, "%s/opt/share/packages/%s.xml", TEMP_DIR, gpkgname);
	_d_msg(DEBUG_ERR, "Manifest name is %s\n", manifest);
	if (access(manifest, F_OK)) {
		_d_msg(DEBUG_ERR, "No rw Manifest File Found\n");

		snprintf(manifest, BUF_SIZE, "%s/usr/share/packages/%s.xml", TEMP_DIR, gpkgname);
		_d_msg(DEBUG_ERR, "Manifest ro name is %s\n", manifest);

		if (access(manifest, F_OK)) {
			_d_msg(DEBUG_ERR, "No ro Manifest File Found\n");
			ret = RPM_INSTALLER_ERR_NO_MANIFEST;
			goto err;
		} else {
			m_exist = 1;
			home_dir = 0;
		}
	} else {
		m_exist = 1;
		home_dir = 1;
	}

	if (m_exist) {
		ret = pkgmgr_parser_check_manifest_validation(manifest);
		if(ret < 0) {
			_d_msg(DEBUG_ERR, "Invalid manifest\n");
			ret = RPM_INSTALLER_ERR_INVALID_MANIFEST;
			goto err;
		}
		/*get package name from xml*/
		mfx = pkgmgr_parser_process_manifest_xml(manifest);
		if (mfx) {
			if (gpkgname) {
				free(gpkgname);
				gpkgname = strdup(mfx->package);
			}
		}
		pkgmgr_parser_free_manifest_xml(mfx);
	}
	/*check for signature and certificate*/
	_ri_verify_signatures(TEMP_DIR, gpkgname);
    if (ret < 0) {
		_d_msg(DEBUG_ERR, "_ri_verify_signatures Failed : %s\n", gpkgname);
		ret = RPM_INSTALLER_ERR_SIG_INVALID;
		goto err;
    }

	ret = chdir(cwd);
	if (ret != 0) {
		_d_msg(DEBUG_ERR, "chdir(%s) failed [%s]\n", cwd, strerror(errno));
		ret = RPM_INSTALLER_ERR_INTERNAL;
		goto err;
	}
	/*Parse the manifest to get install location and size. If upgradation fails, remove manifest info from DB*/
	ret = pkgmgr_parser_parse_manifest_for_upgrade(manifest, NULL);
	if (ret < 0) {
		_d_msg(DEBUG_ERR, "Parsing Manifest Failed\n");
		ret = RPM_INSTALLER_ERR_INTERNAL;
		goto err;
	} else {
		_d_msg(DEBUG_ERR, "Parsing Manifest Success\n");
	}
#endif

#ifdef APP2EXT_ENABLE
	ret = pkgmgr_pkginfo_get_pkginfo(gpkgname, &pkghandle);
	if (ret < 0) {
		_d_msg(DEBUG_ERR, "Failed to get pkginfo handle\n");
		ret = RPM_INSTALLER_ERR_PKG_NOT_FOUND;
		goto err;
	} else {
		ret = pkgmgr_pkginfo_get_install_location(pkghandle, &location);
		if (ret < 0) {
			_d_msg(DEBUG_ERR, "Failed to get install location\n");
			pkgmgr_pkginfo_destroy_pkginfo(pkghandle);
			ret = RPM_INSTALLER_ERR_INTERNAL;
			goto err;
		} else {
			if (location == PM_INSTALL_LOCATION_PREFER_EXTERNAL) {
				ret = pkgmgr_pkginfo_get_package_size(pkghandle, &size);
				if (ret < 0) {
					_d_msg(DEBUG_ERR, "Failed to get package size\n");
					pkgmgr_pkginfo_destroy_pkginfo(pkghandle);
					ret = RPM_INSTALLER_ERR_INTERNAL;
					goto err;
				}
			}
		}
		pkgmgr_pkginfo_destroy_pkginfo(pkghandle);
		if ((location == PM_INSTALL_LOCATION_PREFER_EXTERNAL) && size > 0) {
			handle = app2ext_init(APP2EXT_SD_CARD);
			if (handle == NULL) {
				_d_msg(DEBUG_ERR, "app2ext init failed\n");
				ret = RPM_INSTALLER_ERR_INTERNAL;
				goto err;
			}
			if ((&(handle->interface) != NULL) && (handle->interface.pre_upgrade != NULL) && (handle->interface.post_upgrade != NULL)){
				dir_list = __rpm_populate_dir_list();
				if (dir_list == NULL) {
					_d_msg(DEBUG_ERR, "\nError in populating the directory list\n");
					ret = RPM_INSTALLER_ERR_RPM_SCRIPT_WRONG_ARGS;
					app2ext_deinit(handle);
					goto err;
				}
				ret = handle->interface.pre_upgrade(gpkgname, dir_list, size);
				if (ret == APP2EXT_ERROR_MMC_STATUS || ret == APP2EXT_SUCCESS ) {
					_d_msg(DEBUG_ERR, "app2xt MMC is not here, go internal (%d)\n", ret);
				}
				else {
					_d_msg(DEBUG_ERR, "app2xt pre upgrade API failed (%d)\n", ret);
					__rpm_clear_dir_list(dir_list);
					handle->interface.post_upgrade(gpkgname, APP2EXT_STATUS_FAILED);
					ret = RPM_INSTALLER_ERR_INTERNAL;
					app2ext_deinit(handle);
					goto err;
				}
			}
		}
	}
#endif
	const char *upgrade_argv[] = {UPGRADE_SCRIPT, pkgfilepath, installoptions, NULL};
	ret = __rpm_xsystem(upgrade_argv);
	if (ret != 0) {
		_d_msg(DEBUG_ERR, "upgrade complete with error(%d)\n", ret);
		/*remove manifest info*/
		#ifdef PRE_CHECK_FOR_MANIFEST
//		pkgmgr_parser_parse_manifest_for_uninstallation(manifest, NULL);
		#endif
		#ifdef APP2EXT_ENABLE
		if ((handle != NULL) && (handle->interface.post_upgrade != NULL)){
			__rpm_clear_dir_list(dir_list);
			handle->interface.post_upgrade(gpkgname, APP2EXT_STATUS_FAILED);
			app2ext_deinit(handle);
		}
		#endif
		goto err;
	}
#ifdef APP2EXT_ENABLE
	if ((handle != NULL) && (handle->interface.post_upgrade != NULL)){
		__rpm_clear_dir_list(dir_list);
		handle->interface.post_upgrade(gpkgname, APP2EXT_STATUS_SUCCESS);
		app2ext_deinit(handle);
	}
#endif

	__rpm_apply_shared_privileges(gpkgname, home_dir);
	ret = _ri_apply_perm(gpkgname);
	if (ret != 0) {
		_d_msg(DEBUG_ERR, "apply perm failed with err(%d)\n", ret);
	} else {
		_d_msg(DEBUG_INFO, "apply perm success\n");
	}

	/*Register cert info*/
	_ri_unregister_cert(gpkgname);
	_ri_register_cert(gpkgname);
err:
	__rpm_delete_dir(TEMP_DIR);
	return ret;
}

int _rpm_move_pkg(char *pkgid, int move_type)
{
	app2ext_handle *hdl = NULL;
	int ret = 0;
	int movetype = -1;
	GList *dir_list = NULL;

	if (move_type == PM_MOVE_TO_INTERNAL)
		movetype = APP2EXT_MOVE_TO_PHONE;
	else if (move_type == PM_MOVE_TO_SDCARD)
		movetype = APP2EXT_MOVE_TO_EXT;
	else
		return RPM_INSTALLER_ERR_WRONG_PARAM;

	hdl = app2ext_init(APP2EXT_SD_CARD);
	if ((hdl != NULL) && (hdl->interface.move != NULL)){
		dir_list = __rpm_populate_dir_list();
		if (dir_list == NULL) {
			_d_msg(DEBUG_ERR, "\nError in populating the directory list\n");
			return RPM_INSTALLER_ERR_RPM_SCRIPT_WRONG_ARGS;
		}
		ret = hdl->interface.move(pkgid, dir_list, movetype);
		__rpm_clear_dir_list(dir_list);
		if (ret != 0) {
			_d_msg(DEBUG_ERR, "Failed to move app\n");
			return RPM_INSTALLER_ERR_INTERNAL;
		}
		app2ext_deinit(hdl);
		return RPM_INSTALLER_SUCCESS;
	} else {
		_d_msg(DEBUG_ERR,"Failed to get app2ext handle\n");
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
	char csc_str[BUF_SIZE] = {'\0'};
	snprintf(csc_str, BUF_SIZE - 1, "%s:", csc_script);

	/*get params from csc script*/
	path_str = __ri_get_str(csc_str, TOKEN_PATH_STR);
	op_str = __ri_get_str(csc_str, TOKEN_OPERATION_STR);
	remove_str = __ri_get_str(csc_str, TOKEN_REMOVE_STR);
	if((path_str == NULL) || (op_str == NULL) || (remove_str == NULL)){
		_d_msg(DEBUG_ERR, "csc-info : input param is null[%s, %s, %s]\n", path_str, op_str, remove_str);
		goto end;
	}
	_d_msg(DEBUG_INFO, "csc-info : path=%s, op=%s, remove=%s\n", path_str, op_str, remove_str);

	/*get operation type*/
	op_type = __ri_get_op_type(op_str);
	if(op_type < 0){
		_d_msg(DEBUG_ERR, "csc-info : operation error[%s, %s]\n", path_str, op_str);
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
		_d_msg(DEBUG_ERR, "fota-info : Fota fail [pkgid=%s, operation=%d]\n",path_str, op_type);

end:
	if(path_str)
		free(path_str);
	if(op_str)
		free(op_str);
	if(remove_str)
		free(remove_str);

	return ret;
}

int _rpm_process_fota(char *fota_script)
{
	int ret = 0;
	int op_type = 0;
	char *pkgid = NULL;
	char *op_str = NULL;

	char csc_str[BUF_SIZE] = {'\0'};
	snprintf(csc_str, BUF_SIZE - 1, "%s:", fota_script);

	/*get params from fota script*/
	pkgid = __ri_get_str(csc_str, TOKEN_PATH_STR);
	op_str = __ri_get_str(csc_str, TOKEN_OPERATION_STR);
	if((pkgid == NULL) || (op_str == NULL)){
		_d_msg(DEBUG_ERR, "fota-info : input param is null[%s, %s]\n", pkgid, op_str);
		goto end;
	}
	_d_msg(DEBUG_INFO, "fota-info : path=%s, op=%s\n", pkgid, op_str);

	/*get operation type*/
	op_type = __ri_get_op_type(op_str);
	if(op_type < 0){
		_d_msg(DEBUG_ERR, "fota-info : operation error[%s, %s]\n", pkgid, op_str);
		goto end;
	}

	switch (op_type) {
		case INSTALL_REQ:
			ret = __ri_install_fota(pkgid);
			break;

		case UPGRADE_REQ:
			ret = __ri_upgrade_fota(pkgid);
			break;

		case UNINSTALL_REQ:
			ret = __ri_uninstall_fota(pkgid);
			break;

		default:
			break;
	}

	if (ret < 0)
		_d_msg(DEBUG_ERR, "fota-info : Fota fail [pkgid=%s, operation=%d]\n",pkgid, op_type);

end:
	if(pkgid)
		free(pkgid);
	if(op_str)
		free(op_str);

	return ret;
}

int _rpm_process_fota_for_rw(char *fota_script)
{
	int ret = 0;
	int op_type = 0;
	char *pkgid = NULL;
	char *op_str = NULL;

	char fota_str[BUF_SIZE] = {'\0'};
	snprintf(fota_str, BUF_SIZE - 1, "%s:", fota_script);

	/*get params from fota script*/
	pkgid = __ri_get_str(fota_str, TOKEN_PATH_STR);
	op_str = __ri_get_str(fota_str, TOKEN_OPERATION_STR);
	if((pkgid == NULL) || (op_str == NULL)){
		_d_msg(DEBUG_ERR, "fota-info : input param is null[%s, %s]\n", pkgid, op_str);
		goto end;
	}
	_d_msg(DEBUG_INFO, "fota-info : path=%s, op=%s\n", pkgid, op_str);

	/*get operation type*/
	op_type = __ri_get_op_type(op_str);
	if(op_type < 0){
		_d_msg(DEBUG_ERR, "fota-info : operation error[%s, %s]\n", pkgid, op_str);
		goto end;
	}

	switch (op_type) {
		case INSTALL_REQ:
			ret = __ri_install_fota_for_rw(pkgid);
			break;

		case UPGRADE_REQ:
			ret = __ri_upgrade_fota_for_rw(pkgid);
			break;

		case UNINSTALL_REQ:
			ret = __ri_uninstall_fota_for_rw(pkgid);
			break;

		default:
			break;
	}

	if (ret < 0)
		_d_msg(DEBUG_ERR, "fota-info : Fota fail [pkgid=%s, operation=%d]\n",pkgid, op_type);

end:
	if(pkgid)
		free(pkgid);
	if(op_str)
		free(op_str);

	sync();

	return ret;
}

int _rpm_process_enable(char *pkgid)
{
	int ret = 0;
	char *manifest = NULL;
	pkgmgrinfo_pkginfo_h handle;
	bool is_system = 0;

	_d_msg(DEBUG_ERR, "start :: pkgid[%s] enable process\n",pkgid);

	ret = pkgmgrinfo_pkginfo_get_pkginfo(pkgid, &handle);
	if ((ret == 0) && (handle != NULL)) {
		_d_msg(DEBUG_ERR, "pkg[%s] is already installed.", pkgid);
		pkgmgrinfo_pkginfo_destroy_pkginfo(handle);
		return 0;
	}

	manifest = pkgmgr_parser_get_manifest_file(pkgid);
	if (manifest == NULL) {
		_d_msg(DEBUG_ERR, "Failed to fetch package manifest file\n");
		return -1;
	}

	_ri_broadcast_status_notification(pkgid, PKGMGR_INSTALLER_START_KEY_STR, PKGMGR_INSTALLER_INSTALL_EVENT_STR);

	ret = pkgmgr_parser_parse_manifest_for_installation(manifest, NULL);
	free(manifest);
	if (ret < 0) {
		_ri_broadcast_status_notification(pkgid, PKGMGR_INSTALLER_END_KEY_STR, PKGMGR_INSTALLER_FAIL_EVENT_STR);
		_d_msg(DEBUG_ERR, "insert in db failed\n");
		return -1;
	}

	ret = pkgmgrinfo_pkginfo_get_pkginfo(pkgid, &handle);
	if (ret < 0) {
		_d_msg(DEBUG_ERR, "insert in db failed\n");
	} else {
		ret = pkgmgrinfo_pkginfo_is_system(handle, &is_system);
		if (is_system) {
			pkgmgrinfo_appinfo_get_list(handle, PM_UI_APP, __ri_update_ail_info, NULL);
		}
		pkgmgrinfo_pkginfo_destroy_pkginfo(handle);
	}

	/*delete disabled pkg info from backup db table*/
	pkgmgr_parser_delete_disabled_pkg(pkgid, NULL);

	_ri_broadcast_status_notification(pkgid, PKGMGR_INSTALLER_END_KEY_STR, PKGMGR_INSTALLER_OK_EVENT_STR);

	_d_msg(DEBUG_ERR, "end :: pkgid[%s] enable process\n",pkgid);

	return 0;
}

int _rpm_process_disable(char *pkgid)
{
	int ret = 0;
	pkgmgrinfo_pkginfo_h handle;

	_d_msg(DEBUG_ERR, "start :: pkgid[%s] disable process\n",pkgid);

	ret = pkgmgrinfo_pkginfo_get_pkginfo(pkgid, &handle);
	if ((ret < 0) || (handle == NULL)) {
		_d_msg(DEBUG_ERR, "pkgid[%s] is already disabled\n", pkgid);
		return 0;
	}

	_ri_broadcast_status_notification(pkgid, PKGMGR_INSTALLER_START_KEY_STR, PKGMGR_INSTALLER_UNINSTALL_EVENT_STR);

	pkgmgrinfo_appinfo_get_list(handle, PM_UI_APP, __ri_check_running_app, NULL);
	pkgmgrinfo_pkginfo_destroy_pkginfo(handle);

	ret = pkgmgr_parser_parse_manifest_for_uninstallation(pkgid, NULL);
	if (ret < 0) {
		_ri_broadcast_status_notification(pkgid, PKGMGR_INSTALLER_END_KEY_STR, PKGMGR_INSTALLER_FAIL_EVENT_STR);
		_d_msg(DEBUG_ERR, "pkgmgr_parser_parse_manifest_for_uninstallation failed.\n");
		return -1;
	}

	/*save disabled pkg info to backup db table*/
	pkgmgr_parser_insert_disabled_pkg(pkgid, NULL);

	_ri_broadcast_status_notification(pkgid, PKGMGR_INSTALLER_END_KEY_STR, PKGMGR_INSTALLER_OK_EVENT_STR);

	_d_msg(DEBUG_ERR, "end :: pkgid[%s] disable process\n",pkgid);
	return 0;
}

int _rpm_process_enabled_list(const char *enabled_list)
{
	char* token = NULL;
	char delims[] = ":";
	char pkgid[MAX_BUF_SIZE] = {'\0'};
	char pkgid_list[MAX_BUF_SIZE] = {'\0'};

	if (enabled_list == NULL)
		return -1;

	snprintf(pkgid_list, MAX_BUF_SIZE, "%s", enabled_list);
	token = strtok(pkgid_list, delims);

	while(token)
	{
		memset(pkgid, 0x00, sizeof(pkgid));
		strncat(pkgid, token, strlen(token));

		_rpm_process_enable(pkgid);

		token = strtok(NULL, delims);
	}

	return 0;
}

int _rpm_process_disabled_list(const char *disabled_list)
{
	char* token = NULL;
	char delims[] = ":";
	char pkgid[MAX_BUF_SIZE] = {'\0'};
	char pkgid_list[MAX_BUF_SIZE] = {'\0'};

	if (disabled_list == NULL)
		return -1;

	snprintf(pkgid_list, MAX_BUF_SIZE, "%s", disabled_list);
	token = strtok(pkgid_list, delims);

	while(token)
	{
		memset(pkgid, 0x00, sizeof(pkgid));
		strncat(pkgid, token, strlen(token));

		_rpm_process_disable(pkgid);

		token = strtok(NULL, delims);
	}

	return 0;
}

