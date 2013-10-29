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

#include "rpm-installer-util.h"
#include "rpm-installer-signature.h"
#include "rpm-installer.h"
#include "rpm-frontend.h"

#define PRE_CHECK_FOR_MANIFEST
#define INSTALL_SCRIPT		"/usr/bin/install_rpm_package.sh"
#define UNINSTALL_SCRIPT	"/usr/bin/uninstall_rpm_package.sh"
#define UPGRADE_SCRIPT	"/usr/bin/upgrade_rpm_package.sh"
#define RPM2CPIO	"/usr/bin/rpm2cpio"
#define TEMP_DIR			"/tmp/@@rpminstaller@@"
#define SIGNATURE1_XML		"signature1.xml"
#define SIGNATURE2_XML		"signature2.xml"
#define AUTHOR_SIGNATURE_XML		"author-signature.xml"
#define USR_APPS			"/usr/apps"
#define OPT_USR_APPS			"/opt/usr/apps"
#define BUFF_SIZE			256
#define APP_OWNER_ID		5000
#define APP_GROUP_ID		5000
#define MAX_BUFF_LEN		4096
#define MAX_CERT_NUM		9

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

enum rpm_app_path_type {
	RPM_APP_PATH_PRIVATE,
	RPM_APP_PATH_GROUP_RW,
	RPM_APP_PATH_PUBLIC_RO,
	RPM_APP_PATH_SETTINGS_RW,
	RPM_APP_PATH_NPRUNTIME,
	RPM_APP_PATH_ANY_LABEL
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
	char buf[BUFF_SIZE] = {'\0'};
	char dirpath[BUFF_SIZE] = {'\0'};
	/*execute privilege APIs. The APIs should not fail*/
	_ri_privilege_register_package(pkgname);

	/*home dir. Dont setup path but change smack access to "_" */
	snprintf(dirpath, BUFF_SIZE, "/usr/apps/%s", pkgname);
	if (__is_dir(dirpath))
		_ri_privilege_change_smack_label(dirpath, "_", 0);/*0 is SMACK_LABEL_ACCESS*/
	memset(dirpath, '\0', BUFF_SIZE);
	snprintf(dirpath, BUFF_SIZE, "/opt/usr/apps/%s", pkgname);
	if (__is_dir(dirpath))
		_ri_privilege_change_smack_label(dirpath, "_", 0);/*0 is SMACK_LABEL_ACCESS*/
	memset(dirpath, '\0', BUFF_SIZE);

	/*/shared dir. Dont setup path but change smack access to "_" */
	snprintf(dirpath, BUFF_SIZE, "/usr/apps/%s/shared", pkgname);
	if (__is_dir(dirpath))
		_ri_privilege_change_smack_label(dirpath, "_", 0);/*0 is SMACK_LABEL_ACCESS*/
	memset(dirpath, '\0', BUFF_SIZE);
	snprintf(dirpath, BUFF_SIZE, "/opt/usr/apps/%s/shared", pkgname);
	if (__is_dir(dirpath))
		_ri_privilege_change_smack_label(dirpath, "_", 0);/*0 is SMACK_LABEL_ACCESS*/
	memset(dirpath, '\0', BUFF_SIZE);

	/*/shared/res dir. setup path and change smack access to "_" */
	if (flag == 0)
		snprintf(dirpath, BUFF_SIZE, "/usr/apps/%s/shared/res", pkgname);
	else
		snprintf(dirpath, BUFF_SIZE, "/opt/usr/apps/%s/shared/res", pkgname);
	if (__is_dir(dirpath))
		_ri_privilege_setup_path(pkgname, dirpath, RPM_APP_PATH_ANY_LABEL, "_");
	memset(dirpath, '\0', BUFF_SIZE);

	/*/shared/data dir. setup path and change group to 'app'*/
	if (flag == 0)
		snprintf(dirpath, BUFF_SIZE, "/usr/apps/%s/shared/data", pkgname);
	else
		snprintf(dirpath, BUFF_SIZE, "/opt/usr/apps/%s/shared/data", pkgname);
	if (__is_dir(dirpath)) {
		ret = chown(dirpath, APP_OWNER_ID, APP_GROUP_ID);
		if (ret == -1) {
			strerror_r(errno, buf, sizeof(buf));
			_d_msg(DEBUG_ERR, "FAIL : chown %s %d.%d, because %s", dirpath, APP_OWNER_ID, APP_GROUP_ID, buf);
			return;
		}
		_ri_privilege_setup_path(pkgname, dirpath, RPM_APP_PATH_PUBLIC_RO, NULL);
	} else {
		memset(dirpath, '\0', BUFF_SIZE);
		if (flag == 0)
			snprintf(dirpath, BUFF_SIZE, "/opt/usr/apps/%s/shared/data", pkgname);
		else
			snprintf(dirpath, BUFF_SIZE, "/usr/apps/%s/shared/data", pkgname);
		if (__is_dir(dirpath))
			ret = chown(dirpath, APP_OWNER_ID, APP_GROUP_ID);
			if (ret == -1) {
				strerror_r(errno, buf, sizeof(buf));
				_d_msg(DEBUG_ERR, "FAIL : chown %s %d.%d, because %s", dirpath, APP_OWNER_ID, APP_GROUP_ID, buf);
				return;
			}
			_ri_privilege_setup_path(pkgname, dirpath, RPM_APP_PATH_PUBLIC_RO, NULL);
	}
}

static int __is_dir(char *dirname)
{
	struct stat stFileInfo;
	stat(dirname, &stFileInfo);
	if (S_ISDIR(stFileInfo.st_mode)) {
		return 1;
	}
	return 0;
}

static int __rpm_delete_dir(char *dirname)
{
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
					__rpm_delete_dir(abs_filename);
					remove(abs_filename);
				}
			} else {
				remove(abs_filename);
			}
		}
		(void)closedir(dp);
	} else {
		_d_msg(DEBUG_ERR, "Couldn't open the directory\n");
		return -1;
	}
	remove(dirname);
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
	static char buffer[1024] = { 0, };
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

static int __rpm_xsystem(const char *argv[])
{
	int err = 0;
	int status = 0;
	pid_t pid;
	int pipefd[2];

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
			dup(pipefd[1]);
			dup(pipefd[1]);
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

void _ri_apply_smack(char *pkgname, int flag)
{
	__rpm_apply_shared_privileges(pkgname, flag);
}

int _rpm_uninstall_pkg(char *pkgid)
{
	int ret = 0;
	int err = 0;
	char buff[BUFF_SIZE] = {'\0'};
	pkgmgr_install_location location = 1;
#ifdef APP2EXT_ENABLE
	app2ext_handle *handle = NULL;
#endif
	char *manifest = NULL;
	pkgmgr_pkginfo_h pkghandle;
	const char *argv[] = { UNINSTALL_SCRIPT, pkgid, NULL };

#ifdef APP2EXT_ENABLE
	ret = pkgmgr_pkginfo_get_pkginfo(pkgid, &pkghandle);
	if (ret < 0) {
		_d_msg(DEBUG_ERR, "Failed to get pkginfo handle\n");
		return RPM_INSTALLER_ERR_PKG_NOT_FOUND;
	} else {
		ret = pkgmgr_pkginfo_get_install_location(pkghandle, &location);
		if (ret < 0) {
			_d_msg(DEBUG_ERR, "Failed to get install location\n");
			pkgmgr_pkginfo_destroy_pkginfo(pkghandle);
			return RPM_INSTALLER_ERR_INTERNAL;
		}
		pkgmgr_pkginfo_destroy_pkginfo(pkghandle);
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
	pkgmgr_parser_parse_manifest_for_uninstallation(manifest, NULL);
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
	snprintf(buff, BUFF_SIZE, "db/app-info/%s/installed-time", pkgid);
	err = vconf_unset(buff);
	if (err) {
		_d_msg(DEBUG_ERR, "unset installation time failed\n");
	}
	/*execute privilege APIs*/
	_ri_privilege_revoke_permissions(pkgid);
	_ri_privilege_unregister_package(pkgid);
	/*Unregister cert info*/
	_ri_unregister_cert(gpkgname);
	return ret;
}

int _rpm_install_corexml(char *pkgfilepath, char *pkgid)
{
	/*validate signature and certifictae*/
	char buff[BUFF_SIZE] = {'\0'};
	int ret = 0;
	char *homedir = NULL;

	if (sig_enable) {
		/*chdir to appropriate dir*/
		snprintf(buff, BUFF_SIZE, "/usr/apps/%s", pkgid);
		if (__is_dir(buff)) {
			ret = chdir(buff);
			if (ret != 0) {
				_d_msg(DEBUG_ERR, "chdir() failed [%s]\n", strerror(errno));
				return RPM_INSTALLER_ERR_INTERNAL;
			}
			homedir = USR_APPS;
		} else {
			memset(buff, '\0', BUFF_SIZE);
			snprintf(buff, BUFF_SIZE, "/opt/usr/apps/%s", pkgid);
			if (__is_dir(buff)) {
				ret = chdir(buff);
				if (ret != 0) {
					_d_msg(DEBUG_ERR, "chdir() failed [%s]\n", strerror(errno));
					return RPM_INSTALLER_ERR_INTERNAL;
				}
				homedir = OPT_USR_APPS;
			} else {
				_d_msg(DEBUG_ERR, "Could not find package home directory\n");
				return RPM_INSTALLER_ERR_INVALID_MANIFEST;
			}
		}
		memset(buff, '\0', BUFF_SIZE);

		/*signature2.xml is optional*/
		snprintf(buff, BUFF_SIZE, "%s/%s/signature2.xml", homedir, pkgid);
		_d_msg(DEBUG_INFO, "signature2.xml path is %s\n", buff);
		if (access(buff, F_OK) == 0) {
			ret = _ri_verify_sig_and_cert(buff);
			if (ret) {
				_d_msg(DEBUG_ERR, "Failed to verify [%s]\n", buff);
				goto err;
			}
			_d_msg(DEBUG_INFO, "Successfully verified [%s]\n", buff);
		}
		memset(buff, '\0', BUFF_SIZE);

		/*signature1.xml is mandatory*/
		snprintf(buff, BUFF_SIZE, "%s/%s/signature1.xml", homedir, pkgid);
		_d_msg(DEBUG_INFO, "signature1.xml path is %s\n", buff);
		if (access(buff, F_OK) == 0) {
			ret = _ri_verify_sig_and_cert(buff);
			if (ret) {
				_d_msg(DEBUG_ERR, "Failed to verify [%s]\n", buff);
				goto err;
			}
			_d_msg(DEBUG_INFO, "Successfully verified [%s]\n", buff);
		} else {
			_d_msg(DEBUG_ERR, "No signature1.xml file found\n");
			ret = RPM_INSTALLER_ERR_SIG_NOT_FOUND;
			goto err;
		}
		memset(buff, '\0', BUFF_SIZE);

		/*author-signature.xml is mandatory*/
		snprintf(buff, BUFF_SIZE, "%s/%s/author-signature.xml", homedir, pkgid);
		_d_msg(DEBUG_INFO, "author-signature.xml path is %s\n", buff);
		if (access(buff, F_OK) == 0) {
			ret = _ri_verify_sig_and_cert(buff);
			if (ret) {
				_d_msg(DEBUG_ERR, "Failed to verify [%s]\n", buff);
				goto err;
			}
			_d_msg(DEBUG_INFO, "Successfully verified [%s]\n", buff);
		} else {
			_d_msg(DEBUG_ERR, "No author-signature.xml file found\n");
			ret = RPM_INSTALLER_ERR_SIG_NOT_FOUND;
			goto err;
		}
		memset(buff, '\0', BUFF_SIZE);
	}

	/* Parse and insert manifest in DB*/
    pkgmgr_parser_parse_manifest_for_uninstallation(pkgfilepath, NULL);
    ret = pkgmgr_parser_parse_manifest_for_installation(pkgfilepath, NULL);
    if (ret < 0) {
		_d_msg(DEBUG_RESULT, "Installing Manifest Failed : %s\n", pkgfilepath);
		ret = RPM_INSTALLER_ERR_PACKAGE_NOT_INSTALLED;
		goto err;
    }

	ret = RPM_INSTALLER_SUCCESS;

err:
	__ri_free_cert_chain();
	return ret;

}

int _rpm_install_pkg(char *pkgfilepath, char *installoptions)
{
	int ret = 0;
	time_t cur_time;
	char buff[BUFF_SIZE] = {'\0'};
	char manifest[1024] = { '\0'};
	char *mfst = NULL;
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
	char cwd[1024] = {'\0'};
	char query[1024] = {'\0'};
	int m_exist = 0;
	/*flag to test whether app home dir is /usr or /opt*/
	int home_dir = 0;
	getcwd(cwd, 1024);
	if (cwd[0] == '\0') {
		_d_msg(DEBUG_ERR, "getcwd() Failed\n");
		return RPM_INSTALLER_ERR_INTERNAL;
	}
	_d_msg(DEBUG_ERR, "Current working directory is %s\n", cwd);
	ret = mkdir(TEMP_DIR, 0644);
	if (ret < 0) {
		_d_msg(DEBUG_ERR, "mkdir() failed\n");
		return RPM_INSTALLER_ERR_INTERNAL;
	}
	ret = chdir(TEMP_DIR);
	if (ret != 0) {
		_d_msg(DEBUG_ERR, "chdir() failed [%s]\n", strerror(errno));
		ret = RPM_INSTALLER_ERR_INTERNAL;
		goto err;
	}
	_d_msg(DEBUG_ERR, "Switched to %s\n", TEMP_DIR);
	snprintf(query, 1024, "/usr/bin/rpm2cpio %s | cpio -idmv", pkgfilepath);
	_d_msg(DEBUG_INFO, "query= %s\n", query);
	system(query);
	snprintf(manifest, 1024, "%s/opt/share/packages/%s.xml", TEMP_DIR, gpkgname);
	_d_msg(DEBUG_ERR, "Manifest name is %s\n", manifest);
	if (access(manifest, F_OK)) {
		_d_msg(DEBUG_ERR, "No rw Manifest File Found\n");

		snprintf(manifest, 1024, "%s/usr/share/packages/%s.xml", TEMP_DIR, gpkgname);
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
	if (sig_enable) {
		/*chdir to appropriate dir*/
		snprintf(buff, BUFF_SIZE, "%s/usr/apps/%s", TEMP_DIR, gpkgname);
		ret = chdir(buff);
		if (ret != 0) {
			_d_msg(DEBUG_ERR, "chdir() failed [%s]\n", strerror(errno));
			ret = RPM_INSTALLER_ERR_INTERNAL;
			goto err;
		}
		memset(buff, '\0', BUFF_SIZE);

		/*signature2.xml is optional*/
		snprintf(buff, BUFF_SIZE, "%s/usr/apps/%s/signature2.xml", TEMP_DIR, gpkgname);
		_d_msg(DEBUG_INFO, "signature2.xml path is %s\n", buff);
		if (access(buff, F_OK) == 0) {
			ret = _ri_verify_sig_and_cert(buff);
			if (ret) {
				_d_msg(DEBUG_ERR, "Failed to verify [%s]\n", buff);
				goto err;
			}
			_d_msg(DEBUG_INFO, "Successfully verified [%s]\n", buff);
		}
		memset(buff, '\0', BUFF_SIZE);

		/*signature1.xml is mandatory*/
		snprintf(buff, BUFF_SIZE, "%s/usr/apps/%s/signature1.xml", TEMP_DIR, gpkgname);
		_d_msg(DEBUG_INFO, "signature1.xml path is %s\n", buff);
		if (access(buff, F_OK) == 0) {
			ret = _ri_verify_sig_and_cert(buff);
			if (ret) {
				_d_msg(DEBUG_ERR, "Failed to verify [%s]\n", buff);
				goto err;
			}
			_d_msg(DEBUG_INFO, "Successfully verified [%s]\n", buff);
		} else {
			_d_msg(DEBUG_ERR, "No signature1.xml file found\n");
			ret = RPM_INSTALLER_ERR_SIG_NOT_FOUND;
			goto err;
		}
		memset(buff, '\0', BUFF_SIZE);

		/*author-signature.xml is mandatory*/
		snprintf(buff, BUFF_SIZE, "%s/usr/apps/%s/author-signature.xml", TEMP_DIR, gpkgname);
		_d_msg(DEBUG_INFO, "author-signature.xml path is %s\n", buff);
		if (access(buff, F_OK) == 0) {
			ret = _ri_verify_sig_and_cert(buff);
			if (ret) {
				_d_msg(DEBUG_ERR, "Failed to verify [%s]\n", buff);
				goto err;
			}
			_d_msg(DEBUG_INFO, "Successfully verified [%s]\n", buff);
		} else {
			_d_msg(DEBUG_ERR, "No author-signature.xml file found\n");
			ret = RPM_INSTALLER_ERR_SIG_NOT_FOUND;
			goto err;
		}
		memset(buff, '\0', BUFF_SIZE);
	}
	ret = chdir(cwd);
	if (ret != 0) {
		_d_msg(DEBUG_ERR, "chdir() failed [%s]\n", strerror(errno));
		ret = RPM_INSTALLER_ERR_INTERNAL;
		goto err;
	}

#endif

#ifdef APP2EXT_ENABLE
	ret = pkgmgrinfo_pkginfo_get_location_from_xml(manifest, &location);
	if (ret < 0) {
		_d_msg(DEBUG_ERR, "Failed to get install location\n");
		ret = RPM_INSTALLER_ERR_INTERNAL;
		goto err;
	} else {
		if (location == PMINFO_INSTALL_LOCATION_PREFER_EXTERNAL) {
			ret = pkgmgrinfo_pkginfo_get_size_from_xml(manifest, &size);
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

#ifndef PRE_CHECK_FOR_MANIFEST
	mfst = pkgmgr_parser_get_manifest_file(gpkgname);
	if (mfst == NULL) {
		_d_msg(DEBUG_ERR, "manifest name is NULL\n");
		ret = RPM_INSTALLER_ERR_NO_MANIFEST;
		goto err;
	}
	pkgmgr_parser_parse_manifest_for_installation(mfst, NULL);
	if (mfst) {
		free(mfst);
		mfst = NULL;
	}
#endif
	/* Install Success. Store the installation time*/
	cur_time = time(NULL);
	snprintf(buff, BUFF_SIZE, "db/app-info/%s/installed-time", gpkgname);
	/* The time is stored in time_t format. It can be converted to
	local time or GMT time as per the need by the apps*/
	if(vconf_set_int(buff, cur_time)) {
		_d_msg(DEBUG_ERR, "setting installation time failed\n");
		vconf_unset(buff);
	}
	__rpm_apply_shared_privileges(gpkgname, home_dir);
	/*Register cert info*/
	_ri_register_cert(gpkgname);
err:
	__rpm_delete_dir(TEMP_DIR);
	return ret;
}

int _rpm_upgrade_pkg(char *pkgfilepath, char *installoptions)
{
	int ret = 0;
	char manifest[1024] = { '\0'};
	char *mfst = NULL;
	manifest_x *mfx = NULL;
	char buff[BUFF_SIZE] = { '\0' };
	pkgmgr_install_location location = 1;
	int size = -1;
#ifdef APP2EXT_ENABLE
	app2ext_handle *handle = NULL;
	GList *dir_list = NULL;
#endif
	pkgmgr_pkginfo_h pkghandle;
	const char *argv[] = {
		UPGRADE_SCRIPT, pkgfilepath, installoptions, NULL
	};

#ifdef PRE_CHECK_FOR_MANIFEST
	char cwd[1024] = {'\0'};
	char query[1024] = {'\0'};
	int m_exist = 0;
	int home_dir = 0;
	getcwd(cwd, 1024);
	if (cwd[0] == '\0') {
		_d_msg(DEBUG_ERR, "getcwd() Failed\n");
		return RPM_INSTALLER_ERR_INTERNAL;
	}
	_d_msg(DEBUG_ERR, "Current working directory is %s\n", cwd);
	ret = mkdir(TEMP_DIR, 0644);
	if (ret < 0) {
		_d_msg(DEBUG_ERR, "mkdir() failed\n");
		return RPM_INSTALLER_ERR_INTERNAL;
	}
	ret = chdir(TEMP_DIR);
	if (ret != 0) {
		_d_msg(DEBUG_ERR, "chdir() failed [%s]\n", strerror(errno));
		ret = RPM_INSTALLER_ERR_INTERNAL;
		goto err;
	}
	_d_msg(DEBUG_ERR, "Switched to %s\n", TEMP_DIR);
	snprintf(query, 1024, "/usr/bin/rpm2cpio %s | cpio -idmv", pkgfilepath);
	_d_msg(DEBUG_INFO, "query= %s\n", query);
	system(query);
	snprintf(manifest, 1024, "%s/opt/share/packages/%s.xml", TEMP_DIR, gpkgname);
	_d_msg(DEBUG_ERR, "Manifest name is %s\n", manifest);
	if (access(manifest, F_OK)) {
		_d_msg(DEBUG_ERR, "No rw Manifest File Found\n");

		snprintf(manifest, 1024, "%s/usr/share/packages/%s.xml", TEMP_DIR, gpkgname);
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
	if (sig_enable) {
		/*chdir to appropriate dir*/
		snprintf(buff, BUFF_SIZE, "%s/usr/apps/%s", TEMP_DIR, gpkgname);
		ret = chdir(buff);
		if (ret != 0) {
			_d_msg(DEBUG_ERR, "chdir() failed [%s]\n", strerror(errno));
			ret = RPM_INSTALLER_ERR_INTERNAL;
			goto err;
		}
		memset(buff, '\0', BUFF_SIZE);

		/*signature2.xml is optional*/
		snprintf(buff, BUFF_SIZE, "%s/usr/apps/%s/signature2.xml", TEMP_DIR, gpkgname);
		_d_msg(DEBUG_INFO, "signature2.xml path is %s\n", buff);
		if (access(buff, F_OK) == 0) {
			ret = _ri_verify_sig_and_cert(buff);
			if (ret) {
				_d_msg(DEBUG_ERR, "Failed to verify [%s]\n", buff);
				goto err;
			}
			_d_msg(DEBUG_INFO, "Successfully verified [%s]\n", buff);
		}
		memset(buff, '\0', BUFF_SIZE);

		/*signature1.xml is mandatory*/
		snprintf(buff, BUFF_SIZE, "%s/usr/apps/%s/signature1.xml", TEMP_DIR, gpkgname);
		_d_msg(DEBUG_INFO, "signature1.xml path is %s\n", buff);
		if (access(buff, F_OK) == 0) {
			ret = _ri_verify_sig_and_cert(buff);
			if (ret) {
				_d_msg(DEBUG_ERR, "Failed to verify [%s]\n", buff);
				goto err;
			}
			_d_msg(DEBUG_INFO, "Successfully verified [%s]\n", buff);
		} else {
			_d_msg(DEBUG_ERR, "No signature1.xml file found\n");
			ret = RPM_INSTALLER_ERR_SIG_NOT_FOUND;
			goto err;
		}
		memset(buff, '\0', BUFF_SIZE);

		/*author-signature.xml is mandatory*/
		snprintf(buff, BUFF_SIZE, "%s/usr/apps/%s/author-signature.xml", TEMP_DIR, gpkgname);
		_d_msg(DEBUG_INFO, "author-signature.xml path is %s\n", buff);
		if (access(buff, F_OK) == 0) {
			ret = _ri_verify_sig_and_cert(buff);
			if (ret) {
				_d_msg(DEBUG_ERR, "Failed to verify [%s]\n", buff);
				goto err;
			}
			_d_msg(DEBUG_INFO, "Successfully verified [%s]\n", buff);
		} else {
			_d_msg(DEBUG_ERR, "No author-signature.xml file found\n");
			ret = RPM_INSTALLER_ERR_SIG_NOT_FOUND;
			goto err;
		}
		memset(buff, '\0', BUFF_SIZE);
	}
	ret = chdir(cwd);
	if (ret != 0) {
		_d_msg(DEBUG_ERR, "chdir() failed [%s]\n", strerror(errno));
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

	ret = __rpm_xsystem(argv);
	if (ret != 0) {
		_d_msg(DEBUG_ERR, "upgrade complete with error(%d)\n", ret);
		/*remove manifest info*/
		#ifdef PRE_CHECK_FOR_MANIFEST
		pkgmgr_parser_parse_manifest_for_uninstallation(manifest, NULL);
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

#ifndef PRE_CHECK_FOR_MANIFEST
        mfst = pkgmgr_parser_get_manifest_file(gpkgname);
        if (mfst == NULL) {
                _d_msg(DEBUG_ERR, "manifest name is NULL\n");
                ret = RPM_INSTALLER_ERR_INTERNAL;
		goto err;
        }
        pkgmgr_parser_parse_manifest_for_upgrade(mfst, NULL);
        if (mfst) {
                free(mfst);
                mfst = NULL;
        }
#endif
	__rpm_apply_shared_privileges(gpkgname, home_dir);
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

