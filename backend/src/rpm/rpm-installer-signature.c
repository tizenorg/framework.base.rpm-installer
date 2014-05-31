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
#include <pkgmgr_parser.h>
#include "rpm-installer-util.h"
#include "rpm-installer-signature.h"

#define ASCII(s) (const char *)s
#define XMLCHAR(s) (const xmlChar *)s

static int _ri_next_child_element(xmlTextReaderPtr reader, int depth)
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

static void _ri_free_transform(transform_x *transform)
{
	if (transform == NULL)
		return;
	if (transform->algorithm) {
	        free((void *)transform->algorithm);
	        transform->algorithm = NULL;
	}
	free((void*)transform);
	transform = NULL;
}

static void _ri_free_cannonicalizationmethod(cannonicalizationmethod_x *cannonicalizationmethod)
{
	if (cannonicalizationmethod == NULL)
		return;
	if (cannonicalizationmethod->algorithm) {
	        free((void *)cannonicalizationmethod->algorithm);
	        cannonicalizationmethod->algorithm = NULL;
	}
	free((void*)cannonicalizationmethod);
	cannonicalizationmethod = NULL;
}

static void _ri_free_signaturemethod(signaturemethod_x *signaturemethod)
{
	if (signaturemethod == NULL)
		return;
	if (signaturemethod->algorithm) {
	        free((void *)signaturemethod->algorithm);
	        signaturemethod->algorithm = NULL;
	}
	free((void*)signaturemethod);
	signaturemethod = NULL;
}

static void _ri_free_digestmethod(digestmethod_x *digestmethod)
{
	if (digestmethod == NULL)
		return;
	if (digestmethod->algorithm) {
	        free((void *)digestmethod->algorithm);
	        digestmethod->algorithm = NULL;
	}
	free((void*)digestmethod);
	digestmethod = NULL;
}

static void _ri_free_digestvalue(digestvalue_x *digestvalue)
{
	if (digestvalue == NULL)
		return;
	if (digestvalue->text) {
	        free((void *)digestvalue->text);
	        digestvalue->text = NULL;
	}
	free((void*)digestvalue);
	digestvalue = NULL;
}

static void _ri_free_signaturevalue(signaturevalue_x *signaturevalue)
{
	if (signaturevalue == NULL)
		return;
	if (signaturevalue->text) {
	        free((void *)signaturevalue->text);
	        signaturevalue->text = NULL;
	}
	free((void*)signaturevalue);
	signaturevalue = NULL;
}

static void _ri_free_x509certificate(x509certificate_x *x509certificate)
{
	if (x509certificate == NULL)
		return;
	if (x509certificate->text) {
	        free((void *)x509certificate->text);
	        x509certificate->text = NULL;
	}
	free((void*)x509certificate);
	x509certificate = NULL;
}

static void _ri_free_x509data(x509data_x *x509data)
{
	if (x509data == NULL)
		return;
	if (x509data->x509certificate) {
		x509certificate_x *x509certificate = x509data->x509certificate;
		x509certificate_x *tmp = NULL;
		while(x509certificate != NULL) {
		        tmp = x509certificate->next;
		        _ri_free_x509certificate(x509certificate);
		        x509certificate = tmp;
		}
	}
	free((void*)x509data);
	x509data = NULL;
}

static void _ri_free_keyinfo(keyinfo_x *keyinfo)
{
	if (keyinfo == NULL)
		return;
	if (keyinfo->x509data) {
		x509data_x *x509data = keyinfo->x509data;
		x509data_x *tmp = NULL;
		while(x509data != NULL) {
		        tmp = x509data->next;
		        _ri_free_x509data(x509data);
		        x509data = tmp;
		}
	}
	free((void*)keyinfo);
	keyinfo = NULL;
}

static void _ri_free_transforms(transforms_x *transforms)
{
	if (transforms == NULL)
		return;
	if (transforms->transform) {
		transform_x *transform = transforms->transform;
		transform_x *tmp = NULL;
		while(transform != NULL) {
		        tmp = transform->next;
		        _ri_free_transform(transform);
		        transform = tmp;
		}
	}
	free((void*)transforms);
	transforms = NULL;
}

static void _ri_free_reference(reference_x *reference)
{
	if (reference == NULL)
		return;
	if (reference->digestmethod) {
		digestmethod_x *digestmethod = reference->digestmethod;
		digestmethod_x *tmp = NULL;
		while(digestmethod != NULL) {
		        tmp = digestmethod->next;
		        _ri_free_digestmethod(digestmethod);
		        digestmethod = tmp;
		}
	}
	if (reference->digestvalue) {
		digestvalue_x *digestvalue = reference->digestvalue;
		digestvalue_x *tmp = NULL;
		while(digestvalue != NULL) {
		        tmp = digestvalue->next;
		        _ri_free_digestvalue(digestvalue);
		        digestvalue = tmp;
		}
	}
	if (reference->transforms) {
		transforms_x *transforms = reference->transforms;
		transforms_x *tmp = NULL;
		while(transforms != NULL) {
		        tmp = transforms->next;
		        _ri_free_transforms(transforms);
		        transforms = tmp;
		}
	}
	free((void*)reference);
	reference = NULL;
}

static void _ri_free_signedinfo(signedinfo_x *signedinfo)
{
	if (signedinfo == NULL)
		return;
	if (signedinfo->cannonicalizationmethod) {
		cannonicalizationmethod_x *cannonicalizationmethod = signedinfo->cannonicalizationmethod;
		cannonicalizationmethod_x *tmp = NULL;
		while(cannonicalizationmethod != NULL) {
		        tmp = cannonicalizationmethod->next;
		        _ri_free_cannonicalizationmethod(cannonicalizationmethod);
		        cannonicalizationmethod = tmp;
		}
	}
	if (signedinfo->signaturemethod) {
		signaturemethod_x *signaturemethod = signedinfo->signaturemethod;
		signaturemethod_x *tmp = NULL;
		while(signaturemethod != NULL) {
		        tmp = signaturemethod->next;
		        _ri_free_signaturemethod(signaturemethod);
		        signaturemethod = tmp;
		}
	}
	if (signedinfo->reference) {
		reference_x *reference = signedinfo->reference;
		reference_x *tmp = NULL;
		while(reference != NULL) {
		        tmp = reference->next;
		        _ri_free_reference(reference);
		        reference = tmp;
		}
	}
	free((void*)signedinfo);
	signedinfo = NULL;
}

void _ri_free_signature_xml(signature_x *sigx)
{
	if (sigx == NULL)
		return;
	if (sigx->id) {
	        free((void *)sigx->id);
	        sigx->id = NULL;
	}
	if (sigx->xmlns) {
	        free((void *)sigx->xmlns);
	        sigx->xmlns = NULL;
	}
	if (sigx->signedinfo) {
		signedinfo_x *signedinfo = sigx->signedinfo;
		signedinfo_x *tmp = NULL;
		while(signedinfo != NULL) {
		        tmp = signedinfo->next;
		        _ri_free_signedinfo(signedinfo);
		        signedinfo = tmp;
		}
	}
	if (sigx->signaturevalue) {
		signaturevalue_x *signaturevalue = sigx->signaturevalue;
		signaturevalue_x *tmp = NULL;
		while(signaturevalue != NULL) {
		        tmp = signaturevalue->next;
		        _ri_free_signaturevalue(signaturevalue);
		        signaturevalue = tmp;
		}
	}
	if (sigx->keyinfo) {
		keyinfo_x *keyinfo = sigx->keyinfo;
		keyinfo_x *tmp = NULL;
		while(keyinfo != NULL) {
		        tmp = keyinfo->next;
		        _ri_free_keyinfo(keyinfo);
		        keyinfo = tmp;
		}
	}
	/*Object will be freed when it will be parsed in future*/
	free((void*)sigx);
	sigx = NULL;
}

static int _ri_process_digestmethod(xmlTextReaderPtr reader, digestmethod_x *digestmethod)
{
	if (xmlTextReaderGetAttribute(reader, XMLCHAR("Algorithm")))
		digestmethod->algorithm = ASCII(xmlTextReaderGetAttribute(reader, XMLCHAR("Algorithm")));
	return 0;
}

static int _ri_process_digestvalue(xmlTextReaderPtr reader, digestvalue_x *digestvalue)
{
	xmlTextReaderRead(reader);
	if (xmlTextReaderValue(reader))
		digestvalue->text = ASCII(xmlTextReaderValue(reader));
	return 0;
}

static int _ri_process_transform(xmlTextReaderPtr reader, transform_x *transform)
{
	if (xmlTextReaderGetAttribute(reader, XMLCHAR("Algorithm")))
		transform->algorithm = ASCII(xmlTextReaderGetAttribute(reader, XMLCHAR("Algorithm")));
	return 0;
}

static int _ri_process_transforms(xmlTextReaderPtr reader, transforms_x *transforms)
{
	const xmlChar *node = NULL;
	int ret = 0;
	int depth = 0;
	transform_x *tmp1 = NULL;

	depth = xmlTextReaderDepth(reader);
	while ((ret = _ri_next_child_element(reader, depth))) {
		node = xmlTextReaderConstName(reader);
		if (!node) {
			_d_msg(DEBUG_ERR, "node is NULL\n");
			return -1;
		}
		if (strcmp(ASCII(node), "Transform") == 0) {
			transform_x *transform = calloc(1, sizeof(transform_x));
			if (transform == NULL) {
				_d_msg(DEBUG_ERR, "Calloc Failed\n");
				return -1;
			}
			LISTADD(transforms->transform, transform);
			ret = _ri_process_transform(reader, transform);
		} else {
			_d_msg(DEBUG_INFO, "Invalid tag %s", ASCII(node));
			return -1;
		}
		if (ret < 0)
			return ret;
	}
	if (transforms->transform) {
		LISTHEAD(transforms->transform, tmp1);
		transforms->transform = tmp1;
	}
	return ret;
}

static int _ri_process_cannonicalizationmethod(xmlTextReaderPtr reader, cannonicalizationmethod_x *cannonicalizationmethod)
{
	if (xmlTextReaderGetAttribute(reader, XMLCHAR("Algorithm")))
		cannonicalizationmethod->algorithm = ASCII(xmlTextReaderGetAttribute(reader, XMLCHAR("Algorithm")));
	return 0;
}

static int _ri_process_signaturemethod(xmlTextReaderPtr reader, signaturemethod_x *signaturemethod)
{
	if (xmlTextReaderGetAttribute(reader, XMLCHAR("Algorithm")))
		signaturemethod->algorithm = ASCII(xmlTextReaderGetAttribute(reader, XMLCHAR("Algorithm")));
	return 0;
}

static int _ri_process_reference(xmlTextReaderPtr reader, reference_x *reference)
{
	const xmlChar *node = NULL;
	int ret = 0;
	int depth = 0;
	digestmethod_x *tmp1 = NULL;
	digestvalue_x *tmp2 = NULL;
	transforms_x *tmp3 = NULL;

	if (xmlTextReaderGetAttribute(reader, XMLCHAR("URI")))
		reference->uri = ASCII(xmlTextReaderGetAttribute(reader, XMLCHAR("URI")));

	depth = xmlTextReaderDepth(reader);
	while ((ret = _ri_next_child_element(reader, depth))) {
		node = xmlTextReaderConstName(reader);
		if (!node) {
			_d_msg(DEBUG_ERR, "node is NULL\n");
			return -1;
		}
		if (strcmp(ASCII(node), "DigestMethod") == 0) {
			digestmethod_x *digestmethod = calloc(1, sizeof(digestmethod_x));
			if (digestmethod == NULL) {
				_d_msg(DEBUG_ERR, "Calloc Failed\n");
				return -1;
			}
			LISTADD(reference->digestmethod, digestmethod);
			ret = _ri_process_digestmethod(reader, digestmethod);
		} else if (strcmp(ASCII(node), "DigestValue") == 0) {
			digestvalue_x *digestvalue = calloc(1, sizeof(digestvalue_x));
			if (digestvalue == NULL) {
				_d_msg(DEBUG_ERR, "Calloc Failed\n");
				return -1;
			}
			LISTADD(reference->digestvalue, digestvalue);
			ret = _ri_process_digestvalue(reader, digestvalue);
		} else if (strcmp(ASCII(node), "Transforms") == 0) {
			transforms_x *transforms = calloc(1, sizeof(transforms_x));
			if (transforms == NULL) {
				_d_msg(DEBUG_ERR, "Calloc Failed\n");
				return -1;
			}
			LISTADD(reference->transforms, transforms);
			ret = _ri_process_transforms(reader, transforms);
		} else {
			_d_msg(DEBUG_INFO, "Invalid tag %s", ASCII(node));
			return -1;
		}
		if (ret < 0)
			return ret;
	}
	if (reference->digestmethod) {
		LISTHEAD(reference->digestmethod, tmp1);
		reference->digestmethod = tmp1;
	}
	if (reference->digestvalue) {
		LISTHEAD(reference->digestvalue, tmp2);
		reference->digestvalue = tmp2;
	}
	if (reference->transforms) {
		LISTHEAD(reference->transforms, tmp3);
		reference->transforms = tmp3;
	}
	return ret;
}

static int _ri_process_x509certificate(xmlTextReaderPtr reader, x509certificate_x *x509certificate)
{
	xmlTextReaderRead(reader);
	if (xmlTextReaderValue(reader)) {
		x509certificate->text = ASCII(xmlTextReaderValue(reader));
		_d_msg(DEBUG_INFO, "certlen=%d, x509certificate : %s", strlen(x509certificate->text), x509certificate->text);
	}
	return 0;
}

static int _ri_process_x509data(xmlTextReaderPtr reader, x509data_x *x509data)
{
	const xmlChar *node = NULL;
	int ret = 0;
	int depth = 0;
	x509certificate_x *tmp1 = NULL;

	depth = xmlTextReaderDepth(reader);
	while ((ret = _ri_next_child_element(reader, depth))) {
		node = xmlTextReaderConstName(reader);
		if (!node) {
			_d_msg(DEBUG_ERR, "node is NULL\n");
			return -1;
		}
		if (strcmp(ASCII(node), "X509Certificate") == 0) {
			x509certificate_x *x509certificate = calloc(1, sizeof(x509certificate_x));
			if (x509certificate == NULL) {
				_d_msg(DEBUG_ERR, "Calloc Failed\n");
				return -1;
			}
			LISTADD(x509data->x509certificate, x509certificate);
			ret = _ri_process_x509certificate(reader, x509certificate);
		} else {
			_d_msg(DEBUG_INFO, "Invalid tag %s", ASCII(node));
			return -1;
		}
		if (ret < 0)
			return ret;
	}
	if (x509data->x509certificate) {
		LISTHEAD(x509data->x509certificate, tmp1);
		x509data->x509certificate = tmp1;
	}
	return ret;
}

#if 0
static int _ri_process_object(xmlTextReaderPtr reader, object_x *object)
{
	/*To be parsed later*/
	return 0;
}
#endif

static int _ri_process_keyinfo(xmlTextReaderPtr reader, keyinfo_x *keyinfo)
{
	const xmlChar *node = NULL;
	int ret = 0;
	int depth = 0;
	x509data_x *tmp1 = NULL;

	depth = xmlTextReaderDepth(reader);
	while ((ret = _ri_next_child_element(reader, depth))) {
		node = xmlTextReaderConstName(reader);
		if (!node) {
			_d_msg(DEBUG_ERR, "node is NULL\n");
			return -1;
		}
		if (strcmp(ASCII(node), "X509Data") == 0) {
			x509data_x *x509data = calloc(1, sizeof(x509data_x));
			if (x509data == NULL) {
				_d_msg(DEBUG_ERR, "Calloc Failed\n");
				return -1;
			}
			LISTADD(keyinfo->x509data, x509data);
			ret = _ri_process_x509data(reader, x509data);
		} else {
			_d_msg(DEBUG_INFO, "Invalid tag %s", ASCII(node));
			return -1;
		}
		if (ret < 0)
			return ret;
	}
	if (keyinfo->x509data) {
		LISTHEAD(keyinfo->x509data, tmp1);
		keyinfo->x509data = tmp1;
	}
	return ret;
}

static int _ri_process_signaturevalue(xmlTextReaderPtr reader, signaturevalue_x *signaturevalue)
{
	xmlTextReaderRead(reader);
	if (xmlTextReaderValue(reader)) {
		signaturevalue->text = ASCII(xmlTextReaderValue(reader));
		_d_msg(DEBUG_INFO, "siglen=%d SignatureValue %s", strlen(signaturevalue->text), signaturevalue->text);
	}
	return 0;
}

static int _ri_process_signedinfo(xmlTextReaderPtr reader, signedinfo_x *signedinfo)
{
	const xmlChar *node = NULL;
	int ret = 0;
	int depth = 0;
	cannonicalizationmethod_x *tmp1 = NULL;
	signaturemethod_x *tmp2 = NULL;
	reference_x *tmp3 = NULL;

	depth = xmlTextReaderDepth(reader);
	while ((ret = _ri_next_child_element(reader, depth))) {
		node = xmlTextReaderConstName(reader);
		if (!node) {
			_d_msg(DEBUG_ERR, "node is NULL\n");
			return -1;
		}
		if (strcmp(ASCII(node), "CanonicalizationMethod") == 0) {
			cannonicalizationmethod_x *cannonicalizationmethod = calloc(1, sizeof(cannonicalizationmethod_x));
			if (cannonicalizationmethod == NULL) {
				_d_msg(DEBUG_ERR, "Calloc Failed\n");
				return -1;
			}
			LISTADD(signedinfo->cannonicalizationmethod, cannonicalizationmethod);
			ret = _ri_process_cannonicalizationmethod(reader, cannonicalizationmethod);
		} else if (strcmp(ASCII(node), "SignatureMethod") == 0) {
			signaturemethod_x *signaturemethod = calloc(1, sizeof(signaturemethod_x));
			if (signaturemethod == NULL) {
				_d_msg(DEBUG_ERR, "Calloc Failed\n");
				return -1;
			}
			LISTADD(signedinfo->signaturemethod, signaturemethod);
			ret = _ri_process_signaturemethod(reader, signaturemethod);
		} else if (strcmp(ASCII(node), "Reference") == 0) {
			reference_x *reference = calloc(1, sizeof(reference_x));
			if (reference == NULL) {
				_d_msg(DEBUG_ERR, "Calloc Failed\n");
				return -1;
			}
			LISTADD(signedinfo->reference, reference);
			ret = _ri_process_reference(reader, reference);
		} else {
			_d_msg(DEBUG_INFO, "Invalid tag %s", ASCII(node));
			return -1;
		}
		if (ret < 0)
			return ret;
	}
	if (signedinfo->cannonicalizationmethod) {
		LISTHEAD(signedinfo->cannonicalizationmethod, tmp1);
		signedinfo->cannonicalizationmethod = tmp1;
	}
	if (signedinfo->signaturemethod) {
		LISTHEAD(signedinfo->signaturemethod, tmp2);
		signedinfo->signaturemethod = tmp2;
	}
	if (signedinfo->reference) {
		LISTHEAD(signedinfo->reference, tmp3);
		signedinfo->reference = tmp3;
	}
	return ret;
}

static int _ri_process_sign(xmlTextReaderPtr reader, signature_x *sigx)
{
	const xmlChar *node = NULL;
	int ret = 0;
	int depth = 0;
	signedinfo_x *tmp1 = NULL;
	signaturevalue_x *tmp2 = NULL;
	keyinfo_x *tmp3 = NULL;
	object_x *tmp4 = NULL;

	depth = xmlTextReaderDepth(reader);
	while ((ret = _ri_next_child_element(reader, depth))) {
		node = xmlTextReaderConstName(reader);
		if (!node) {
			_d_msg(DEBUG_ERR, "node is NULL\n");
			return -1;
		}
		if (strcmp(ASCII(node), "SignedInfo") == 0) {
			signedinfo_x *signedinfo = calloc(1, sizeof(signedinfo_x));
			if (signedinfo == NULL) {
				_d_msg(DEBUG_ERR, "Calloc Failed\n");
				return -1;
			}
			LISTADD(sigx->signedinfo, signedinfo);
			ret = _ri_process_signedinfo(reader, signedinfo);
		} else if (strcmp(ASCII(node), "SignatureValue") == 0) {
			signaturevalue_x *signaturevalue = calloc(1, sizeof(signaturevalue_x));
			if (signaturevalue == NULL) {
				_d_msg(DEBUG_ERR, "Calloc Failed\n");
				return -1;
			}
			LISTADD(sigx->signaturevalue, signaturevalue);
			ret = _ri_process_signaturevalue(reader, signaturevalue);
		} else if (strcmp(ASCII(node), "KeyInfo") == 0) {
			keyinfo_x *keyinfo = calloc(1, sizeof(keyinfo_x));
			if (keyinfo == NULL) {
				_d_msg(DEBUG_ERR, "Calloc Failed\n");
				return -1;
			}
			LISTADD(sigx->keyinfo, keyinfo);
			ret = _ri_process_keyinfo(reader, keyinfo);
		} else if (strcmp(ASCII(node), "Object") == 0) {
			/*
			object_x *object = calloc(1, sizeof(object_x));
			if (object == NULL) {
				_d_msg(DEBUG_ERR, "Calloc Failed\n");
				return -1;
			}
			LISTADD(sigx->object, object);
			ret = _ri_process_object(reader, object);
			*/
			continue;
		} else {
			_d_msg(DEBUG_INFO, "Invalid tag %s", ASCII(node));
			return -1;
		}
		if (ret < 0)
			return ret;
	}
	if (sigx->signedinfo) {
		LISTHEAD(sigx->signedinfo, tmp1);
		sigx->signedinfo = tmp1;
	}
	if (sigx->signaturevalue) {
		LISTHEAD(sigx->signaturevalue, tmp2);
		sigx->signaturevalue = tmp2;
	}
	if (sigx->keyinfo) {
		LISTHEAD(sigx->keyinfo, tmp3);
		sigx->keyinfo = tmp3;
	}
	if (sigx->object) {
		LISTHEAD(sigx->object, tmp4);
		sigx->object = tmp4;
	}
	return ret;
}

static int _ri_process_signature(xmlTextReaderPtr reader, signature_x *sigx)
{
	const xmlChar *node = NULL;
	int ret = -1;

	if ((ret = _ri_next_child_element(reader, -1))) {
		node = xmlTextReaderConstName(reader);
		if (!node) {
			_d_msg(DEBUG_ERR, "Node is null");
			return -1;
		}
		if (!strcmp(ASCII(node), "Signature")) {
			if (xmlTextReaderGetAttribute(reader, XMLCHAR("Id")))
				sigx->id = ASCII(xmlTextReaderGetAttribute(reader, XMLCHAR("Id")));
			if (xmlTextReaderGetAttribute(reader, XMLCHAR("xmlns")))
				sigx->xmlns = ASCII(xmlTextReaderGetAttribute(reader, XMLCHAR("xmlns")));
			ret = _ri_process_sign(reader, sigx);
		} else {
			_d_msg(DEBUG_ERR, "No Signature element found\n");
			return -1;
		}
	}
	return ret;
}

signature_x *_ri_process_signature_xml(const char *signature_file)
{
	xmlTextReaderPtr reader;
	signature_x *sigx = NULL;

	reader = xmlReaderForFile(signature_file, NULL, 0);

	if (reader) {
		sigx = calloc(1, sizeof(signature_x));
		if (sigx) {
			if (_ri_process_signature(reader, sigx) < 0) {
				/* error in parsing. Let's display some hint where we failed */
				_d_msg(DEBUG_ERR, "Syntax error in processing signature in the above line\n");
				_ri_free_signature_xml(sigx);
				xmlFreeTextReader(reader);
				return NULL;
			}
		} else {
			_d_msg(DEBUG_ERR, "Calloc failed\n");
		}
		xmlFreeTextReader(reader);
	} else {
		_d_msg(DEBUG_ERR, "Unable to create xml reader\n");
	}
	return sigx;
}
