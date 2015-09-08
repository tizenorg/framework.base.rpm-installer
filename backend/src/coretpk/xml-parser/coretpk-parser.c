
#include <bundle.h>
#include <glib.h>
#include <libxml/xpath.h>
#include <stdbool.h>
#include <unistd.h>
#include <cert-service.h>
#include "rpm-installer-type.h"
#include "coretpk-installer-type.h"
//#ifdef _APPFW_FEATURE_DELTA_UPDATE
#include "rpm-installer-util.h"
//#endif

int __coretpk_parser_unlink_node(xmlXPathContextPtr context, xmlChar* xpath)
{
	retv_if(context == NULL, RPM_INSTALLER_ERR_WRONG_PARAM);
	retv_if(xpath == NULL, RPM_INSTALLER_ERR_WRONG_PARAM);

	int ret = 0;
	int size = 0;
	int i = 0;
	xmlXPathObjectPtr result = NULL;

	result = xmlXPathEvalExpression((xmlChar*) xpath, context);
	tryvm_if(result == NULL, ret = -1, "xmlXPathEvalExpression(%s) failed.", xpath);

	if (!xmlXPathNodeSetIsEmpty(result->nodesetval)) {
		size = (result->nodesetval) ? result->nodesetval->nodeNr : 0;
		_LOGD("feature, size=[%d]", size);

		for(i = size - 1; i >= 0; i--) {
			xmlUnlinkNode(result->nodesetval->nodeTab[i]);
			xmlFreeNodeList(result->nodesetval->nodeTab[i]);
		}
	}

catch:
	if (result) {
		xmlXPathFreeObject(result);
		result = NULL;
	}

	return ret;
}

int __coretpk_parser_set_value(xmlXPathContextPtr context, xmlChar *xpath, const char *value)
{
	retv_if(context == NULL, RPM_INSTALLER_ERR_WRONG_PARAM);
	retv_if(xpath == NULL, RPM_INSTALLER_ERR_WRONG_PARAM);
	retv_if(value == NULL, RPM_INSTALLER_ERR_WRONG_PARAM);

	int ret = 0;
	int size = 0;
	int i = 0;
	xmlXPathObjectPtr result = NULL;
	xmlChar *origin_value = NULL;

	_LOGD("xpath=[%s], value=[%s]", (char*) xpath, value);

	result = xmlXPathEvalExpression(xpath, context);
	tryvm_if(result == NULL, ret = -1, "xmlXPathEvalExpression(%s) failed.", (char*) xpath);

	ret = xmlXPathNodeSetIsEmpty(result->nodesetval);
	tryvm_if(ret == 1, ret = -1, "NodeSet is empty. (%s)", (char*) xpath);

	size = (result->nodesetval) ? result->nodesetval->nodeNr : 0;
	_LOGD("size=[%d]", size);

	for(i = size - 1; i >= 0; i--) {
		origin_value = xmlNodeGetContent(result->nodesetval->nodeTab[i]);
		if (origin_value == NULL) {
			_LOGE("origin_value[%d] is NULL.", i);
			continue;
		}

		xmlNodeSetContent(result->nodesetval->nodeTab[i], (xmlChar*) value);
		_LOGD("value:[%s] -> [%s]", origin_value, value);

		xmlFree(origin_value);
		origin_value = NULL;

		if (result->nodesetval->nodeTab[i]->type != XML_NAMESPACE_DECL) {
			result->nodesetval->nodeTab[i] = NULL;
		}
	}

catch:
	if (result) {
		xmlXPathFreeObject(result);
		result = NULL;
	}

	return ret;
}

int __coretpk_parser_add_property(xmlXPathContextPtr context, const char* clientid, const bundle *optional_data)
{
	retv_if(context == NULL, RPM_INSTALLER_ERR_WRONG_PARAM);

	int ret = 0;
	char *csc_path = NULL;
	char buffer[BUF_SIZE] = {0, };
	xmlXPathObjectPtr result = NULL;
	xmlXPathObjectPtr manifest = NULL;
	xmlXPathObjectPtr service = NULL;

	// 1. install-location -> //*[name() = 'manifest']/@install-location
	result = xmlXPathEvalExpression((xmlChar*) "//*[name() = 'manifest']/@install-location", context);
	tryvm_if(result == NULL, ret = -1, "xmlXPathEvalExpression(@install-location) failed.");

	manifest = xmlXPathEvalExpression((xmlChar*) "//*[name() = 'manifest']", context);
	tryvm_if(manifest == NULL, ret = -1, "xmlXPathEvalExpression(//*[name() = 'manifest']) failed.");

	if (xmlXPathNodeSetIsEmpty(result->nodesetval)) {
		service = xmlXPathEvalExpression((xmlChar*) "//*[name() = 'service-application']", context);
		tryvm_if(service == NULL, ret = -1, "xmlXPathEvalExpression(//*[name() = 'service-application') failed.");

		if (xmlXPathNodeSetIsEmpty(service->nodesetval)) {
			snprintf(buffer, BUF_SIZE, "%s", "auto");
		} else {
			snprintf(buffer, BUF_SIZE, "%s", "internal-only");
		}

		xmlNewProp(*(manifest->nodesetval->nodeTab), BAD_CAST "install-location", BAD_CAST buffer);
		_LOGD("install-location=[%s]", buffer);
	} else {
		_LOGD("install-location is already existed.");
	}

	// 2. clientid
	if (clientid && clientid[0]) {
		xmlNewProp(*(manifest->nodesetval->nodeTab), BAD_CAST "storeclient-id", BAD_CAST clientid);
		_LOGD("storeclient-id=[%s]", clientid);
	}

	// 3. csc
	if (optional_data) {
		bundle_get_str((bundle*) optional_data, "csc_path", &csc_path);
		_LOGD("csc_path=[%s]", csc_path);

		xmlNewProp(*(manifest->nodesetval->nodeTab), BAD_CAST "csc_path", BAD_CAST csc_path);
	}

catch:
	if (result) {
		xmlXPathFreeObject(result);
		result = NULL;
	}

	if (manifest) {
		xmlXPathFreeObject(manifest);
		manifest = NULL;
	}

	if (service) {
		xmlXPathFreeObject(service);
		service = NULL;
	}

	return ret;
}

int __coretpk_parser_append_path(xmlXPathContextPtr context, xmlChar* xpath, const char *path)
{
	retv_if(context == NULL, RPM_INSTALLER_ERR_WRONG_PARAM);
	retv_if(xpath == NULL, RPM_INSTALLER_ERR_WRONG_PARAM);
	retv_if(path == NULL, RPM_INSTALLER_ERR_WRONG_PARAM);

	int ret = 0;
	int size = 0;
	int i = 0;
	char buffer[BUF_SIZE] = {0, };
	xmlXPathObjectPtr result = NULL;
	xmlChar *value = NULL;

	_LOGD("xpath=[%s], path=[%s]", (char*) xpath, path);

	result = xmlXPathEvalExpression(xpath, context);
	tryvm_if(result == NULL, ret = -1, "xmlXPathEvalExpression(%s) failed.", (char*) xpath);

	ret = xmlXPathNodeSetIsEmpty(result->nodesetval);
	tryvm_if(ret == 1, ret = -1, "NodeSet is empty. (%s)", (char*) xpath);

	size = (result->nodesetval) ? result->nodesetval->nodeNr : 0;
	_LOGD("size=[%d]", size);

	for(i = size - 1; i >= 0; i--) {
		value = xmlNodeGetContent(result->nodesetval->nodeTab[i]);
		if (value == NULL) {
			_LOGE("value[%d] is NULL.", i);
			continue;
		}

		snprintf(buffer, BUF_SIZE, "%s/%s", path, value);

		if (strstr((char*)value, USR_APPS)) {
			_LOGE("skip! absolute path=[%s]", value);
		} else {
			_LOGD("value:[%s] -> [%s]", value, buffer);
			xmlNodeSetContent(result->nodesetval->nodeTab[i], (xmlChar*) buffer);
		}

		xmlFree(value);
		value = NULL;

		if (result->nodesetval->nodeTab[i]->type != XML_NAMESPACE_DECL) {
			result->nodesetval->nodeTab[i] = NULL;
		}
	}

catch:
	if (result) {
		xmlXPathFreeObject(result);
		result = NULL;
	}

	return ret;
}

int __coretpk_parser_widget_replace_widget_tag(xmlXPathContextPtr context)
{
	retv_if(context == NULL, RPM_INSTALLER_ERR_WRONG_PARAM);

	int ret = 0;
	int size = 0;
	int i = 0;
	xmlXPathObjectPtr widget = NULL;
	char *from_tag = "widget-application";
	char *to_tag = "widget";
	char *from_xpath = "//*[name() = 'widget-application']";

	widget = xmlXPathEvalExpression((xmlChar *)from_xpath, context);
	tryvm_if(widget == NULL, ret = -1, "xmlXPathEvalExpression(%s) failed.", (char*) from_xpath);

	ret = xmlXPathNodeSetIsEmpty(widget->nodesetval);
	tryvm_if(ret == 1, ret = -1, "NodeSet is empty. (%s)", (char*) from_xpath);

	size = (widget->nodesetval) ? widget->nodesetval->nodeNr : 0;
	for(i = size - 1; i >= 0; i--) {
		_LOGD("value:[%s] -> [%s]", from_tag, to_tag);
		xmlNodeSetName(widget->nodesetval->nodeTab[i], (xmlChar*) to_tag);
	}

catch:
	if (widget) {
		xmlXPathFreeObject(widget);
		widget = NULL;
	}

	return ret;
}

int __coretpk_parser_widget_modify_uiapp_property(xmlXPathContextPtr context, xmlNodePtr node)
{
	retv_if(context == NULL, RPM_INSTALLER_ERR_WRONG_PARAM);
	retv_if(node == NULL, RPM_INSTALLER_ERR_WRONG_PARAM);

	xmlAttrPtr attr = NULL;

	//Delete attribute
	attr = xmlHasProp(node,(xmlChar*) "update-period" );
	if (attr != NULL) {
		xmlRemoveProp(attr);
	}
	attr = xmlHasProp(node,(xmlChar*) "main" );
	if (attr != NULL) {
		xmlRemoveProp(attr);
	}
	attr = xmlHasProp(node,(xmlChar*) "count" );
	if (attr != NULL) {
		xmlRemoveProp(attr);
	}

	//Delete node
	__coretpk_parser_unlink_node(context, (xmlChar *)"//*[name() = 'manifest']/*[name()='widget-ui']/*[name()='support-size']");
	__coretpk_parser_unlink_node(context, (xmlChar *)"//*[name() = 'manifest']/*[name()='widget-ui']/*[name()='metadata']");

	//Add attribute
	xmlNewProp(node, BAD_CAST "nodisplay", BAD_CAST "true");
	xmlNewProp(node, BAD_CAST "multiple", BAD_CAST "false");
	xmlNewProp(node, BAD_CAST "type", BAD_CAST "capp");
	xmlNewProp(node, BAD_CAST "taskmanage", BAD_CAST "false");
	xmlNewProp(node, BAD_CAST "indicatordisplay", BAD_CAST "false");
	xmlNewProp(node, BAD_CAST "component-type", BAD_CAST "widgetapp");

	return 0;
}


int __coretpk_parser_widget_copy_dbox2ui_tag(xmlXPathContextPtr context, xmlDocPtr doc)
{
	retv_if(doc == NULL, RPM_INSTALLER_ERR_WRONG_PARAM);

	int ret = 0;
	int size = 0;
	int i = 0;
	xmlXPathObjectPtr dbox = NULL;
	xmlNodePtr parent_node = doc->children;
	xmlNodePtr copied_node = NULL;
	char *from_xpath = "//*[name() = 'widget']";

	//Copy node and change name temporarily (widget -> widget-ui)
	dbox = xmlXPathEvalExpression((xmlChar*) from_xpath, context);
	tryvm_if(dbox == NULL, ret = -1, "xmlXPathEvalExpression(%s) failed.", from_xpath);

	ret = xmlXPathNodeSetIsEmpty(dbox->nodesetval);
	tryvm_if(ret == 1, ret = -1, "NodeSet is empty. (%s)", (char*) from_xpath);

	size = (dbox->nodesetval) ? dbox->nodesetval->nodeNr : 0;
	for(i = size - 1; i >= 0; i--) {
		copied_node = xmlCopyNode(dbox->nodesetval->nodeTab[i], 1);
		copied_node = xmlDocCopyNode(copied_node, doc, 1);
		xmlAddChild(parent_node, copied_node);
		xmlNodeSetName(copied_node, (xmlChar*) "widget-ui"); //Change widget => widget-ui after copying

		__coretpk_parser_widget_modify_uiapp_property(context, copied_node); //Fix ui-application property

		//Change node name temporarily (widget-ui -> ui-application)
		xmlNodeSetName(copied_node, (xmlChar*) "ui-application");
	}

catch:
	if (dbox) {
		xmlXPathFreeObject(dbox);
		dbox = NULL;
	}
	return ret;
}

int __coretpk_parser_widget_add_dbox_metadata(xmlXPathContextPtr context)
{
	retv_if(context == NULL, RPM_INSTALLER_ERR_WRONG_PARAM);

	xmlXPathObjectPtr metadata = NULL;
	int ret = 0;
	int size = 0;
	int i = 0;
	xmlChar *key = NULL;
	xmlChar *value = NULL;

	metadata = xmlXPathEvalExpression((xmlChar*) "//*[name() = 'manifest']/*[name()='widget']/*[name()='metadata']", context);
	if(metadata) {
		ret = xmlXPathNodeSetIsEmpty(metadata->nodesetval);
		if(ret != 1) {
			size = (metadata->nodesetval) ? metadata->nodesetval->nodeNr : 0;
			_LOGD("metadata size=[%d]", size);

			for(i = size - 1; i >= 0; i--) {
				key = xmlGetProp(metadata->nodesetval->nodeTab[i], (xmlChar*) "key");
				if (key == NULL) {
					_LOGE("value[%d] is NULL.", i);
					continue;
				}

				_LOGD("key=[%s]", key);
				if (xmlStrcasecmp(key, (const xmlChar*) "http://developer.samsung.com/tizen/metadata/widget/count") == 0) {
					value = xmlGetProp(metadata->nodesetval->nodeTab[i], (xmlChar*) "value");
					if (value) {
						_LOGD("key=[%s] value=[%s]", key, value);

						xmlNewProp(metadata->nodesetval->nodeTab[i], BAD_CAST "count", BAD_CAST value);

						xmlFree(value);
						value = NULL;
					}
				}

				xmlFree(key);
				key = NULL;
			}

			for(i = size - 1; i >= 0; i--) {
				xmlUnlinkNode(metadata->nodesetval->nodeTab[i]);
				xmlFreeNodeList(metadata->nodesetval->nodeTab[i]);
			}
		}
	}

	return 0;
}


int __coretpk_parser_change_dbox_tag(xmlXPathContextPtr context, xmlDocPtr doc)
{
	retv_if(context == NULL, RPM_INSTALLER_ERR_WRONG_PARAM);

	int ret = 0;
	int size = 0;
	int i = 0;
	xmlXPathObjectPtr dbox = NULL;
	char *from_xpath = "//*[name() = 'widget']";
	xmlAttrPtr attr = NULL;
	xmlNodePtr box_node = NULL;
	xmlNodePtr sub_node = NULL;
	xmlNode *cur_node = NULL;
	xmlNode *size_node = NULL;
	xmlNodePtr copied_node = NULL;

	dbox = xmlXPathEvalExpression((xmlChar*) from_xpath, context);
	tryvm_if(dbox == NULL, ret = -1, "xmlXPathEvalExpression(%s) failed.", from_xpath);

	ret = xmlXPathNodeSetIsEmpty(dbox->nodesetval);
	tryvm_if(ret == 1, ret = -1, "NodeSet is empty. (%s)", (char*) from_xpath);

	size = (dbox->nodesetval) ? dbox->nodesetval->nodeNr : 0;
	for(i = size - 1; i >= 0; i--) {
		//Change dbox properties
		attr = xmlHasProp(dbox->nodesetval->nodeTab[i],(xmlChar*) "main" );
		if (attr != NULL) {
			xmlChar *ret_val = xmlGetProp(dbox->nodesetval->nodeTab[i], (const xmlChar *)"main");
			xmlRemoveProp(attr);
			xmlNewProp(dbox->nodesetval->nodeTab[i], BAD_CAST "primary", ret_val);
			xmlFree(ret_val);
		}

		attr = xmlHasProp(dbox->nodesetval->nodeTab[i],(xmlChar*) "exec" );
		if (attr != NULL) {
			xmlChar *ret_val = xmlGetProp(dbox->nodesetval->nodeTab[i], (const xmlChar *)"exec");
			xmlRemoveProp(attr);
			xmlNewProp(dbox->nodesetval->nodeTab[i], BAD_CAST "libexec", ret_val);
			xmlFree(ret_val);
		}

		attr = xmlHasProp(dbox->nodesetval->nodeTab[i],(xmlChar*) "update-period" );
		if (attr != NULL) {
			xmlChar *ret_val = xmlGetProp(dbox->nodesetval->nodeTab[i], (const xmlChar *)"update-period");
			xmlRemoveProp(attr);
			xmlNewProp(dbox->nodesetval->nodeTab[i], BAD_CAST "period", ret_val);
			xmlFree(ret_val);
		}

		//Add properties to dbox
		xmlNewProp(dbox->nodesetval->nodeTab[i], BAD_CAST "network", BAD_CAST "false");
		xmlNewProp(dbox->nodesetval->nodeTab[i], BAD_CAST "timeout", BAD_CAST "60");
		xmlNewProp(dbox->nodesetval->nodeTab[i], BAD_CAST "script", BAD_CAST "edje");
		xmlNewProp(dbox->nodesetval->nodeTab[i], BAD_CAST "pinup", BAD_CAST "false");
		xmlNewProp(dbox->nodesetval->nodeTab[i], BAD_CAST "secured", BAD_CAST "false");
		xmlNewProp(dbox->nodesetval->nodeTab[i], BAD_CAST "abi", BAD_CAST "app");

		//Add category node
		sub_node = xmlNewNode(NULL,(xmlChar*)"category"); //category畴靛 积己
		xmlAddChild(dbox->nodesetval->nodeTab[i], sub_node);
		xmlSetProp(sub_node, (xmlChar*)"name", (xmlChar*)"http://tizen.org/widget/default");

		//Create box node <box> </box>
		box_node = xmlNewNode(NULL,(xmlChar*)"box"); //box畴靛 积己
		xmlAddChild(dbox->nodesetval->nodeTab[i], box_node);

		//Add box properties
		xmlNewProp(box_node, BAD_CAST "type", BAD_CAST "buffer");
		xmlNewProp(box_node, BAD_CAST "mouse_event", BAD_CAST "false");
		xmlNewProp(box_node, BAD_CAST "touch_effect", BAD_CAST "false");
		xmlNewProp(box_node, BAD_CAST "need_frame", BAD_CAST "true");

		//Change size to box/size
		//1) Copy size to box/size
		cur_node = size_node = dbox->nodesetval->nodeTab[i]->children;
		for( ; cur_node; cur_node = cur_node->next) {
			if(cur_node->type == XML_ELEMENT_NODE && (!xmlStrcmp(cur_node->name, (const xmlChar*)"support-size")))	{
				//This should be fixed - currently only 1 size is supported
				copied_node = xmlCopyNode(cur_node, 1);
				copied_node = xmlDocCopyNode(copied_node, doc, 1);
				xmlAddChild(box_node, copied_node);
				xmlNodeSetName(copied_node, (xmlChar*) "size"); //Change widget => widget-ui after copying
			}
		}

		//2) Remove size tag
		xmlNode *next_node = NULL;
		cur_node = size_node;
		while(cur_node) {
			if(cur_node->type == XML_ELEMENT_NODE && (!xmlStrcmp(cur_node->name, (const xmlChar*)"support-size")))	{
				next_node = cur_node->next;
				xmlUnlinkNode(cur_node);
				xmlFreeNode(cur_node);
				cur_node = next_node;
			} else {
				cur_node = cur_node->next;
			}
		}
	}

	// Convert metadata info to dbox property
	__coretpk_parser_widget_add_dbox_metadata(context);

catch:
	if (dbox) {
		xmlXPathFreeObject(dbox);
		dbox = NULL;
	}

	return ret;
}

int __coretpk_parser_remove_value(xmlDocPtr doc)
{
	retv_if(doc == NULL, RPM_INSTALLER_ERR_WRONG_PARAM);

	int ret = 0;
	xmlXPathContextPtr context = NULL;

	context = xmlXPathNewContext(doc);
	tryvm_if(context == NULL, ret = -1, "xmlXPathNewContext() failed.");

	ret = __coretpk_parser_unlink_node(context, (xmlChar *)"//*[name() = 'manifest']/*[name()='feature']");
	tryvm_if(ret != 0, ret = -1, "__coretpk_parser_unlink_node() failed.");

catch:
	if (context) {
		xmlXPathFreeContext(context);
		context = NULL;
	}

	return ret;
}

int __coretpk_parser_add_value(xmlDocPtr doc, const char* value, const bundle *optional_data)
{
	retv_if(doc == NULL, RPM_INSTALLER_ERR_WRONG_PARAM);

	int ret = 0;
	xmlXPathContextPtr context = NULL;

	context = xmlXPathNewContext(doc);
	tryvm_if(context == NULL, ret = -1, "xmlXPathNewContext() failed.");

	ret = __coretpk_parser_add_property(context, value, optional_data);
	tryvm_if(ret != 0, ret = -1, "__coretpk_parser_add_property() failed.");

catch:
	if (context) {
		xmlXPathFreeContext(context);
		context = NULL;
	}

	return ret;
}

int __coretpk_parser_modify_value(xmlDocPtr doc, bool preload, const char *pkgid)
{
	retv_if(doc == NULL, RPM_INSTALLER_ERR_WRONG_PARAM);
	retv_if(pkgid == NULL, RPM_INSTALLER_ERR_WRONG_PARAM);

	int ret = 0;
	char buffer[BUF_SIZE] = {0, };
	char usr_tizen_manifest[BUF_SIZE] = {0, };
	xmlXPathContextPtr context = NULL;

	context = xmlXPathNewContext(doc);
	tryvm_if(context == NULL, ret = -1, "xmlXPathNewContext(%s) failed.", pkgid);

	snprintf(usr_tizen_manifest, BUF_SIZE, "%s/%s/%s", USR_APPS, pkgid, CORETPK_XML);

	// mandatory
	// 1. exec -> //@exec
	if (preload == true)
		snprintf(buffer, BUF_SIZE, "%s/%s/%s", USR_APPS, pkgid, BIN_DIR_STR);
	else {
		snprintf(buffer, BUF_SIZE, "%s/%s/%s", OPT_USR_APPS, pkgid, BIN_DIR_STR);
		if (access(usr_tizen_manifest, F_OK) == 0) {
			_LOGD("First update case: /usr -> /opt");
			if (access(buffer, F_OK) != 0) {
				_LOGD("exec[%s] is not existed.", buffer);
				memset(buffer, '\0', BUF_SIZE);
				snprintf(buffer, BUF_SIZE, "%s/%s/%s", USR_APPS, pkgid, BIN_DIR_STR);
			}
		}
	}

	ret = __coretpk_parser_append_path(context, (xmlChar *) "//@exec", buffer);
	tryvm_if(ret != 0, ret = -1, "__coretpk_parser_append_path(%s) failed.", buffer);
	_LOGD("exec value is modified.");

	// 2. icon -> //*[name() ='ui-application' or name()='service-application' or name()='watch-application' or name()='widget-application']/*[name()='icon']
	memset(buffer, '\0', BUF_SIZE);
	if (preload == true) {
		snprintf(buffer, BUF_SIZE, "%s/%s/%s", USR_APPS, pkgid, SHARED_RES_DIR_STR);
	} else {
		snprintf(buffer, BUF_SIZE, "%s/%s/%s", OPT_USR_APPS, pkgid, SHARED_RES_DIR_STR);
	}
	ret = __coretpk_parser_append_path(context, (xmlChar*) "//*[name() ='ui-application' or name()='service-application' or name()='watch-application' or name()='widget-application']/*[name()='icon']", buffer);
	tryvm_if(ret != 0, ret = -1, "__coretpk_parser_append_path(%s) failed.", buffer);
	_LOGD("icon value is modified.");

	// optional
	// 1. portrait-effectimage -> //@portrait-effectimage
	memset(buffer, '\0', BUF_SIZE);
	if (preload == true) {
		snprintf(buffer, BUF_SIZE, "%s/%s", USR_APPS, pkgid);
	} else {
		snprintf(buffer, BUF_SIZE, "%s/%s", OPT_USR_APPS, pkgid);
	}
	__coretpk_parser_append_path(context, (xmlChar*) "//@portrait-effectimage", buffer);


	// widget - Change widget tags
	//0. ppreview image for support-size of widet
	memset(buffer, '\0', BUF_SIZE);
	if (preload == true)
		snprintf(buffer, BUF_SIZE, "%s/%s/%s", USR_APPS, pkgid, SHARED_RES_DIR_STR);
	else
		snprintf(buffer, BUF_SIZE, "%s/%s/%s", OPT_USR_APPS, pkgid, SHARED_RES_DIR_STR);
	__coretpk_parser_append_path(context, (xmlChar *) "//*[name()='widget-application']//*[name()='support-size']/@preview", buffer);

	// 1. change widget-application => widget
	if(__coretpk_parser_widget_replace_widget_tag(context) == 0) {

		// 2. copy widget => widget-ui
		//     modify property of widget-ui (ui-application)
		//     convert widget-ui => ui-application
		__coretpk_parser_widget_copy_dbox2ui_tag(context, doc);

		// 3. change widget property
		__coretpk_parser_change_dbox_tag(context, doc);
	}

catch:
	if (context) {
		xmlXPathFreeContext(context);
		context = NULL;
	}

	return ret;
}

#ifdef WEARABLE
static int __coretpk_parser_remove_attribute(xmlDocPtr doc, xmlChar *xpath)
{
	int ret = 0;
	xmlXPathContextPtr context = NULL;
	xmlXPathObjectPtr result = NULL;

	retv_if(doc == NULL, RPM_INSTALLER_ERR_WRONG_PARAM);

	context = xmlXPathNewContext(doc);
	tryvm_if(context == NULL, ret = -1, "xmlXPathNewContext() failed.");

	result = xmlXPathEvalExpression(xpath, context);
	tryvm_if(result == NULL, ret = -1, "xmlXPathEvalExpression(%s) failed.", (char*) xpath);

	ret = xmlXPathNodeSetIsEmpty(result->nodesetval);
	if (!ret) {
		int i;
		int size;
		size = (result->nodesetval) ? result->nodesetval->nodeNr : 0;

		for(i = size - 1; i >= 0; i--) {
			xmlUnlinkNode(result->nodesetval->nodeTab[i]);
		}
	}

catch:
	if (result) {
		xmlXPathFreeObject(result);
		result = NULL;
	}

	if (context) {
		xmlXPathFreeContext(context);
		context = NULL;
	}

	return ret;

}
static int __coretpk_parser_remove_onboot_autorestart(xmlDocPtr doc)
{
	int ret;

	retv_if(doc == NULL, RPM_INSTALLER_ERR_WRONG_PARAM);

	ret = __coretpk_parser_remove_attribute(doc, (xmlChar *)"//@on-boot");
	if (ret == -1) {
		_LOGE("failed to remove on-boot attribute");
		return -1;
	}

	ret = __coretpk_parser_remove_attribute(doc, (xmlChar *)"//@auto-restart");
	if (ret == -1) {
		_LOGE("failed to remove auto-restart attribute");
		return -1;
	}

	return 0;
}
#endif

int _coretpk_parser_convert_manifest(const char *tizen_manifest, const char *pkgid, const char *clientid, bool hybrid, int api_visibility,  const bundle *optional_data)
{
	retv_if(tizen_manifest == NULL, RPM_INSTALLER_ERR_WRONG_PARAM);
	retv_if(pkgid == NULL, RPM_INSTALLER_ERR_WRONG_PARAM);

	int ret = 0;
	bool preload = true;
	char system_manifest[BUF_SIZE] = {0, };
	xmlDocPtr doc = NULL;

	_LOGD("------------------------------------------");
	_LOGD("convert_manifest");
	_LOGD("------------------------------------------");

	if (strstr(tizen_manifest, OPT_USR_APPS)) {
		snprintf(system_manifest, BUF_SIZE, "%s/%s.xml", OPT_SHARE_PACKAGES, pkgid);
		preload = false;
	} else
		snprintf(system_manifest, BUF_SIZE, "%s/%s.xml", USR_SHARE_PACKAGES, pkgid);

	if (hybrid == true) {
		memset(system_manifest, '\0', sizeof(system_manifest));
		snprintf(system_manifest, BUF_SIZE, "%s/%s", TEMP_XML_DIR, CORETPK_XML);
		_LOGD("hybrid - tmp_xml=[%s]", system_manifest);
	}

	_LOGD("tizen_manifest=[%s], preload=[%d]", tizen_manifest, preload);

	ret = access(tizen_manifest, F_OK);
	tryvm_if(ret != 0, ret = -1, "cannot access to [%s].", tizen_manifest);

	xmlKeepBlanksDefault(0);
	doc = xmlParseFile(tizen_manifest);
	tryvm_if(doc == NULL, ret = -1, "xmlParseFile(%s) failed.", tizen_manifest);

	// 0. modify - exec, icon, portrait-effectimage
	__coretpk_parser_modify_value(doc, preload, pkgid);

	// 1. add - install-location, clientid
	__coretpk_parser_add_value(doc, clientid, optional_data);

	// 2. remove -feature
	__coretpk_parser_remove_value(doc);

#ifdef WEARABLE
	// remove on-boot, auto-restart for the wearable devices
	if (!((api_visibility & CERT_SVC_VISIBILITY_PARTNER) ||
		(api_visibility & CERT_SVC_VISIBILITY_PARTNER_OPERATOR) ||
		(api_visibility & CERT_SVC_VISIBILITY_PARTNER_MANUFACTURER) ||
		(api_visibility & CERT_SVC_VISIBILITY_PLATFORM)))
		__coretpk_parser_remove_onboot_autorestart(doc);
#endif

	(void)remove(system_manifest);
	xmlSaveFormatFile(system_manifest, doc, 1);
	_LOGD("xmlSaveFormatFile=[%s]", system_manifest);

catch:
	if (doc) {
		xmlFreeDoc(doc);
		doc = NULL;
	}

	return ret;
}

bool _coretpk_parser_is_widget(const char *tizen_manifest)
{
	retv_if(tizen_manifest == NULL, false);

	bool ret = false;
	xmlDocPtr doc = NULL;
	xmlXPathContextPtr context = NULL;
	xmlXPathObjectPtr widgetapp = NULL;

	doc = xmlParseFile(tizen_manifest);
	tryvm_if(doc == NULL, ret = false, "xmlParseFile(%s) failed.", tizen_manifest);

	context = xmlXPathNewContext(doc);
	tryvm_if(context == NULL, ret = false, "xmlXPathNewContext(%s) failed.", tizen_manifest);

	widgetapp = xmlXPathEvalExpression((xmlChar*) "//*[name() = 'manifest']/*[name()='widget-application']", context);
	tryvm_if(widgetapp == NULL, ret = false, "xmlXPathEvalExpression(//*[name() = 'manifest']/*[name()='widget-application']) failed.");

	ret = xmlXPathNodeSetIsEmpty(widgetapp->nodesetval);
	tryvm_if(ret == 1, ret = false, "NodeSet is empty. (//*[name() = 'manifest']/*[name()='widget-application'])");

	ret = true;

catch:
	if (widgetapp) {
		xmlXPathFreeObject(widgetapp);
		widgetapp = NULL;
	}

	if (context) {
		xmlXPathFreeContext(context);
		context = NULL;
	}

	if (doc) {
		xmlFreeDoc(doc);
		doc = NULL;
	}

	return ret;
}


#ifdef _APPFW_FEATURE_DELTA_UPDATE
int __coretpk_parser_get_attr_value_list(xmlXPathContextPtr context, const char *xpath, GList **value_list)
{
	retvm_if(context == NULL, -1, "context is NULL.");
	retvm_if(xpath == NULL, -1, "xpath is NULL.");
	retvm_if(value_list == NULL, -1, "value_list is NULL.");

	int ret = 0;
	int size = 0;
	int i = 0;
	xmlXPathObjectPtr object = NULL;
	xmlChar *value = NULL;
	char *key = "name";

	object = xmlXPathEvalExpression((xmlChar*) xpath, context);
	tryvm_if(object == NULL, ret = -1, "xmlXPathEvalExpression(%s) failed.", xpath);

	ret = xmlXPathNodeSetIsEmpty(object->nodesetval);
	tryvm_if(ret == 1, ret = -1, "[%s] is empty.", xpath);

	size = (object->nodesetval) ? object->nodesetval->nodeNr : 0;

	for(i = size - 1; i >= 0; i--) {
		value = xmlGetProp(object->nodesetval->nodeTab[i], (xmlChar*) key);
		if (value == NULL) {
			_LOGE("value[%d] is NULL.", i);
			continue;
		}
		_LOGD("%s=[%s]", key, (char*) value);
		*value_list= g_list_append(*value_list, value);
	}

catch:
	if (object) {
		xmlXPathFreeObject(object);
		object = NULL;
	}

	return ret;
}
#endif

int __coretpk_parser_get_value_list(xmlXPathContextPtr context, const char *xpath, const char *key, GList **value_list)
{
	retvm_if(context == NULL, -1, "context is NULL.");
	retvm_if(xpath == NULL, -1, "xpath is NULL.");
	retvm_if(key == NULL, -1, "key is NULL.");
	retvm_if(value_list == NULL, -1, "value_list is NULL.");

	int ret = 0;
	int size = 0;
	int i = 0;
	xmlXPathObjectPtr object = NULL;
	xmlChar *value = NULL;

	object = xmlXPathEvalExpression((xmlChar*) xpath, context);
	tryvm_if(object == NULL, ret = -1, "xmlXPathEvalExpression(%s) failed.", xpath);

	ret = xmlXPathNodeSetIsEmpty(object->nodesetval);
	tryvm_if(ret == 1, ret = -1, "[%s] is empty.", xpath);

	size = (object->nodesetval) ? object->nodesetval->nodeNr : 0;

	for(i = size - 1; i >= 0; i--) {
		value = xmlNodeGetContent(object->nodesetval->nodeTab[i]);
		if (value == NULL) {
			_LOGE("value[%d] is NULL.", i);
			continue;
		}

		_LOGD("%s=[%s]", key, (char*) value);
		*value_list= g_list_append(*value_list, value);
	}

catch:
	if (object) {
		xmlXPathFreeObject(object);
		object = NULL;
	}

	return ret;
}

int __coretpk_parser_get_value(xmlXPathContextPtr context, const char *xpath, const char *key, char *value)
{
	retvm_if(context == NULL, -1, "context is NULL.");
	retvm_if(xpath == NULL, -1, "xpath is NULL.");
	retvm_if(key == NULL, -1, "key is NULL.");
	retvm_if(value == NULL, -1, "value is NULL.");

	int ret = 0;
	int len = 0;
	xmlChar *result_value = NULL;
	xmlXPathObjectPtr object = NULL;

	object = xmlXPathEvalExpression((xmlChar*) xpath, context);
	tryvm_if(object == NULL, ret = -1, "xmlXPathEvalExpression(%s) failed.", xpath);

	ret = xmlXPathNodeSetIsEmpty(object->nodesetval);
	tryvm_if(ret == 1, ret = -1, "xmlXPathNodeSetIsEmpty(%s) is failed.", xpath);

	result_value = xmlGetProp(object->nodesetval->nodeTab[0], (xmlChar*) key);
	tryvm_if(result_value == NULL, ret = -1, "[%s] is empty.", key);

	len = strlen((char*) result_value);
	strncpy(value, (char*) result_value, len);

	_LOGD("%s=[%s]", key, value);

catch:
	if (result_value) {
		xmlFree(result_value);
		result_value = NULL;
	}

	if (object) {
		xmlXPathFreeObject(object);
		object = NULL;
	}

	return ret;
}

pkginfo *_coretpk_parser_get_manifest_info(const char *tizen_manifest)
{
	retvm_if(tizen_manifest == NULL, NULL, "tizen_manifest is NULL.");

	int ret = 0;
	pkginfo *info = NULL;
	char install_location[BUF_SIZE] = {0, };
	xmlDocPtr doc = NULL;
	xmlXPathContextPtr context = NULL;

	_LOGD("------------------------------------------");
	_LOGD("Get manifest info");
	_LOGD("------------------------------------------");

	doc = xmlParseFile(tizen_manifest);
	tryvm_if(doc == NULL, ret = -1, "xmlParseFile(%s) failed.", tizen_manifest);

	context = xmlXPathNewContext(doc);
	tryvm_if(context == NULL, ret = -1, "xmlXPathNewContext(%s) failed.", tizen_manifest);

	info = calloc(1, sizeof(pkginfo));
	tryvm_if(info == NULL, ret = -1, "calloc() failed.");

	// 1. mandatory field
	// package_id -> //*[name() ='manifest']
	ret = __coretpk_parser_get_value(context, "//*[name() ='manifest']", "package", info->package_name);
	tryvm_if(ret != 0, ret = -1, "__coretpk_parser_get_value(package) failed.");

	// version -> //*[name() ='manifest']
	ret = __coretpk_parser_get_value(context, "//*[name() ='manifest']", "version", info->version);
	tryvm_if(ret != 0, ret = -1, "__coretpk_parser_get_value(version) failed.");

	// 2. optional field
	// installation_location -> //*[name() ='manifest']
	__coretpk_parser_get_value(context, "//*[name() ='manifest']", "install-location", install_location);
	if (install_location[0]) {
		if (!strcmp(install_location, "internal-only")) {
			info->install_location = PMINFO_INSTALL_LOCATION_INTERNAL_ONLY;
		} else if (!strcmp(install_location, "prefer-external")) {
			info->install_location = PMINFO_INSTALL_LOCATION_PREFER_EXTERNAL;
		} else {
			info->install_location = PMINFO_INSTALL_LOCATION_AUTO;
		}
	}

	// privilege -> //*[name() ='privileges']/*[name()='privilege']
	__coretpk_parser_get_value_list(context, "//*[name() ='privileges']/*[name()='privilege']", "privilege", &(info->privileges));

	// api-version -> //*[name() ='manifest']
	__coretpk_parser_get_value(context, "//*[name() ='manifest']", "api-version", info->api_version);

catch:
	if (ret != 0) {
		if (info) {
			free((void*)info);
			info = NULL;
		}
	}

	if (context) {
		xmlXPathFreeContext(context);
		context = NULL;
	}

	if (doc) {
		xmlFreeDoc(doc);
		doc = NULL;
	}

	return info;
}

int __coretpk_parser_add_watchface(xmlXPathContextPtr context)
{
	retv_if(context == NULL, RPM_INSTALLER_ERR_WRONG_PARAM);

	int ret = 0;
	xmlXPathObjectPtr result = NULL;
	xmlXPathObjectPtr manifest = NULL;

	// 1. watchface -> //*[name() = 'watchface']
	result = xmlXPathEvalExpression((xmlChar*) "//*[name() = 'watchface']", context);
	tryvm_if(result == NULL, ret = -1, "xmlXPathEvalExpression(//*[name() = 'watchface']) failed.");

	if (xmlXPathNodeSetIsEmpty(result->nodesetval)) {
		manifest = xmlXPathEvalExpression((xmlChar*) "//*[name() = 'manifest']", context);
		tryvm_if(manifest == NULL, ret = -1, "xmlXPathEvalExpression(//*[name() = 'manifest']) failed.");

		xmlNewChild(*(manifest->nodesetval->nodeTab), NULL, BAD_CAST "watchface", NULL);
		_LOGD("<watchface> is added.");
	} else {
		_LOGD("<watchface> is already existed.");
	}

catch:
	if (result) {
		xmlXPathFreeObject(result);
		result = NULL;
	}

	if (manifest) {
		xmlXPathFreeObject(manifest);
		manifest = NULL;
	}

	return ret;
}

int _coretpk_parser_update_manifest(const char *tizen_manifest, const char *label)
{
	retv_if(tizen_manifest == NULL, RPM_INSTALLER_ERR_WRONG_PARAM);
	retv_if(label == NULL, RPM_INSTALLER_ERR_WRONG_PARAM);

	int ret = 0;
	xmlDocPtr doc = NULL;
	xmlXPathContextPtr context = NULL;

	_LOGD("------------------------------------------");
	_LOGD("update_manifest");
	_LOGD("------------------------------------------");

	doc = xmlParseFile(tizen_manifest);
	tryvm_if(doc == NULL, ret = -1, "xmlParseFile(%s) failed.", tizen_manifest);

	context = xmlXPathNewContext(doc);
	tryvm_if(context == NULL, ret = -1, "xmlXPathNewContext(%s) failed.", tizen_manifest);

	// 1. label -> //*[name() = 'label']
	ret = __coretpk_parser_set_value(context, (xmlChar*) "//*[name() = 'label']", label);
	tryvm_if(ret != 0, ret = -1, "__coretpk_parser_set_value(%s) failed.", tizen_manifest);

	(void)remove(tizen_manifest);
	xmlSaveFormatFile(tizen_manifest, doc, 1);
	_LOGD("xmlSaveFormatFile=[%s]", tizen_manifest);

catch:
	if (context) {
		xmlXPathFreeContext(context);
		context = NULL;
	}

	if (doc) {
		xmlFreeDoc(doc);
		doc = NULL;
	}

	return ret;
}

#ifdef _APPFW_FEATURE_DELTA_UPDATE
/*parse the metadata file and retrieve the info*/
delta_info* _coretpk_parser_get_delta_info(char* delta_info_file, char *manifest_file)
{

	retvm_if(delta_info_file == NULL, NULL, "metadata_file is NULL.");

	int ret = 0;
	delta_info *info = NULL;;
	xmlDocPtr deltadoc = NULL;
	xmlXPathContextPtr deltacontext = NULL;
	xmlDocPtr manifestdoc = NULL;
	xmlXPathContextPtr manifestcontext = NULL;

	_LOGD("------------------------------------------");
	_LOGD("Get Delta & manifest info info");
	_LOGD("------------------------------------------");

	deltadoc = xmlParseFile(delta_info_file);
	tryvm_if(deltadoc == NULL, ret = -1, "xmlParseFile(%s) failed.", delta_info_file);

	deltacontext = xmlXPathNewContext(deltadoc);
	tryvm_if(deltacontext == NULL, ret = -1, "xmlXPathNewContext(%s) failed.", delta_info_file);

	manifestdoc = xmlParseFile(manifest_file);
	tryvm_if(manifestdoc == NULL, ret = -1, "xmlParseFile(%s) failed.", manifest_file);

	manifestcontext = xmlXPathNewContext(manifestdoc);
	tryvm_if(manifestcontext == NULL, ret = -1, "xmlXPathNewContext(%s) failed.", manifest_file);

	info = calloc(1, sizeof(delta_info));
	tryvm_if(info == NULL, ret = -1, "calloc() failed.");

	info->pkg_info = _coretpk_parser_get_manifest_info(manifest_file);
	tryvm_if(info->pkg_info == NULL, ret = -1, "failed to get manifest info from (%s)", manifest_file);

	_LOGD("modify-files");
	__coretpk_parser_get_attr_value_list(deltacontext, "//*[name()='delta']/*[name() ='modify-files']/*[name()='file']", &(info->modify_files_list));

	_LOGD("add-files");
	__coretpk_parser_get_attr_value_list(deltacontext, "//*[name()='delta']/*[name() ='add-files']/*[name()='file']",  &(info->add_files_list));

	_LOGD("remove-files");
	__coretpk_parser_get_attr_value_list(deltacontext, "//*[name()='delta']/*[name() ='remove-files']/*[name()='file']", &(info->remove_files_list));

catch:
	/*handle errors*/
	if(ret != 0) {
		_installer_util_free_delta_info(info);
		info = NULL;
	}

	if (deltacontext) {
		xmlXPathFreeContext(deltacontext);
		deltacontext = NULL;
	}
	if (deltadoc) {
		xmlFreeDoc(deltadoc);
		deltadoc = NULL;
	}
	if (manifestcontext) {
		xmlXPathFreeContext(manifestcontext);
		manifestcontext = NULL;
	}
	if (manifestdoc) {
		xmlFreeDoc(manifestdoc);
		manifestdoc = NULL;
	}
	return info;

}
#endif
