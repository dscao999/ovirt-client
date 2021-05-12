#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <assert.h>
#include "ovirt-xml.h"

#define warn_overflow \
	fprintf(stderr, "Warning: buffer overflow in %s:%s\n", \
			__FILE__, __func__)

static inline const char *node_value_pointer(xmlNode *nod)
{
	const char *val = NULL;

	if (!nod || !nod->children || !nod->children->content)
		return val;
	if (strcmp((const char *)nod->children->name, "text") == 0)
		val = (const char *)nod->children->content;
	return val;
}

int xml_get_node_value(xmlNode *nod, char *buf, int buflen)
{
	int len;
	const char *nname;

	*buf = 0;
	nname = node_value_pointer(nod);
	if (!nname)
		return 0;
	len = strlen(nname);
	if (len < buflen)
		strcpy(buf, nname);
	else
		warn_overflow;
	return len;
}

int xml_get_value(struct ovirt_xml *oxml, const char *xpath, char *buf, int buflen)
{
	xmlNode *node;
	int len = 0;

	node = xml_search_element(oxml, xpath);
	if (node)
		len = xml_get_node_value(node, buf, buflen);
	return len;
}

struct ovirt_xml * ovirt_xml_init(const char *xmlbuf, int len)
{
	struct ovirt_xml *oxml;

	oxml = malloc(sizeof(struct ovirt_xml));
	if (!oxml) {
		fprintf(stderr, "Out of Memory!\n");
		return NULL;
	}
	oxml->ctxt = xmlNewParserCtxt();
	if (!oxml->ctxt) {
		fprintf(stderr, "Failed to allocate parser context. " \
				"Maybe out of memory.\n");
		free(oxml);
		return NULL;
	}
	oxml->doc = xmlCtxtReadMemory(oxml->ctxt, xmlbuf, len, NULL, NULL,
			XML_PARSE_NONET);
	if (!oxml->doc) {
		fprintf(stderr, "Failed to parse the response: %s\n", xmlbuf);
		goto err_10;
	}
	if (oxml->ctxt->valid == 0) {
		fprintf(stderr, "Failed to validate the response: %s\n",
				xmlbuf);
		goto err_20;
	}
	return oxml;

err_20:
	xmlFreeDoc(oxml->doc);
err_10:
	xmlFreeParserCtxt(oxml->ctxt);
	xmlCleanupParser();
	return NULL;
}

static xmlNode * xml_search_siblings(xmlNode *node, const char *nname)
{
	xmlNode *cur = node;

	while (cur) {
		if (cur->type == XML_ELEMENT_NODE &&
				strcmp((const char *)cur->name, nname) == 0)
			break;
		cur = cur->next;
	}
	return cur;
}

xmlNode * xml_search_children(xmlNode *node, const char *nname)
{
	return xml_search_siblings(node->children, nname);
}

xmlNode * xml_search_element(struct ovirt_xml *oxml, const char *xpath)
{
	xmlNode *cur = NULL, *found;
	char *pbuf, *nname;

	pbuf = malloc(strlen(xpath) + 1);
	strcpy(pbuf, xpath);

	cur = xmlDocGetRootElement(oxml->doc);
	found = cur;
	nname = strtok(pbuf, "/");
	while (nname) {
		found = xml_search_siblings(cur, nname);
		if (!found)
			break;
		nname = strtok(NULL, "/");
		cur = found->children;
	}
	free(pbuf);
	return found;
}

int xml_get_node_attr(xmlNode *node, const char *attr, char *buf, int maxlen)
{
	const char *val;
	xmlAttr *prop;
	int len;

	len = 0;
	if (!node)
		return len;

	prop = node->properties;
	while (prop) {
		assert(prop->type == XML_ATTRIBUTE_NODE && prop->name);
		val = (const char *)prop->children->content;
		if (strcmp((const char *)prop->name, attr) == 0) {
			len = strlen(val);
			buf[0] = 0;
			if (len < maxlen)
				strcpy(buf, val);
			else
				warn_overflow;
			break;
		}
		prop = prop->next;
	}
	return len;
}
