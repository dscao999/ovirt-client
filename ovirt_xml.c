#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include "ovirt_xml.h"

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

static xmlNode * search_siblings(xmlNode *node, const char *nname)
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

static xmlNode * xml_search_element(struct ovirt_xml *oxml, const char *xpath)
{
	xmlNode *cur = NULL, *found;
	char *pbuf, *nname;

	pbuf = malloc(strlen(xpath) + 1);
	strcpy(pbuf, xpath);

	cur = xmlDocGetRootElement(oxml->doc);
	found = cur;
	nname = strtok(pbuf, "/");
	while (nname) {
		found = search_siblings(cur, nname);
		if (!found)
			break;
		nname = strtok(NULL, "/");
		cur = found->children;
	}
	free(pbuf);
	return found;
}

int ovirt_xml_get(struct ovirt_xml *oxml, const char *xpath, char *buf, int buflen)
{
	xmlNode *node;
	int len;

	node = xml_search_element(oxml, xpath);
	if (!node)
		return 0;
	len = strlen((const char *)node->children->content);
	if (len < buflen)
		strcpy(buf, (const char *)node->children->content);
	return len;
}
