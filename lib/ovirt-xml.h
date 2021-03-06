#ifndef OVIRT_XML_DSCAO__
#define OVIRT_XML_DSCAO__

#include <libxml/parser.h>
#include <libxml/tree.h>

struct ovirt_xml {
	xmlParserCtxtPtr ctxt;
	xmlDocPtr doc;
};

struct ovirt_xml *ovirt_xml_init(const char *xmlbuf, int len);

static inline void ovirt_xml_exit(struct ovirt_xml *oxml)
{
	xmlFreeDoc(oxml->doc);
	xmlFreeParserCtxt(oxml->ctxt);
	xmlCleanupParser();
}

static inline xmlNode * xml_next_element(xmlNode *node)
{
	if (!node)
		return NULL;

	node = node->next;
	while (node) {
		if (node->type == XML_ELEMENT_NODE)
			break;
		node = node->next;
	}
	return node;
}

xmlNode * xml_search_siblings(xmlNode *node, const char *nname);

xmlNode * xml_search_element(struct ovirt_xml *oxml, const char *xpath);

int xmlget_value(struct ovirt_xml *oxml, const char *xpath,
		char *buf, int len);

#endif /* OVIRT_XML_DSCAO__ */
