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
	free(oxml);
}

xmlNode * xml_search_element(struct ovirt_xml *oxml, const char *xpath);
xmlNode * xml_search_children(xmlNode *node, const char *nname);
static inline xmlNode * xml_next_node(xmlNode *node)
{
	xmlNode *next = node->next;

	while(next) {
		if (next->type == XML_ELEMENT_NODE)
			break;
		next = next->next;
	}
	return next;
}

int xml_get_node_attr(xmlNode *node, const char *attr, char *buf, int buflen);
int xml_get_node_value(xmlNode *node, char *buf, int buflen);
int xml_get_value(struct ovirt_xml *oxml, const char *xpath, char *buf, int len);

#endif /* OVIRT_XML_DSCAO__ */
