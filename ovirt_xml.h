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

int ovirt_xml_get(struct ovirt_xml *oxml, const char *xpath,
		char *buf, int len);

#endif /* OVIRT_XML_DSCAO__ */
