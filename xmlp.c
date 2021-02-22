#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include "ovirt_xml.h"

int main(int argc, char *argv[])
{
	xmlParserCtxtPtr ctxt;
	xmlDocPtr doc;
	const char *filename;
	xmlNode *root = NULL, *n_major, *n_minor;

	if (argc < 2) {
		fprintf(stderr, "usage: %s xml_file_name\n", argv[0]);
		return 1;
	}
	ctxt = xmlNewParserCtxt();
	if (ctxt == NULL) {
		fprintf(stderr, "Failed to allocate parser context. "\
				"Maybe out of memory.\n");
		return 100;
	}
	filename = argv[1];
	doc = xmlCtxtReadFile(ctxt, filename, NULL, XML_PARSE_NONET);
	if (doc == NULL) {
		fprintf(stderr, "Failed to parse file: %s\n", filename);
	} else {
		if (ctxt->valid == 0) {
			fprintf(stderr, "Falied to validate the file: %s\n",
					filename);
			goto exit_10;
		}
	}

	root = xmlDocGetRootElement(doc);
	n_major = search_element(root, "/api/product_info/version/major");
	if (n_major)
		printf("Node Name: %s, value: %s\n", n_major->name, n_major->children->content);
	n_minor = search_element(root, "/api/product_info/version/minor");
	if (n_minor)
		printf("Node Name: %s, value: %s\n", n_minor->name, n_minor->children->content);

exit_10:
	xmlFreeDoc(doc);
	xmlFreeParserCtxt(ctxt);
	xmlCleanupParser();
	return 0;
}
