#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include "ovirt-xml.h"

int main(int argc, char *argv[])
{
	const char *filename;
	struct ovirt_xml *oxml;
	int len;
	FILE *fin;
	char *buf;
	xmlNode *n_major, *n_minor;

	if (argc < 2) {
		fprintf(stderr, "usage: %s xml_file_name\n", argv[0]);
		return 1;
	}
	buf = malloc(4096);
	filename = argv[1];
	fin = fopen(filename, "rb");
	len = fread(buf, 1, 4096, fin);
	fclose(fin);

	oxml = ovirt_xml_init(buf, len);
	if (!oxml)
		return 1;
	n_major = xml_search_element(oxml, "/api/product_info/version/major");
	if (n_major)
		printf("Node Name: %s, value: %s\n", n_major->name, n_major->children->content);
	n_minor = xml_search_element(oxml, "/api/product_info/version/minor");
	if (n_minor)
		printf("Node Name: %s, value: %s\n", n_minor->name, n_minor->children->content);

	ovirt_xml_exit(oxml);
	return 0;
}
