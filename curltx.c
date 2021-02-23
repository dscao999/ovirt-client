#include <stdio.h>
#include <stdlib.h>
#include <locale.h>
#include "ovirt-client.h"

int main(int argc, char *argv[])
{
	struct ovirt *ov;
	const char *host;
	int retv, verbose = 0;

	if (argc > 1)
		host = argv[1];
	else
		host = "engine.cluster";
	if (argc > 2)
		verbose = atoi(argv[2]);

	ov = ovirt_init(host, verbose);
	if (!ov) {
		fprintf(stderr, "CURL Initialization failed.\n");
		fprintf(stderr, "Error:\n%s\n", ov->errmsg);
		return 1;
	}
	retv = ovirt_logon(ov, "test1", "Lenovo@123", NULL);
	if (retv < 0)
		return 5;
	retv = ovirt_init_version(ov);
	if (retv >= 0)
		printf("oVirt Version: %d\n", (int)ov->version);
	ovirt_exit(ov);
	return retv;
}
