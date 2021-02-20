#include <stdio.h>
#include <locale.h>
#include "ovirt-client.h"

int main(int argc, char *argv[])
{
	struct ovirt *ov;
	const char *host;
	int retv;

	if (argc > 1)
		host = argv[1];
	else
		host = "engine.cluster";
	setlocale(LC_ALL, "en_US.utf8");
	ov = ovirt_init(host, 1);
	if (!ov) {
		fprintf(stderr, "CURL Initialization failed.\n");
		fprintf(stderr, "Error:\n%s\n", ov->errmsg);
		return 1;
	}
	retv = ovirt_logon(ov, "test1", "Lenovo@123", NULL);
	printf("RETV: %d\n", retv);
	printf("Header:\n%s\n", ov->hdbuf);
	printf("Response:\n%s\n", ov->dndat);
	printf("Error Message:\n%s\n", ov->errmsg);
	ovirt_exit(ov);
	return retv;
}
