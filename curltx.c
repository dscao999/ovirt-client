#include <stdio.h>
#include <stdlib.h>
#include <locale.h>
#include <assert.h>
#include "ovirt-client.h"

int main(int argc, char *argv[])
{
	struct ovirt *ov;
	const char *username, *pass;
	int retv, verbose = 0, num;
	char **vmids, **vmid;

	if (argc > 1)
		username = argv[1];
	else
		username = "testx";
	if (argc > 2)
		pass = argv[2];
	else
		pass = "abc123";
	if (argc > 3)
		verbose = atoi(argv[3]);

	ov = ovirt_init("engine.cluster", verbose);
	if (!ov) {
		fprintf(stderr, "CURL Initialization failed.\n");
		fprintf(stderr, "Error:\n%s\n", ov->errmsg);
		return 1;
	}
	retv = ovirt_logon(ov, username, pass, NULL);
	if (retv < 0)
		goto exit_10;
	retv = ovirt_init_version(ov);
	if (retv != 0) {
		fprintf(stderr, "Cannot Init version\n");
		goto exit_10;
	}
	num = ovirt_list_vms(ov, &vmids);
	if (num < 0) {
		retv = 5;
		assert(vmids == NULL);
		goto exit_10;
	}
	vmid = vmids;
	while (*vmid)
		printf("vms: %s\n", *vmid++);
	printf("Number of VMs: %d\n", num);
	ovirt_free_list(vmids);
exit_10:
	ovirt_exit(ov);
	return retv;
}
