#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <locale.h>
#include <assert.h>
#include "ovirt-client.h"

int main(int argc, char *argv[])
{
	struct ovirt *ov;
	const char *username, *pass, *action;
	int retv, verbose = 0, num;
	char **vmids, **vmid;
	int status, compcode;

	if (argc > 1)
		username = argv[1];
	else
		username = "testx";
	if (argc > 2)
		pass = argv[2];
	else
		pass = "abc123";
	if (argc > 3)
		action = argv[3];
	else
		action = "status";
	if (argc > 4)
		verbose = atoi(argv[4]);

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
	while (*vmid) {
		compcode = 0;
		if (strcmp(action, "start") == 0)
			compcode = 4;
		else if (strcmp(action, "shutdown") == 0 || 
				strcmp(action, "stop") == 0)
			compcode = 1;
		status = ovirt_vm_action(ov, *vmid, action);
		if (compcode) {
			do {
				sleep(3);
				status = ovirt_vm_action(ov, *vmid, "status");
				printf("VM Status: %d\n", status);
			} while (status != compcode);
		} else {
			printf("VM State: %d\n", status);
		}

		vmid++;
	}
	ovirt_free_list(vmids);

exit_10:
	ovirt_exit(ov);
	return retv;
}
