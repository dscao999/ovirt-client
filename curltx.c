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
	int status, compcode, i;
	struct ovirt_vm *vms, *curvm;

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
	num = ovirt_list_vms(ov, &vms);
	curvm = vms;
	for (curvm = vms, i = 0; i < num; i++, curvm++) {
		if (strcmp(action, "start") == 0)
			compcode = 4;
		else if (strcmp(action, "shutdown") == 0 || 
				strcmp(action, "stop") == 0)
			compcode = 1;
		else if (strcmp(action, "status") == 0)
			compcode = 0;
		status = ovirt_vm_action(ov, curvm, action);
		if (compcode != 0) {
			do {
				sleep(3);
				status = ovirt_vm_action(ov, curvm, "status");
				printf("VM Status: %d\n", status);
			} while (status != compcode);
		} else {
			printf("VM State: %d\n%s\n", status, ov->dndat);
		}
	}
	free(vms);

exit_10:
	ovirt_exit(ov);
	return retv;
}
