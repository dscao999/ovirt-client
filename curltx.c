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
	const char *username, *pass;
	int retv, verbose = 0, num;
	int i, selvm;
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
	num = ovirt_list_vms(ov, &vms);
	do {
		for (curvm = vms, i = 0; i < num; i++, curvm++) {
			ovirt_vm_action(ov, curvm, "status");
			printf("[%2d] - %s, state: %s\n", i, curvm->id,
					curvm->state);
		}
		printf("Please select the VM to connect: ");
		fflush(stdout);
		scanf("%d", &selvm);
	} while (selvm < 0 || selvm >= num);
	printf("Selected VM: %d\n", selvm);
//	num = ovirt_get_vmconsole(ov, curvm, "/tmp/myvv.txt");
	free(vms);

exit_10:
	ovirt_exit(ov);
	return retv;
}
