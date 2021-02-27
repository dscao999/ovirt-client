#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <locale.h>
#include <errno.h>
#include <assert.h>
#include <signal.h>
#include <sys/types.h>
#include <sys/wait.h>
#include "list_head.h"
#include "ovirt-client.h"

struct remote_view {
	struct list_head lst;
	char vmid[128];
	pid_t rid;
};

static int post_view(struct list_head *head)
{
	struct remote_view *view;
	struct list_head *cur, *tmp;
	pid_t expid;
	int num;

	INIT_LIST_HEAD(&rem_head);
	num = 0;
	list_for_each_safe(cur, tmp, head) {
		view = list_entry(cur, struct remote_view, lst);
		expid = waitpid(view->rid, NULL, WNOHANG);
		if (expid == -1)
			fprintf(stderr, "waitpid failed: %s\n",
					strerror(errno));
		else if (expid > 0) {
			list_del(cur, head);
			free(view);
			num++;
		}
	}
	return num;
}

static volatile int global_stop = 0;
static volatile int view_exited = 0;


void sig_handler(int sig)
{
	if (sig == SIGCHLD)
		view_exited = 1;
	else if (sig == SIGINT || sig == SIGTERM)
		global_stop = 1;
}

static int connect_vm(struct ovirt *ov, struct ovirt_vm *curvm,
		struct list_head *head)
{
	int retv = 0, num, sact;
	struct remote_view *view;
	char vvname[64];

	view = malloc(sizeof(struct remote_view));
	if (!view) {
		fprintf(stderr, "Out of memory.\n");
		return -ENOMEM;
	}
	sact = 0;
	if (strcmp(curvm->state, "down") == 0 ||
			strcmp(curvm->state, "suspended") == 0) {
		printf("Starting the VM %s .", curvm->id);
		retv = ovirt_vm_action(ov, curvm, "start");
		sact = 1;
	}
	if (retv != 0)
		goto exit_10;
	while (strcmp(curvm->state, "up") != 0 && global_stop == 0 &&
			retv == 0) {
		sleep(3);
		retv = ovirt_vm_action(ov, curvm, "status");
		printf(".");
		fflush(stdout);
	}
	if (sact)
		printf("\n");
	if (retv < 0 || global_stop != 0)
		goto exit_10;
	sprintf(vvname, "vv-%s.txt", curvm->id);
	num = ovirt_get_vmconsole(ov, curvm, vvname);
	if (num <= 0)
		goto exit_10;
	strcpy(view->vmid, curvm->id);
	view->rid = fork();
	if (view->rid == -1) {
		fprintf(stderr, "Cannot fork: %s\n", strerror(errno));
		retv = -errno;
		goto exit_10;
	} else if (view->rid == 0) {
		retv = execlp("remote-viewer", "remote-viewer", "--",
				vvname, NULL);
		fprintf(stderr, "Cannot start remote-viewer: %s\n",
				strerror(errno));
		exit(1);
	}
	list_add(&view->lst, head);
	retv = 1;

exit_10:
	if (retv != 1)
		free(view);
	return retv;
}

int main(int argc, char *argv[])
{
	struct ovirt *ov;
	const char *username, *pass;
	int retv, verbose = 0, num;
	int i, selvm;
	struct ovirt_vm *vms, *curvm;
	struct sigaction act;
	struct dblist view_head, *cur;
	struct remote_view *view;

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

	memset(&act, 0, sizeof(act));
	act.sa_handler = sig_handler;
	if (sigaction(SIGCHLD, &act, NULL) == -1) {
		fprintf(stderr, "Cannot install SIG handler: %s\n", 
				strerror(errno));
		return 5;
	}
	if (sigaction(SIGTERM, &act, NULL) == -1) {
		fprintf(stderr, "Cannot install SIG handler: %s\n", 
				strerror(errno));
		return 5;
	}
	if (sigaction(SIGINT, &act, NULL) == -1) {
		fprintf(stderr, "Cannot install SIG handler: %s\n", 
				strerror(errno));
		return 5;
	}
	view_head.next = &view_head;
	view_head.prev = &view_head;

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
	vms = NULL;
	while (global_stop == 0) {
		free(vms);
		num = ovirt_list_vms(ov, &vms);
		if (num <= 0) {
			fprintf(stderr, "No usable VMs now: %s.\n",
					username);
			sleep(5);
			continue;
		}
		for (curvm = vms, i = 0; i < num; i++, curvm++) {
			ovirt_vm_action(ov, curvm, "status");
			printf("[%2d] - %s, state: %s\n", i, curvm->id,
					curvm->state);
		}
		printf("Please select the VM to connect: ");
		fflush(stdout);
		scanf("%d", &selvm);
		if (selvm == -1)
			break;
		if (selvm > -1 && selvm < num) {
			curvm = vms + selvm;
			retv = connect_vm(ov, curvm, &view_head);
		}
		if (view_exited != 0) {
			view_exited = 0;
			num = post_view(&view_head);
		}
	}
	cur = view_head.next;
	while (cur != &view_head) {
		view =container_of(cur, struct remote_view, lst);
		kill(view->rid, SIGTERM);
		cur = cur->next;
	}
	do {
		num = post_view(&view_head);
		fprintf(stderr, "%d view collected.\n", num);
	} while (view_head.next != &view_head);

	free(vms);
exit_10:
	ovirt_exit(ov);
	if (retv < 0)
		retv = (-retv) & 0x0fff;
	return retv;
}
