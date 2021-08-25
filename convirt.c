/*
 * A C client communicationg with oVirt engine through its REST API
 * by the means of libcurl
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <locale.h>
#include <errno.h>
#include <assert.h>
#include <signal.h>
#include <time.h>
#include <sys/types.h>
#include <sys/wait.h>
#include "list_head.h"
#include "http_codes.h"
#include "ovirt-client.h"

struct remote_view {
	struct list_head vw_link;
	struct ovirt *ov;
	char vmid[40];
	pid_t rid;
};

static int post_view(struct list_head *head)
{
	struct remote_view *view;
	struct list_head *cur, *tmp;
	pid_t expid;
	int num, wstatus;
	time_t curtm;
	char *stmp, *ln;

	num = 0;
	list_for_each_safe(cur, tmp, head) {
		view = list_entry(cur, struct remote_view, vw_link);
		expid = waitpid(view->rid, &wstatus, WNOHANG);
		if (expid == -1)
			fprintf(stderr, "waitpid failed: %s\n",
					strerror(errno));
		else if (expid > 0) {
			curtm = time(NULL);
			stmp = ctime(&curtm);
			ln = strchr(stmp, '\n');
			if (ln)
				*ln = 0;
			fprintf(stderr, "%s Info: vm %s disconnected, code: %x\n",
					stmp, view->vmid, wstatus);
			list_del(cur, head);
			free(view);
			num++;
		}
	}
	return num;
}

static volatile int global_stop = 0;
static volatile int view_exited = 0;

static const struct timespec itv = {.tv_sec = 1, .tv_nsec = 0};


void sig_handler(int sig)
{
	if (sig == SIGCHLD)
		view_exited = 1;
	else if (sig == SIGINT || sig == SIGTERM)
		global_stop = 1;
}

static int connect_vm(struct ovirt *ov, const char *vmid, struct list_head *head)
{
	int retv, start = 0;
	struct list_head *cur;
	struct remote_view *view;
	char vvname[128];
	pid_t cpid;
	const char *vm_status;

	list_for_each(cur, head) {
		view = list_entry(cur, struct remote_view , vw_link);
		if (strcmp(view->vmid, vmid) == 0)
			break;
	}
	if (cur != head) {
		fprintf(stderr, "VM %s already connected.\n", vmid);
		return 0;
	}
	view = malloc(sizeof(struct remote_view));
	if (!view) {
		fprintf(stderr, "Out of Memory!\n");
		return -ENOMEM;
	};
	view->ov = ov;
	strcpy(view->vmid, vmid);
	INIT_LIST_HEAD(&view->vw_link);
	view->rid = 0;

	retv = ovirt_vm_status_query(ov, vmid);
	if (retv < 0)
		goto err_exit_10;
	vm_status = ovirt_vm_status(retv);
	if (strcmp(vm_status, "down") == 0 ||
			strcmp(vm_status, "suspended") == 0) {
		retv = ovirt_vm_start(ov, vmid);
		if (retv < 0)
			goto err_exit_10;
		start = 1;
	}
	if (start) {
		while (1) {
			nanosleep(&itv, 0);
			retv = ovirt_vm_status_query(ov, vmid);
			if (retv < 0)
				goto err_exit_10;
			vm_status = ovirt_vm_status(retv);
			if (strcmp(vm_status, "down") == 0 ||
					strcmp(vm_status, "suspended") == 0)
				goto err_exit_10;
			if (strcmp(vm_status, "wait_for_launch") != 0)
				break;
		}
	}

	sprintf(vvname, "vv-%s.txt", vmid);
	retv = ovirt_vm_getvv(ov, vmid, vvname);
	if (retv < 0) {
		if ((-retv & 0x0fff) == http_no_content) {
			fprintf(stderr, "VM: %s, console occupied.\n", vmid);
			retv = 0;
		}
		goto err_exit_10;
	}
	cpid = fork();
	if (cpid == -1) {
		fprintf(stderr, "Cannot fork: %s\n", strerror(errno));
		retv = -errno;
		goto err_exit_10;
	} else if (cpid == 0) {
		retv = execlp("remote-viewer", "remote-viewer", "--",
				vvname, NULL);
		fprintf(stderr, "Cannot start remote-viewer: %s\n",
				strerror(errno));
		exit(1);
	}
	view->rid = cpid;
	list_add(&view->vw_link, head);

	return retv;

err_exit_10:
	free(view);
	printf("Cannot connect the VM: %s, error code: %X\n", vmid, -retv);
	return retv;
}

struct ovirt_uuid {
	char id[40];
	char name[32];
	unsigned char pool;
};

static struct ovirt_uuid idrecs[20];

static int refresh_idrecs(struct ovirt *ov, int *numpools, int *numvms)
{
	int retv, i;
	void *ctx;
	struct ovirt_uuid *curid;

	retv = ovirt_refresh_resources(ov);
	if (retv < 0) {
		fprintf(stderr, "oVirt resources refresh failed: %X\n", -retv);
		return retv;
	}
	*numpools = ovirt_vmpool_getnum(ov);
	*numvms = ovirt_vm_getnum(ov);
	i = 0;
	curid = idrecs;
	ctx = NULL;
	do {
		retv = ovirt_vmpool_next(ov, curid->id, sizeof(curid->id),
				&ctx);
		if (retv == 0)
			break;
		ovirt_vmpool_name(ov, curid->id, curid->name, sizeof(curid->name));
		curid->pool = 1;
		i += 1;
		curid++;
	} while (i < 20);
	assert(*numpools == i);

	ctx = NULL;
	do {
		retv = ovirt_vm_next(ov, curid->id, sizeof(curid->id), &ctx);
		if (retv == 0)
			break;
		ovirt_vm_name(ov, curid->id, curid->name, sizeof(curid->name));
		curid->pool = 0;
		i += 1;
		curid++;
	} while (i < 20);
	assert(*numpools + *numvms == i);

	return *numpools + *numvms;
}

int main(int argc, char *argv[])
{
	struct ovirt *ov;
	const char *username, *pass;
	int retv, numvms;
	int i, selvm, op_kill = 0;
	struct sigaction act;
	struct list_head view_head, *cur;
	struct remote_view *cur_view;
	struct timespec tm;
	int numpools;
	char *host = "engine.lidc.com";
	struct ovirt_uuid *curid;
	const char *vm_status;
	int vmsmax, vmsnow;
	char ans[16], *digit;

	tzset();
	retv = 0;
	if (argc > 1)
		username = argv[1];
	else
		username = "testx";
	if (argc > 2)
		pass = argv[2];
	else
		pass = "abc123";
	if (argc > 3)
		host = argv[3];

	INIT_LIST_HEAD(&view_head);
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

	retv = ovirt_valid(host);
	if (retv <= 0) {
		fprintf(stderr, "Host %s has no oVirt service running.\n", host);
		return 6;
	}

	ov = ovirt_connect(host, username, pass, NULL);
	if (!ov) {
		fprintf(stderr, "Connection Initialization failed.\n");
		return 1;
	}
	if ((retv = ovirt_major_version(ov)) < 4) {
		fprintf(stderr, "Current oVirt service version: %d, Only " \
				"version 4 or highter is supported.", retv);
		ovirt_disconnect(ov, 0);
		return 2;
	}

	curid = NULL;
	while (global_stop == 0) {
		retv = refresh_idrecs(ov, &numpools, &numvms);
		if (retv < 0) {
			fprintf(stderr, "Cannot get resources for %s.\n",
					username);
			global_stop =1;
			continue;
		}

		curid = idrecs;
		for (i = 0; i < numpools; i++, curid++) {
			assert(curid->pool == 1);
			vmsmax = ovirt_vmpool_maxvms(ov, curid->id);
			vmsnow = ovirt_vmpool_curvms(ov, curid->id);
			printf("[%2d] - %s, Name: %16s, Max VM: %4d, " \
					"Allocated: %1d\n", i, curid->id,
					curid->name, vmsmax, vmsnow);
		}
		for (; i < numpools + numvms; i++, curid++) {
			assert(curid->pool == 0);
			retv = ovirt_vm_status_query(ov, curid->id);
			if (retv < 0) {
				global_stop = 1;
				continue;
			}
			vm_status = ovirt_vm_status(retv);
			printf("[%2d] - %s, Name: %16s, state: %4s\n", i,
					curid->id, curid->name, vm_status);
		}
		printf("Please select the VM to connect[-1, exit]" \
				"[>= %d, refresh]: ", i);
		fflush(stdout);
		scanf("%15s", ans);
		ans[sizeof(ans)-1] = 0;
		digit = ans;
		if (*digit == '+' || *digit == '-')
			digit++;
		while (*digit != 0 && *digit >= '0' && *digit <= '9')
			digit += 1;
		if (*digit != 0)
			selvm = i;
		else
			selvm = atoi(ans);
		if (selvm <= -1)
			break;
		else if (selvm < numpools) {
			retv = ovirt_vmpool_grabvm(ov, idrecs[selvm].id);
			if (retv < 0) {
				global_stop = 1;
				continue;
			}
			if (retv == 0)
				fprintf(stderr, "Cannot allocate more VM.\n");
		} else if (selvm >= numpools && selvm < numvms + numpools) {
			retv = connect_vm(ov, idrecs[selvm].id, &view_head);
		}
		if (view_exited != 0) {
			view_exited = 0;
			post_view(&view_head);
		}
	}

	list_for_each(cur, &view_head) {
		cur_view = list_entry(cur, struct remote_view, vw_link);
		kill(cur_view->rid, SIGTERM);
		if (op_kill== 0)
			op_kill = 1;
	}
	tm.tv_sec = 0;
	tm.tv_nsec = 100000000ul;
	if (op_kill)
		nanosleep(&tm, NULL);
	while (view_head.next != &view_head) {
		post_view(&view_head);
		nanosleep(&tm, NULL);
	}
	if (retv >= 0) {
		retv = refresh_idrecs(ov, &numpools, &numvms);
		if (retv > 0)
		curid = idrecs;
		for (i = 0; i < numpools; i++, curid++) {
			vmsmax = ovirt_vmpool_maxvms(ov, curid->id);
			vmsnow = ovirt_vmpool_curvms(ov, curid->id);
			printf("[%2d] - %s, Max VM: %4d, Allocated: %1d\n", i,
					curid->id, vmsmax, vmsnow);
		}
	}

	ovirt_disconnect(ov, (retv < 0));
	if (retv < 0)
		retv = -retv;
	retv = retv & 0x0fff;
	return retv;
}
