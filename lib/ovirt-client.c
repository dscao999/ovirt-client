#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <sys/mman.h>
#include <json-c/json.h>
#include <libxml/parser.h>
#include <libxml/tree.h>
#include <assert.h>
#include <errno.h>
#include "base64.h"
#include "ovirt-xml.h"
#include "ovirt-client-internal.h"
#include "ovirt-client.h"

static inline struct ovirt_pool *pool_id2struct(struct ovirt *ov, const char *pool_id)
{
	struct ovirt_pool *pool = NULL, *curpool;
	struct list_head *cur;

	list_for_each(cur, &ov->vmpool) {
		curpool = list_entry(cur, struct ovirt_pool, pool_link);
		if (strcmp(curpool->id, pool_id) == 0)
			break;
	}
	if (cur != &ov->vmpool)
		pool = curpool;
	return pool;
}

static inline
struct ovirt_vm *vm_id2struct(struct ovirt *ov, const char *vmid)
{
	struct ovirt_vm *vm = NULL, *curvm;
	struct list_head *cur;

	list_for_each(cur, &ov->vmhead) {
		curvm = list_entry(cur, struct ovirt_vm, vm_link);
		if (strcmp(curvm->id, vmid) == 0)
			break;
	}
	if (cur != &ov->vmhead)
		vm = curvm;
	return vm;
}

int ovirt_valid(const char *host)
{
	struct ovirt *ov;
	int retv = 0;

	ov = ovirt_init(host);
	if (!ov)
		return retv;
	retv = ovirt_is_engine(ov);
	ovirt_exit(ov);
	return retv;
}

int ovirt_refresh_resources(struct ovirt *ov)
{
	int retv, sum;

	retv = ovirt_lock(ov, 30);
	if (retv != 1)
		return retv;
	ov->numpools = 0;
	ov->numvms = 0;
	retv = ovirt_list_vmpools(ov, &ov->vmpool);
	if ( retv >= 0) {
		ov->numpools = retv;
		retv = ovirt_list_vms(ov, &ov->vmhead, &ov->vmpool);
	}
	ovirt_unlock(ov);
	if (retv >= 0) {
	       ov->numvms = retv;
	       sum = ov->numpools + ov->numvms;
	} else
		sum = retv;

	return sum;
}

int ovirt_vmpool_getnum(const struct ovirt *ov)
{
	return ov->numpools;
}

int ovirt_vm_getnum(const struct ovirt *ov)
{
	return ov->numvms;
}

int ovirt_major_version(struct ovirt *ov)
{
	return ov->version;
}

struct ovirt * ovirt_connect(const char *host, const char *user,
		const char *passwd, const char *domain)
{
	struct ovirt *ov;
	int retv;

	ov = ovirt_init(host);
	if (!ov)
		return ov;
	retv = ovirt_logon(ov, user, passwd, domain);
	if (retv < 0)
		goto err_exit_10;
	retv = ovirt_init_version(ov);
	if (retv < 0)
		goto err_exit_10;
	return ov;

err_exit_10:
	ovirt_exit(ov);
	return NULL;
}

void ovirt_disconnect(struct ovirt *ov, int err)
{
	while (ovirt_lock(ov, 30) != 1)
		fprintf(stderr, "Cannot obtain ov lock.\n");

	if (!err)
		ovirt_logout(ov);
	ovirt_exit(ov);
}

int ovirt_vmpool_next(struct ovirt *ov, char *id, int buflen, void **ctx)
{
	struct list_head *cur;
	struct ovirt_pool *nxt_pool, *pool = (struct ovirt_pool *)(*ctx);
	int retv, len = 0;

	retv = ovirt_lock(ov, 30);
	if (retv != 1)
		return retv;

	if (pool == NULL)
		cur = &ov->vmpool;
	else
		cur = &pool->pool_link;
	nxt_pool = NULL;
	while (cur->next != &ov->vmpool) {
		cur = cur->next;
		nxt_pool = list_entry(cur, struct ovirt_pool, pool_link);
		if (nxt_pool->removed == 0)
			break;
		nxt_pool = NULL;
	}
	*ctx = nxt_pool;
	if (nxt_pool) {
		len = strlen(nxt_pool->id);
		if (len < buflen)
			strcpy(id, nxt_pool->id);
	}

	ovirt_unlock(ov);
	return len;
}

int ovirt_vm_next(struct ovirt *ov, char *id, int buflen, void **ctx)
{
	struct list_head *cur;
	struct ovirt_vm *nxt_vm, *vm = (struct ovirt_vm *)(*ctx);
	int retv, len = 0;


	retv = ovirt_lock(ov, 30);
	if (retv != 1)
		return retv;

	if (vm == NULL)
		cur = &ov->vmhead;
	else
		cur = &vm->vm_link;
	nxt_vm = NULL;
	if (cur->next != &ov->vmhead)
		nxt_vm = list_entry(cur->next, struct ovirt_vm, vm_link);
	*ctx = nxt_vm;
	if (nxt_vm) {
		len = strlen(nxt_vm->id);
		if (len < buflen)
			strcpy(id, nxt_vm->id);
	}

	ovirt_unlock(ov);
	return len;
}

int ovirt_vmpool_name(struct ovirt *ov, const char *pool_id,
		char *name, int buflen)
{
	struct list_head *cur;
	struct ovirt_pool *curpool;
	int retv, len;

	retv = ovirt_lock(ov, 30);
	if (retv != 1)
		return retv;

	len = -1;
	list_for_each(cur, &ov->vmpool) {
		curpool = list_entry(cur, struct ovirt_pool, pool_link);
		if (strcmp(curpool->id, pool_id) == 0)
			break;
	}
	if (cur != &ov->vmpool) {
		len = strlen(curpool->name);
		if (len < buflen)
			strcpy(name, curpool->name);
	}
	ovirt_unlock(ov);
	return len;
}

int ovirt_vm_name(struct ovirt *ov, const char *vmid,
		char *name, int buflen)
{
	struct list_head *cur;
	struct ovirt_vm *curvm;
	int retv, len = -1;

	retv = ovirt_lock(ov, 30);
	if (retv != 1)
		return retv;

	list_for_each(cur, &ov->vmhead) {
		curvm = list_entry(cur, struct ovirt_vm, vm_link);
		if (strcmp(curvm->id, vmid) == 0)
			break;
	}
	if (cur != &ov->vmhead) {
		len = strlen(curvm->name);
		if (len < buflen)
			strcpy(name, curvm->name);
	}
	ovirt_unlock(ov);
	return len;
}

int ovirt_vm_status_query(struct ovirt *ov, const char *vmid)
{
	int retv;
	struct ovirt_vm *vm;

	retv = ovirt_lock(ov, 30);
	if (retv != 1)
		return retv;

	vm = vm_id2struct(ov, vmid);
	if (vm)
		retv = ovirt_vm_action(ov, vm, "status");
	else
		retv = -1;

	ovirt_unlock(ov);
	return retv;
}

const char * ovirt_vm_status(int sta)
{
	return ovirt_vm_status_internal(sta);
}

int ovirt_vm_start(struct ovirt *ov, const char *vmid)
{
	int retv = 0;
	struct ovirt_vm *vm;

	retv = ovirt_lock(ov, 30);
	if (retv != 1)
		return retv;

	vm = vm_id2struct(ov, vmid);
	if (!vm) {
		retv = -1;
		goto exit_10;
	}

	retv = ovirt_vm_action(ov, vm, "status");
	if (retv == 1 || retv == 2) {
		retv = ovirt_vm_action(ov, vm, "start");
		if (retv == 0)
			retv = ovirt_vm_action(ov, vm, "status");
	}

exit_10:
	ovirt_unlock(ov);
	return retv;
}

int ovirt_vm_stop(struct ovirt *ov, const char *vmid)
{
	int retv = 0;
	struct ovirt_vm *vm;

	retv = ovirt_lock(ov, 30);
	if (retv != 1)
		return retv;

	vm = vm_id2struct(ov, vmid);
	if (!vm) {
		retv = -1;
		goto exit_10;
	}

	retv = ovirt_vm_action(ov, vm, "status");
	if (retv == 8) {
		retv = ovirt_vm_action(ov, vm, "stop");
		if (retv == 0)
			retv = ovirt_vm_action(ov, vm, "status");
	}

exit_10:
	ovirt_unlock(ov);
	return retv;
}

int ovirt_vm_getvv(struct ovirt *ov, const char *vmid, const char *vvname)
{
	int retv = -1;
	struct ovirt_vm *vm;

	retv = ovirt_lock(ov, 30);
	if (retv != 1)
		return retv;

	vm = vm_id2struct(ov, vmid);
	if (vm)
		retv = ovirt_get_vmconsole(ov, vm, vvname);

	ovirt_unlock(ov);
	return retv;
}

int ovirt_vmpool_maxvms(struct ovirt *ov, const char *id)
{
	struct ovirt_pool *pool;
	int retv;

	retv = ovirt_lock(ov, 30);
	if (retv != 1)
		return retv;

	pool = pool_id2struct(ov, id);
	retv = -1;
	if (pool)
		retv = pool->vmsmax;

	ovirt_unlock(ov);
	return retv;
}

int ovirt_vmpool_curvms(struct ovirt *ov, const char *id)
{
	struct ovirt_pool *pool;
	int retv;

	retv = ovirt_lock(ov, 30);
	if (retv != 1)
		return retv;

	retv = -1;
	pool = pool_id2struct(ov, id);
	if (pool)
		retv = pool->vmsnow;

	ovirt_unlock(ov);
	return retv;
}

int ovirt_vmpool_grabvm(struct ovirt *ov, const char *id)
{
	int retv;
	struct ovirt_pool *pool;

	retv = ovirt_lock(ov, 30);
	if (retv != 1)
		return retv;

	pool = pool_id2struct(ov, id);
	retv= -1;

	if (pool) {
		retv = ovirt_pool_allocatvm(ov, pool);
		if (retv > 0)
			ov->numvms = ovirt_list_vms(ov, &ov->vmhead, &ov->vmpool);
	}

	ovirt_unlock(ov);
	return retv;
}
