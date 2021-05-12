#ifndef OVIRT_CLIENT_DSCAO__
#define OVIRT_CLIENT_DSCAO__
#include <curl/curl.h>
#include "list_head.h"

enum OVIRT_AUTH {AUTH_NONE, AUTH_BASIC, AUTH_OAUTH, AUTH_SESSION};
struct ovirt {
	CURL *curl;
	unsigned short version, auth;
	unsigned short uplen, uppos;
	unsigned int buflen;
	unsigned int dnlen;
        unsigned int max_dnlen;
	unsigned int hdlen;
	unsigned int max_hdlen;
	char username[32], domain[32], pass[64];
	char engine[64];
	char token[256];
	char uri[256];
	char errmsg[CURL_ERROR_SIZE];
	char updat[4096];
	char *hdbuf;
	char dndat[0];
};

struct ovirt_vmdisk {
	char href[128];
	char id[64];
	char interface[16];
	struct list_head dsk_link;
	char name[32];
	unsigned long actsiz;
	char format[16];
	char status[8];
	int hit;
};

struct ovirt_vmnic {
	char id[128];
	struct list_head nic_link;
	char name[16];
	char interface[16];
	char mac[32];
	int hit;
};

struct ovirt_pool {
	char alloc[128];
	char id[64];
	char name[32];
	struct list_head pool_link;
	int vmsnow, vmsmax;
};

struct ovirt_vm {
	char href[128];
	char id[64];
	char state[32];
	char name[32];
	struct list_head vm_link;
	int con, hit;
	struct list_head nics;
	struct list_head disks;
	struct ovirt_pool *pool;
};

struct ovirt *ovirt_init(const char *host);
void ovirt_exit(struct ovirt *ov);
int ovirt_is_engine(struct ovirt *ov);

static inline void ovirt_set_verbose(struct ovirt *ov, int verbose)
{
	curl_easy_setopt(ov->curl, CURLOPT_VERBOSE, verbose);
}

int ovirt_logon(struct ovirt *ov, const char *user, const char *pass,
		const char *domain);
void ovirt_logout(struct ovirt *ov);

int ovirt_init_version(struct ovirt *ov);
int ovirt_list_vms(struct ovirt *ov, struct list_head *vmhead,
		struct list_head *vmpool);
int ovirt_list_pools(struct ovirt *ov, struct list_head *vmpool);
int ovirt_pool_allocatvm(struct ovirt *ov, struct ovirt_pool *vmpool);
int ovirt_vm_action(struct ovirt *ov, struct ovirt_vm *vm,
		const char *action);
int ovirt_get_vmdisks(struct ovirt *ov, struct ovirt_vm *vm);
int ovirt_get_vmnics(struct ovirt *ov, struct ovirt_vm *vm);
int ovirt_get_vmconsole(struct ovirt *ov, struct ovirt_vm *vm, const char *vv);

void ovirt_vmlist_free(struct list_head *vmhead);

#endif /* OVIRT_CLIENT_DSCAO__ */
