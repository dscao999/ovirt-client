#ifndef OVIRT_CLIENT_DSCAO__
#define OVIRT_CLIENT_DSCAO__
#include <curl/curl.h>

enum OVIRT_AUTH {AUTH_NONE, AUTH_BASIC, AUTH_OAUTH, AUTH_SESSION};
struct ovirt {
	CURL *curl;
	unsigned short version, auth;
	unsigned short uplen, uppos;
	unsigned int dnlen;
        unsigned int max_dnlen;
	unsigned int hdlen;
	unsigned int max_hdlen;
	char engine[64];
	char token[256];
	char errmsg[CURL_ERROR_SIZE];
	char updat[4096];
	char *hdbuf;
	char dndat[0];
};

struct ovirt *ovirt_init(const char *host, int verbose);
void ovirt_exit(struct ovirt *ov);

static inline void ovirt_set_verbose(struct ovirt *ov, int verbose)
{
	curl_easy_setopt(ov->curl, CURLOPT_VERBOSE, verbose);
}

static inline void ovirt_free_list(char **list)
{
	void *tmp = list;

	while (*list)
		free(*list++);
	free(tmp);
}

int ovirt_logon(struct ovirt *ov, const char *user, const char *pass,
		const char *domain);

int ovirt_init_version(struct ovirt *ov);
int ovirt_list_vms(struct ovirt *ov, char ***vmids);
int ovirt_vm_action(struct ovirt *ov, const char *vmref, const char *action);

#endif /* OVIRT_CLIENT_DSCAO__ */
