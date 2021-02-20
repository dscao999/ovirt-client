#ifndef OVIRT_CLIENT_DSCAO__
#define OVIRT_CLIENT_DSCAO__
#include <curl/curl.h>

struct ovirt {
	CURL *curl;
	unsigned short version, ocmd;
	unsigned short uplen, uppos;
	unsigned int dnlen;
        unsigned int max_dnlen;
	unsigned int hdlen;
	unsigned int max_hdlen;
	char engine[64];
	char token[128];
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

int ovirt_logon(struct ovirt *ov, const char *user, const char *pass,
		const char *domain);

#endif /* OVIRT_CLIENT_DSCAO__ */
