#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <sys/mman.h>
#include <b64/cencode.h>
#include "ovirt-client.h"

enum OVIRTCMD {
	INIT = 0, LOGON_SSO = 1, LOGON_SESSON = 2, GETVMS = 3, GETCON = 4,
	GETVV = 5
};

#define OVIRT_SIZE (4*1024*1024)
#define OVIRT_HEADER_SIZE	(1024*1024)

static size_t upload(char *buf, size_t siz, size_t nitems, void *usrdat)
{
	struct ovirt *ov = usrdat;
	int uplen, buflen, datlen;

	buflen = siz * nitems;
	datlen = ov->uplen - ov->uppos;
	uplen = buflen > datlen? datlen : buflen;
	if (uplen == 0)
		return 0;
	memcpy(buf, ov->updat + ov->uppos, uplen);
	ov->uppos += uplen;
	return uplen;
}

static size_t dnload(char *buf, size_t siz, size_t nmemb, void *usrdat)
{
	struct ovirt *ov = usrdat;
	int dnlen, lenrem;

	dnlen = nmemb * siz;
	lenrem = ov->max_dnlen - ov->dnlen;
	if (lenrem < dnlen) {
		fprintf(stderr, "Cannot receive more data. Overflow!\n");
		dnlen = lenrem;
	}
	memcpy(ov->dndat + ov->dnlen, buf, dnlen);
	ov->dnlen += dnlen;
	return dnlen;
}

static size_t hdrecv(char *buf, size_t siz, size_t nitems, void *usrdat)
{
	struct ovirt *ov = usrdat;
	int hdlen, lenrem;

	hdlen = siz * nitems;
	lenrem = ov->max_hdlen - ov->hdlen;
	if (lenrem < hdlen) {
		fprintf(stderr, "Cannot receive more header. Overflow!\n");
		hdlen = lenrem;
	}
	memcpy(ov->hdbuf + ov->hdlen, buf, hdlen);
	ov->hdlen += hdlen;
	return hdlen;
}

static int ovirt_oauth_login(struct ovirt *ov, const char *user,
		const char *pass, const char *domain)
{
	static const char sso_path[] = "/ovirt-engine/sso/oauth/token";
	static const char sso_param[] = "grant_type=password&" \
			"scope=ovirt-app-api&username=%s@%s&password=%s";
	const char *dom;
        char url[128];
	char *postdata;
	struct curl_slist *header = NULL;
	int retv;

	strcpy(url, ov->engine);
	strcat(url, sso_path);
	curl_easy_setopt(ov->curl, CURLOPT_URL, url);
	if (domain == NULL || strlen(domain) == 0)
		dom = "internal";
	else
		dom = domain;
	ov->uplen = snprintf(ov->updat, sizeof(ov->updat), sso_param, user,
			dom, pass);
	if (ov->uplen == sizeof(ov->updat) - 1)
		fprintf(stderr, "Warning: sso param may have overflowed" \
			       " the buffer.\n");
	postdata = curl_easy_escape(ov->curl, ov->updat, ov->uplen);
	header = curl_slist_append(header, "Accept: application/json");
	curl_easy_setopt(ov->curl, CURLOPT_HTTPHEADER, header);
	curl_easy_setopt(ov->curl, CURLOPT_POSTFIELDSIZE, strlen(postdata));
	curl_easy_setopt(ov->curl, CURLOPT_POSTFIELDS, postdata); 
	ov->dnlen = 0;
	ov->ocmd = LOGON_SSO;
	ov->errmsg[0] = 0;
	retv = curl_easy_perform(ov->curl);
	curl_easy_setopt(ov->curl, CURLOPT_POST, 0);
	curl_slist_free_all(header);
	curl_free(postdata);
	return retv;
}

struct ovirt * ovirt_init(const char *ohost, int verbose)
{
	struct ovirt *ov;

	ov = mmap(NULL, OVIRT_SIZE + OVIRT_HEADER_SIZE, PROT_READ|PROT_WRITE,
			MAP_PRIVATE|MAP_ANONYMOUS, -1, 0);
	if (ov == MAP_FAILED) {
		fprintf(stderr, "Out of Memory!\n");
		return NULL;
	}
	ov->max_dnlen = OVIRT_SIZE - sizeof(struct ovirt);
	ov->max_hdlen = OVIRT_HEADER_SIZE;
	ov->hdbuf = ((void *)ov) + OVIRT_SIZE;
	strcpy(ov->engine, "https://");
	strcat(ov->engine, ohost);
	curl_global_init(CURL_GLOBAL_DEFAULT);
	ov->curl = curl_easy_init();
	if (!ov->curl) {
		fprintf(stderr, "Out of Memory!\n");
		curl_global_cleanup();
		munmap(ov, OVIRT_SIZE + OVIRT_HEADER_SIZE);
		return NULL;
	}
	curl_easy_setopt(ov->curl, CURLOPT_VERBOSE, verbose);
	curl_easy_setopt(ov->curl, CURLOPT_FOLLOWLOCATION, 1);
	curl_easy_setopt(ov->curl, CURLOPT_READFUNCTION, upload);
	curl_easy_setopt(ov->curl, CURLOPT_READDATA, ov);
	curl_easy_setopt(ov->curl, CURLOPT_WRITEFUNCTION, dnload);
	curl_easy_setopt(ov->curl, CURLOPT_WRITEDATA, ov);
	curl_easy_setopt(ov->curl, CURLOPT_HEADERFUNCTION, hdrecv);
	curl_easy_setopt(ov->curl, CURLOPT_HEADERDATA, ov);
	curl_easy_setopt(ov->curl, CURLOPT_ERRORBUFFER, ov->errmsg);
	curl_easy_setopt(ov->curl, CURLOPT_USERAGENT, "Lenovo oVirt Agent 1.0");

	ov->ocmd = INIT;
	ov->version = 0;

	return ov;
}

void ovirt_exit(struct ovirt *ov)
{
	curl_easy_cleanup(ov->curl);
	curl_global_cleanup();
	munmap(ov, OVIRT_SIZE + OVIRT_HEADER_SIZE);
}

static const char ovirt_api[] = "/ovirt-engine/api";
static const char hd_auth[] = "Authorization: Basic ";
static const char hd_accept_xml[] = "Accept: application/xml";
int ovirt_logon(struct ovirt *ov, const char *user, const char *pass,
		const char *domain)
{
	struct curl_slist *header = NULL;
	int retv, len, rlen;
	static const char pasfmt[] = "%s@%s:%s";
	char passkey[96], *uri;
	const char *dm;
	base64_encodestate b64;

	retv = 0;
	if (ov->version < 4) {
		if (domain == NULL || strlen(domain) == 0)
			dm = "internal";
		else
			dm = domain;
		retv = snprintf(passkey, 96, pasfmt, user, dm, pass);
		if (retv >= 95)
			fprintf(stderr, "Warning: ID token too long.\n");
		base64_init_encodestate(&b64);
		len = base64_encode_block(passkey, strlen(passkey), ov->dndat, &b64);
		rlen = base64_encode_blockend(ov->dndat + len, &b64);
		len += rlen;
		if (ov->dndat[len-1] == '\n')
			ov->dndat[len-1] = 0;
		else
			ov->dndat[len] = 0;
		strcpy(ov->token, hd_auth);
		strcat(ov->token, ov->dndat);
		header = curl_slist_append(header, ov->token);
		header = curl_slist_append(header, hd_accept_xml);
		if (ov->version == 0) {
			uri = passkey;
			strcpy(uri, ov->engine);
			strcat(uri, ovirt_api);
			curl_easy_setopt(ov->curl, CURLOPT_URL, uri);
			curl_easy_setopt(ov->curl, CURLOPT_HTTPHEADER, header);
			ov->hdlen = 0;
			ov->dnlen = 0;
			ov->errmsg[0] = 0;
			retv = curl_easy_perform(ov->curl);
		}
	}

/*	if (ov->ocmd == INIT) {
		strcpy(url, ov->engine);
		strcat(url, "/ovirt-engine/api");
		curl_easy_setopt(ov->curl, CURLOPT_URL, url);
		header = curl_slist_append(header, "Accept: application/xml");
		curl_easy_setopt(ov->curl, CURLOPT_HTTPHEADER, header);
		retv = curl_easy_perform(ov->curl);
		fprintf(stderr, "CURL Return Code: %d\n", retv);
		ov->dndat[ov->dnlen] = 0;
		*(ov->hdbuf+ov->hdlen) = 0;
		curl_slist_free_all(header); */
	return retv;
}
