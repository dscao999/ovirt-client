#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <sys/mman.h>
#include <libxml/parser.h>
#include <libxml/tree.h>
#include "base64.h"
#include "ovirt_xml.h"
#include "ovirt-client.h"

enum OVIRTCMD {
	INIT = 0, INIT_DONE = 1, LOGON_SSO = 2, LOGON_SESSON = 3, GETVMS = 4,
	GETCON = 5, GETVV = 6
};

#define OVIRT_SIZE (4*1024*1024)
#define OVIRT_HEADER_SIZE	(1024*1024)

static const char HTTP_OK[] = "HTTP/1.1 200 OK";

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
//	curl_easy_setopt(ov->curl, CURLOPT_VERBOSE, verbose);
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
static const char hd_basic_auth[] = "Authorization: Basic ";
static const char hd_accept_xml[] = "Accept: application/xml";
int ovirt_logon(struct ovirt *ov, const char *user, const char *pass,
		const char *domain)
{
	struct curl_slist *header = NULL;
	int retv, len;
	static const char pasfmt[] = "%s@%s:%s";
	char passkey[96], *uri;
	const char *dm;
	struct ovirt_xml *oxml;

	retv = 0;
	if (domain == NULL || strlen(domain) == 0)
		dm = "internal";
	else
		dm = domain;
	header = curl_slist_append(header, hd_accept_xml);
	if (ov->version < 4 || ov->ocmd == INIT) {
		len = snprintf(passkey, 96, pasfmt, user, dm, pass);
		if (retv >= 95)
			fprintf(stderr, "Warning: ID token too long.\n");
		len = bin2str_b64(ov->dndat, ov->max_dnlen,
				(const unsigned char *)passkey, len);
		strcpy(ov->token, hd_basic_auth);
		strcat(ov->token, ov->dndat);
		header = curl_slist_append(header, ov->token);
	}
	if (ov->ocmd == INIT) {
		uri = passkey;
		strcpy(uri, ov->engine);
		strcat(uri, ovirt_api);
		curl_easy_setopt(ov->curl, CURLOPT_URL, uri);
		curl_easy_setopt(ov->curl, CURLOPT_HTTPHEADER, header);
		ov->hdlen = 0;
		ov->dnlen = 0;
		ov->errmsg[0] = 0;
		retv = curl_easy_perform(ov->curl);
		if (strstr(ov->hdbuf, HTTP_OK) != ov->hdbuf)
			fprintf(stderr, "HTTP Error:\n%s\n", ov->hdbuf);
		else {
			oxml = ovirt_xml_init(ov->dndat, ov->dnlen);
			if (oxml) {
				len = ovirt_xml_get(oxml, "/api/product_info/version/major",
						ov->dndat, ov->dnlen);
				printf("Version: %s\n", ov->dndat);
				ov->ocmd = INIT_DONE;
			}
			ovirt_xml_exit(oxml);
		}
	}
	return retv;
}
