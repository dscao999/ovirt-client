#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <sys/mman.h>
#include <jansson.h>
#include <libxml/parser.h>
#include <libxml/tree.h>
#include <assert.h>
#include "base64.h"
#include "ovirt_xml.h"
#include "ovirt-client.h"

#define ENOMEM	0x2000

static const unsigned short err_base = 0x1000;
static const unsigned short err_unauth = 0x100;
static const unsigned short err_other = 0x199;

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

static int get_json_token(char *buf, int buflen, const char *jtxt)
{
	json_error_t jerr;
	int retv = 0;
	json_t *root, *token;
	const char *token_str;

	root = json_loads(jtxt, 0, &jerr);
	if (!root) {
		fprintf(stderr, "OAUTH Response Invalid: %s\n", jerr.text);
		return -1;
	}
	token = json_object_get(root, "access_token");
	if (!json_is_string(token)) {
		fprintf(stderr, "OAUTH Response missing \"access_token\".\n");
		retv = -2;
		goto exit_10;
	}
	token_str = json_string_value(token);
	if (strlen(token_str) > buflen - 24) {
		fprintf(stderr, "Buffer overflow in get_json_token.\n");
		retv = -3;
		goto exit_10;
	}
	strcpy(buf, "Authorization: Bearer ");
	strcat(buf, token_str);

exit_10:
	json_decref(root);
	return retv;
}

static int http_check_status(const char *response, const char *msgbody)
{
	static const char HTTP_OK[] = "HTTP/1.1 200 OK";
	static const char HTTP_UNAUTH[] = "HTTP/1.1 401 Unauthorized";

	int retv = 0;

	if (strstr(response, HTTP_OK) == response)
		return retv;
	if (strstr(response, HTTP_UNAUTH) == response) {
		fprintf(stderr, "Unauthorized access.\n");
		retv = -(err_base + err_unauth);
	} else
		retv = -(err_base + err_other);
	fprintf(stderr, "%s\n%s\n", response, msgbody);
	return retv;
}

static int ovirt_oauth_logon(struct ovirt *ov, const char *user,
		const char *pass, const char *domain)
{
	static const char sso_path[] = "/ovirt-engine/sso/oauth/token";
	static const char sso_param[] = "grant_type=password&" \
			"scope=ovirt-app-api&username=%s@%s&password=%s";
	static const char achd_json[] = "Accept: application/json";
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
	postdata = malloc(strlen(ov->updat+1));
	strcpy(postdata, ov->updat);
	header = curl_slist_append(header, achd_json);
	curl_easy_setopt(ov->curl, CURLOPT_HTTPHEADER, header);
	curl_easy_setopt(ov->curl, CURLOPT_POSTFIELDSIZE, strlen(postdata));
	curl_easy_setopt(ov->curl, CURLOPT_POSTFIELDS, postdata); 
	ov->dnlen = 0;
	ov->errmsg[0] = 0;
	retv = curl_easy_perform(ov->curl);
	curl_easy_setopt(ov->curl, CURLOPT_POST, 0);
	curl_easy_setopt(ov->curl, CURLOPT_HTTPHEADER, NULL);
	curl_slist_free_all(header);
	free(postdata);
	ov->dndat[ov->dnlen] = 0;
	ov->hdbuf[ov->hdlen] = 0;
	retv = http_check_status(ov->hdbuf, ov->dndat);
	if (retv != 0) {
		fprintf(stderr, "OAUTH logon operation failed.\n");
		fprintf(stderr, "%s\n", ov->dndat);
		return retv;
	}
	retv = get_json_token(ov->token, sizeof(ov->token), ov->dndat);
	if (retv >= 0)
		ov->auth = AUTH_OAUTH;
	return retv;
}

static const char ovirt_api[] = "/ovirt-engine/api";
static const char hd_basic_auth[] = "Authorization: Basic ";
static const char hd_accept_xml[] = "Accept: application/xml";

static int ovirt_basic_logon(struct ovirt *ov, const char *user,
		const char *pass, const char *domain)
{
	struct curl_slist *header = NULL;
	static const char pasfmt[] = "%s@%s:%s";
	char passkey[96], *uri;
	const char *dm;
	int len, retv;

	if (domain == NULL || strlen(domain) == 0)
		dm = "internal";
	else
		dm = domain;
	len = snprintf(passkey, 96, pasfmt, user, dm, pass);
	if (len >= 95)
		fprintf(stderr, "Warning: ID token too long.\n");
	len = bin2str_b64(ov->dndat, ov->max_dnlen,
			(const unsigned char *)passkey, len);
	strcpy(ov->token, hd_basic_auth);
	strcat(ov->token, ov->dndat);
	header = curl_slist_append(header, ov->token);
	uri = passkey;
	strcpy(uri, ov->engine);
	strcat(uri, ovirt_api);
	curl_easy_setopt(ov->curl, CURLOPT_URL, uri);
	curl_easy_setopt(ov->curl, CURLOPT_HTTPHEADER, header);
	curl_easy_setopt(ov->curl, CURLOPT_NOBODY, 1); 
	ov->hdlen = 0;
	ov->dnlen = 0;
	ov->errmsg[0] = 0;
	retv = curl_easy_perform(ov->curl);
	curl_slist_free_all(header);
	ov->hdbuf[ov->hdlen] = 0;
	ov->dndat[ov->dnlen] = 0;
	curl_easy_setopt(ov->curl, CURLOPT_NOBODY, 0); 
	curl_easy_setopt(ov->curl, CURLOPT_HTTPHEADER, NULL);
	retv = http_check_status(ov->hdbuf, ov->dndat);
	if (retv != 0) {
		fprintf(stderr, "oVirt basic logon operation failed.\n");
		return retv;
	}
	ov->auth = AUTH_BASIC;
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

	ov->auth = AUTH_NONE;
	ov->version = 0;

	return ov;
}

void ovirt_exit(struct ovirt *ov)
{
	curl_easy_cleanup(ov->curl);
	curl_global_cleanup();
	munmap(ov, OVIRT_SIZE + OVIRT_HEADER_SIZE);
}

static int ovirt_session_cookie(char *buf, int buflen, const char *hdbuf)
{
	const char *json_id, *semi = NULL;
	int len;

	json_id = strstr(hdbuf, "JSESSIONID=");
	if (json_id)
		semi = strchr(json_id, ';');
	if (!json_id || !semi) {
		fprintf(stderr, "Invalid response from session logon.\n");
		return 0;
	}
	len = semi - json_id;
	strcpy(buf, "Cookie: ");
	if (len + 8 < buflen) {
		strncat(buf+8, json_id, len);
		buf[len+8] = 0;
	} else
		fprintf(stderr, "Session Token ID too large.\n");
	return len + 8;
}

static const char hd_prefer[] = "Prefer: persistent-auth";

static int ovirt_session_logon(struct ovirt *ov)
{
	char uri[128];
	struct curl_slist *header = NULL;
	int len, retv = 0;

	strcpy(uri, ov->engine);
	strcat(uri, ovirt_api);
	curl_easy_setopt(ov->curl, CURLOPT_URL, uri);
	header = curl_slist_append(header, ov->token);
	header = curl_slist_append(header, hd_prefer);
	curl_easy_setopt(ov->curl, CURLOPT_NOBODY, 1);
	curl_easy_setopt(ov->curl, CURLOPT_HTTPHEADER, header);
	ov->hdlen = 0;
	ov->errmsg[0] = 0;
	curl_easy_perform(ov->curl);
	ov->hdbuf[ov->hdlen] = 0;
	curl_easy_setopt(ov->curl, CURLOPT_NOBODY, 0);
	curl_slist_free_all(header);
	curl_easy_setopt(ov->curl, CURLOPT_HTTPHEADER, NULL);
	retv = http_check_status(ov->hdbuf, ov->dndat);
	if (retv != 0) {
		fprintf(stderr, "Session logon failed.\n");
		return retv;
	}
	len = ovirt_session_cookie(ov->token, sizeof(ov->token), ov->hdbuf);
	if (len > 0 && len < sizeof(ov->token))
		ov->auth = AUTH_SESSION;
	else
		retv = -(err_base + 0x105);
	return retv;
}

int ovirt_logon(struct ovirt *ov, const char *user, const char *pass,
		const char *domain)
{
	int retv = 0, passed = 0;

	ov->auth = 0;
	if (ov->version >= 4 || ov->version == 0) {
		retv = ovirt_oauth_logon(ov, user, pass, domain);
		if (retv == CURLE_OK)
			passed = 1;
		else if (ov->version != 0) {
			fprintf(stderr, "oVirt Logon failed.\n");
			return retv;
		}
	}
	if (passed == 0)
		retv = ovirt_basic_logon(ov, user, pass, domain);
	if (retv != CURLE_OK) {
		fprintf(stderr, "oVirt Logon failed.\n");
		return retv;
	}
	retv = ovirt_session_logon(ov);
	return retv;
}
	
int ovirt_init_version(struct ovirt *ov)
{
	struct ovirt_xml *oxml;
	struct curl_slist *header = NULL;
	char url[128];
	int retv = -1, len;

	strcpy(url, ov->engine);
	strcat(url, ovirt_api);
	curl_easy_setopt(ov->curl, CURLOPT_URL, url);
	header = curl_slist_append(header, ov->token);
	header = curl_slist_append(header, hd_accept_xml);
	header = curl_slist_append(header, hd_prefer);
	curl_easy_setopt(ov->curl, CURLOPT_HTTPHEADER, header);
	ov->dnlen = 0;
	ov->hdlen = 0;
	ov->errmsg[0] = 0;
	curl_easy_perform(ov->curl);
	ov->dndat[ov->dnlen] = 0;
	ov->hdbuf[ov->hdlen] = 0;
	curl_easy_setopt(ov->curl, CURLOPT_HTTPHEADER, NULL);
	retv = http_check_status(ov->hdbuf, ov->dndat);
	if (retv != 0) {
		fprintf(stderr, "Failed to logon session.\n");
		return retv;
	}
	oxml = ovirt_xml_init(ov->dndat, ov->dnlen);
	if (oxml) {
		len = xmlget_value(oxml, "/api/product_info/version/major",
				ov->dndat, ov->max_dnlen);
		ovirt_xml_exit(oxml);
		if (len > 0 && len < ov->max_dnlen) {
			retv = 0;
			ov->version = atoi(ov->dndat);
		}
	}
	return retv;
}

static int xml_getvms(const char *xmlstr, int len, char ***vmids)
{
	struct ovirt_xml *oxml;
	xmlNode *node;
	xmlAttr	*prop;
	int numvms = 0, i, retv;
	char **ids, **cur_id;
	static const char xpath[] = "/vms/vm";

	retv = 0;
	*vmids = NULL;
	oxml = ovirt_xml_init(xmlstr, len);
	if (!oxml)
		return 0;
	node = xml_search_element(oxml, xpath);
	while (node) {
		numvms += 1;
		node = xml_next_element(node);
	}
	ids = malloc(sizeof(char *)*(numvms+1));
	if (!ids) {
		fprintf(stderr, "Out of Memory.\n");
		retv = -ENOMEM;
		goto exit_10;
	}
	memset(ids, 0, sizeof(char *)*(numvms+1));

	node = xml_search_element(oxml, xpath);
	for (cur_id = ids, i = 0; i < numvms && node; i++, cur_id++) {
		prop = node->properties;
		assert(prop->type == XML_ATTRIBUTE_NODE);
		while (prop) {
			if (prop->name)
				if (strcmp((const char *)prop->name, "href") == 0)
					break;
			prop = prop->next;
		}
		if (!prop) {
			fprintf(stderr, "Bad xml, no properties: %s\n", xpath);
			retv = -(err_base + 0x201);
			goto exit_10;
		}
		len = strlen((const char *)prop->children->content);
		*cur_id = malloc(len+1);
		if (!(*cur_id)) {
			fprintf(stderr, "Out of memory.\n");
			retv = -ENOMEM;
			goto exit_10;
		}
		strcpy(*cur_id, (const char *)prop->children->content);
		node = xml_next_element(node);
	}
	retv = numvms;
	*vmids = ids;

exit_10:
	if (retv < 0 && ids)
		ovirt_free_list(ids);
	ovirt_xml_exit(oxml);
	return retv;
}

static const char ovirt_vms[] = "/ovirt-engine/api/vms";

int ovirt_list_vms(struct ovirt *ov, char ***vmids)
{
	struct curl_slist *header = NULL;
	char url[128];
	int retv, numvms;

	*vmids = NULL;
	header = curl_slist_append(header, ov->token);
	header = curl_slist_append(header, hd_accept_xml);
	header = curl_slist_append(header, hd_prefer);
	strcpy(url, ov->engine);
	strcat(url, ovirt_vms);
	curl_easy_setopt(ov->curl, CURLOPT_URL, url);
	curl_easy_setopt(ov->curl, CURLOPT_HTTPHEADER, header);
	ov->hdlen = 0;
	ov->dnlen = 0;
	ov->errmsg[0] = 0;
	curl_easy_perform(ov->curl);
	ov->dndat[ov->dnlen] = 0;
	ov->hdbuf[ov->hdlen] = 0;
	curl_easy_setopt(ov->curl, CURLOPT_HTTPHEADER, NULL);
	retv = http_check_status(ov->hdbuf, ov->dndat);
	if (retv != 0)
		return retv;
	numvms = xml_getvms(ov->dndat, ov->dnlen, vmids);
	return numvms;
}
