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
static const unsigned short err_overflow = 0x105;
static const unsigned short err_auth_invalid = 0x106;
static const unsigned short err_no_auth = 0x107;
static const unsigned short err_no_jsonid = 0x108;

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
		fprintf(stderr, "OAUTH Response is not valid: %s\n", jerr.text);
		return -(err_base + err_auth_invalid);
	}
	token = json_object_get(root, "access_token");
	if (!json_is_string(token)) {
		fprintf(stderr, "OAUTH Response missing \"access_token\".\n");
		retv = -(err_base + err_no_auth);
		goto exit_10;
	}
	token_str = json_string_value(token);
	if (strlen(token_str) > buflen - 22) {
		fprintf(stderr, "Buffer overflow in get_json_token.\n");
		retv = -(err_base + err_overflow);
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
	static const char hd_accept_json[] = "Accept: application/json";
	const char *dom;
	char *postdata;
	struct curl_slist *header = NULL;
	int retv;

	strcpy(ov->uri, ov->engine);
	strcat(ov->uri, sso_path);
	curl_easy_setopt(ov->curl, CURLOPT_URL, ov->uri);
	if (domain == NULL || strlen(domain) == 0)
		dom = "internal";
	else
		dom = domain;
	ov->uplen = snprintf(ov->updat, sizeof(ov->updat), sso_param, user,
			dom, pass);
	assert(ov->uplen < sizeof(ov->updat) -1);
	postdata = malloc(strlen(ov->updat)+1);
	strcpy(postdata, ov->updat);
	header = curl_slist_append(header, hd_accept_json);
	curl_easy_setopt(ov->curl, CURLOPT_HTTPHEADER, header);
	curl_easy_setopt(ov->curl, CURLOPT_POSTFIELDSIZE, strlen(postdata));
	curl_easy_setopt(ov->curl, CURLOPT_POSTFIELDS, postdata); 
	ov->hdlen = 0;
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
	const char *dm;
	int len, retv;

	if (domain == NULL || strlen(domain) == 0)
		dm = "internal";
	else
		dm = domain;
	len = sprintf(ov->updat, pasfmt, user, dm, pass);
	assert(len < sizeof(ov->updat));
	len = bin2str_b64(ov->dndat, ov->max_dnlen,
			(const unsigned char *)ov->updat, len);
	ov->dndat[len] = 0;
	strcpy(ov->token, hd_basic_auth);
	strcat(ov->token, ov->dndat);
	header = curl_slist_append(header, ov->token);
	strcpy(ov->uri, ov->engine);
	strcat(ov->uri, ovirt_api);
	curl_easy_setopt(ov->curl, CURLOPT_URL, ov->uri);
	curl_easy_setopt(ov->curl, CURLOPT_HTTPHEADER, header);
	curl_easy_setopt(ov->curl, CURLOPT_NOBODY, 1); 
	ov->hdlen = 0;
	ov->dnlen = 0;
	ov->errmsg[0] = 0;
	retv = curl_easy_perform(ov->curl);
	ov->hdbuf[ov->hdlen] = 0;
	ov->dndat[ov->dnlen] = 0;
	curl_easy_setopt(ov->curl, CURLOPT_NOBODY, 0); 
	curl_easy_setopt(ov->curl, CURLOPT_HTTPHEADER, NULL);
	curl_slist_free_all(header);
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
		return -(err_base + err_no_jsonid);
	}
	len = semi - json_id;
	strcpy(buf, "Cookie: ");
	if (len + 8 < buflen) {
		strncat(buf+8, json_id, len);
		buf[len+8] = 0;
	} else
		fprintf(stderr, "Session Token ID too large.\n");
	return (len + 8);
}

static const char hd_prefer[] = "Prefer: persistent-auth";
static const char hd_content_xml[] = "Content-Type: application/xml";

static int ovirt_session_logon(struct ovirt *ov)
{
	struct curl_slist *header = NULL;
	int len, retv = 0;

	strcpy(ov->uri, ov->engine);
	strcat(ov->uri, ovirt_api);
	curl_easy_setopt(ov->curl, CURLOPT_URL, ov->uri);
	header = curl_slist_append(header, ov->token);
	header = curl_slist_append(header, hd_prefer);
	curl_easy_setopt(ov->curl, CURLOPT_NOBODY, 1);
	curl_easy_setopt(ov->curl, CURLOPT_HTTPHEADER, header);
	ov->hdlen = 0;
	ov->dnlen = 0;
	ov->errmsg[0] = 0;
	curl_easy_perform(ov->curl);
	ov->hdbuf[ov->hdlen] = 0;
	ov->dndat[ov->dnlen] = 0;
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
	int retv, len;

	strcpy(ov->uri, ov->engine);
	strcat(ov->uri, ovirt_api);
	curl_easy_setopt(ov->curl, CURLOPT_URL, ov->uri);
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
		fprintf(stderr, "session logon failed.\n");
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

static void copy_attribute(xmlAttr *prop, struct ovirt_vm *vm)
{
	while (prop) {
		assert(prop->type == XML_ATTRIBUTE_NODE && prop->name);
		if (strcmp((const char *)prop->name, "href") == 0)
			strcpy(vm->href, (const char *)prop->children->content);
		else if (strcmp((const char *)prop->name, "id") == 0)
			strcpy(vm->id, (const char *)prop->children->content);
		prop = prop->next;
	}
}

static int xml_getvms(const char *xmlstr, int len, struct ovirt_vm *vms, int num)
{
	struct ovirt_xml *oxml;
	xmlNode *node;
	xmlAttr	*prop;
	int numvms;
	struct ovirt_vm *curvm = vms;
	static const char xpath[] = "/vms/vm";

	oxml = ovirt_xml_init(xmlstr, len);
	if (!oxml)
		return 0;
	node = xml_search_element(oxml, xpath);
	numvms = 0;
	while (node) {
		prop = node->properties;
		if (curvm && numvms < num) {
			copy_attribute(prop, curvm);
			curvm++;
		}
		numvms += 1;
		node = xml_next_element(node);
	}
	return numvms;
}

static const char ovirt_vms[] = "/ovirt-engine/api/vms";

int ovirt_list_vms(struct ovirt *ov, struct ovirt_vm **vms)
{
	struct curl_slist *header = NULL;
	int retv, numvms;

	header = curl_slist_append(header, ov->token);
	header = curl_slist_append(header, hd_accept_xml);
	header = curl_slist_append(header, hd_prefer);
	strcpy(ov->uri, ov->engine);
	strcat(ov->uri, ovirt_vms);
	curl_easy_setopt(ov->curl, CURLOPT_URL, ov->uri);
	curl_easy_setopt(ov->curl, CURLOPT_HTTPHEADER, header);
	ov->hdlen = 0;
	ov->dnlen = 0;
	ov->errmsg[0] = 0;
	curl_easy_perform(ov->curl);
	ov->dndat[ov->dnlen] = 0;
	ov->hdbuf[ov->hdlen] = 0;
	curl_easy_setopt(ov->curl, CURLOPT_HTTPHEADER, NULL);
	retv = http_check_status(ov->hdbuf, ov->dndat);
	if (retv != 0) {
		fprintf(stderr, "Cannot list VMs.\n");
		return retv;
	}
	numvms = xml_getvms(ov->dndat, ov->dnlen, NULL, 0);
	*vms = malloc(numvms*sizeof(struct ovirt_vm));
	if (!(*vms)) {
		fprintf(stderr, "Out of Memory.\n");
		return -ENOMEM;
	}
	xml_getvms(ov->dndat, ov->dnlen, *vms, numvms);
	return numvms;
}

static int match_vm_status(const char *st)
{
	static const char *vm_states[] = {
		"wait_for_launch", "down", "powering_down", "powering_up",
		"up", NULL
	};
	int idx;

	idx = 0;
	while (vm_states[idx]) {
		if (strcmp(st, vm_states[idx]) == 0)
			break;
		idx += 1;
	}
	if (vm_states[idx])
		return idx;
	else
		return -1;
}

static int ovirt_vm_getstate(struct ovirt *ov, struct ovirt_vm *vm)
{
	struct curl_slist *header = NULL;
	int retv = -1, len;
	struct ovirt_xml *oxml;

	strcpy(ov->uri, ov->engine);
	strcat(ov->uri, vm->href);
	header = curl_slist_append(header, hd_prefer);
	header = curl_slist_append(header, ov->token);
	header = curl_slist_append(header, hd_accept_xml);
	ov->hdlen = 0;
	ov->dnlen = 0;
	ov->errmsg[0] = 0;
	curl_easy_setopt(ov->curl, CURLOPT_URL, ov->uri);
	curl_easy_setopt(ov->curl, CURLOPT_HTTPHEADER, header);
	curl_easy_perform(ov->curl);
	curl_easy_setopt(ov->curl, CURLOPT_HTTPHEADER, NULL);
	curl_slist_free_all(header);
	ov->hdbuf[ov->hdlen] = 0;
	ov->dndat[ov->dnlen] = 0;
	retv = http_check_status(ov->hdbuf, ov->dndat);
	if (retv < 0)
		return retv;
	oxml = ovirt_xml_init(ov->dndat, ov->dnlen);
	if (!oxml)
		return retv;
	len = xmlget_value(oxml, "/vm/status", vm->state, sizeof(vm->state));
	assert(len < sizeof(vm->state));
	vm->state[len] = 0;
	return match_vm_status(vm->state);
}


int ovirt_vm_action(struct ovirt *ov, struct ovirt_vm *vm, const char *action)
{
	struct curl_slist *header = NULL;
	int retv;
	static const char action_empty[] = "<action/>";
	static const int action_empty_len = 9;

	if (strcmp(action, "status") == 0)
		return ovirt_vm_getstate(ov, vm);

	strcpy(ov->uri, ov->engine);
	strcat(ov->uri, vm->href);
	strcat(ov->uri, "/");
	strcat(ov->uri, action);
	header = curl_slist_append(header, hd_prefer);
	header = curl_slist_append(header, ov->token);
	header = curl_slist_append(header, hd_content_xml);
	header = curl_slist_append(header, hd_accept_xml);
	ov->hdlen = 0;
	ov->dnlen = 0;
	ov->errmsg[0] = 0;
	curl_easy_setopt(ov->curl, CURLOPT_URL, ov->uri);
	curl_easy_setopt(ov->curl, CURLOPT_HTTPHEADER, header);
	curl_easy_setopt(ov->curl, CURLOPT_POSTFIELDS, action_empty);
	curl_easy_setopt(ov->curl, CURLOPT_POSTFIELDSIZE, action_empty_len);
	curl_easy_perform(ov->curl);
	curl_easy_setopt(ov->curl, CURLOPT_POST, 0);
	curl_easy_setopt(ov->curl, CURLOPT_HTTPHEADER, NULL);
	curl_slist_free_all(header);
	ov->hdbuf[ov->hdlen] = 0;
	ov->dndat[ov->dnlen] = 0;
	retv = http_check_status(ov->hdbuf, ov->dndat);
	return retv;
}
