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
#include "ovirt-client.h"

static const unsigned short err_base = 0x1000;
static const unsigned short err_file = 0x10;
static const unsigned short err_download = 0x11;
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
	json_object *json, *jval;
	int retv = 0;
	struct json_object_iterator iter, iend;
	const char *key, *val;

	iter = json_object_iter_init_default();
	iend = json_object_iter_init_default();
	json = json_tokener_parse(jtxt);
	if (!json) {
		fprintf(stderr, "OAUTH Response is not valid: %s\n", jtxt);
		return -(err_base + err_auth_invalid);
	}
	iter = json_object_iter_begin(json);
	iend = json_object_iter_end(json);
	if (json_object_iter_equal(&iter, &iend))
		goto exit_10;
	do {
		key = json_object_iter_peek_name(&iter);
		if (key && strcmp(key, "access_token") == 0)
			break;
		json_object_iter_next(&iter);
	} while (!json_object_iter_equal(&iter, &iend));
	if (json_object_iter_equal(&iter, &iend)) {
		fprintf(stderr, "OAUTH Response has no token: %s\n", jtxt);
		retv = -(err_base + err_no_auth);
		goto exit_10;
	}
	jval = json_object_iter_peek_value(&iter);
	if (!json_object_is_type(jval, json_type_string)) {
		fprintf(stderr, "OAUTH Response is not valid: %s\n", jtxt);
		retv = -(err_base + err_auth_invalid);
		goto exit_10;
	}
	val = json_object_get_string(jval);
	if (strlen(val) + 22 >= buflen) {
		fprintf(stderr, "access token too long, overflow.\n");
		retv = -(err_base + err_overflow);
		goto exit_10;
	}
	strcpy(buf, "Authorization: Bearer ");
	strcat(buf, val);
	retv = strlen(buf);
exit_10:
	json_object_put(json);
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
	struct curl_slist *header = NULL;
	int retv, len;
	static const char sso_path[] = "/ovirt-engine/sso/oauth/token";
	static const char sso_param[] = "grant_type=password&" \
			"scope=ovirt-app-api&username=%s@%s&password=%s";
	static const char hd_accept_json[] = "Accept: application/json";

	strcpy(ov->uri, ov->engine);
	strcat(ov->uri, sso_path);
	curl_easy_setopt(ov->curl, CURLOPT_URL, ov->uri);
	ov->uplen = snprintf(ov->updat, sizeof(ov->updat), sso_param, user,
			domain, pass);
	assert(ov->uplen < sizeof(ov->updat) - 1);
	header = curl_slist_append(header, hd_accept_json);
	curl_easy_setopt(ov->curl, CURLOPT_HTTPHEADER, header);
	curl_easy_setopt(ov->curl, CURLOPT_POSTFIELDSIZE, ov->uplen);
	curl_easy_setopt(ov->curl, CURLOPT_POSTFIELDS, ov->updat);
	ov->hdlen = 0;
	ov->dnlen = 0;
	ov->errmsg[0] = 0;
	retv = curl_easy_perform(ov->curl);
	curl_easy_setopt(ov->curl, CURLOPT_POST, 0);
	curl_easy_setopt(ov->curl, CURLOPT_HTTPHEADER, NULL);
	curl_slist_free_all(header);
	ov->dndat[ov->dnlen] = 0;
	ov->hdbuf[ov->hdlen] = 0;
	retv = http_check_status(ov->hdbuf, ov->dndat);
	if (retv != 0) {
		fprintf(stderr, "OAUTH logon operation failed.\n");
		return retv;
	}
	len = get_json_token(ov->token, sizeof(ov->token), ov->dndat);
	if (len < 0)
		return len;
	ov->auth = AUTH_OAUTH;
	return retv;
}

static const char ovirt_api[] = "/ovirt-engine/api";
static const char hd_accept_xml[] = "Accept: application/xml";

static int ovirt_basic_logon(struct ovirt *ov, const char *user,
		const char *pass, const char *domain)
{
	struct curl_slist *header = NULL;
	static const char pasfmt[] = "%s@%s:%s";
	int len, retv;
	static const char hd_basic_auth[] = "Authorization: Basic ";

	len = sprintf(ov->updat, pasfmt, user, domain, pass);
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

struct ovirt * ovirt_init(const char *ohost)
{
	struct ovirt *ov;

	ov = mmap(NULL, OVIRT_SIZE + OVIRT_HEADER_SIZE, PROT_READ|PROT_WRITE,
			MAP_PRIVATE|MAP_ANONYMOUS, -1, 0);
	if (ov == MAP_FAILED) {
		fprintf(stderr, "Out of Memory!\n");
		return NULL;
	}
	ov->buflen = OVIRT_SIZE + OVIRT_HEADER_SIZE;
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
	curl_easy_setopt(ov->curl, CURLOPT_VERBOSE, 0);
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
	munmap(ov, ov->buflen);
}

static int ovirt_session_cookie(char *buf, int buflen, const char *hdbuf)
{
	const char *json_id, *semi = NULL;
	int len, retv = 0;

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
	} else {
		fprintf(stderr, "Session Token ID too large.\n");
		retv = -(err_base + err_overflow);
	}
	return retv;
}

static const char hd_prefer[] = "Prefer: persistent-auth";
static const char hd_content_xml[] = "Content-Type: application/xml";

static int ovirt_session_logon(struct ovirt *ov, int start)
{
	struct curl_slist *header = NULL;
	int len, retv = 0;

	strcpy(ov->uri, ov->engine);
	strcat(ov->uri, ovirt_api);
	curl_easy_setopt(ov->curl, CURLOPT_URL, ov->uri);
	header = curl_slist_append(header, ov->token);
	if (start)
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
	if (start) {
		len = ovirt_session_cookie(ov->token, sizeof(ov->token),
				ov->hdbuf);
		if (len < 0)
			retv = len;
		else
			ov->auth = AUTH_SESSION;
	}
	return retv;
}

int ovirt_logon(struct ovirt *ov, const char *user, const char *pass,
		const char *domain)
{
	static const char defdm[] = "internal";
	int retv = 0, passed = 0;

	if (!user || !pass) {
		fprintf(stderr, "Username/Password NULL, invalid.\n");
		return -(err_base + err_auth_invalid);
	}
	if (!domain)
		domain = defdm;

	if (strlen(user) + 1 > sizeof(ov->username) ||
			strlen(pass) + 1 > sizeof(ov->pass) ||
			strlen(domain) + 1 > sizeof(ov->domain)) {
		fprintf(stderr, "username/password/domain overflow.\n");
		return -(err_base + err_overflow);
	}
	strcpy(ov->username, user);
	strcpy(ov->domain, domain);
	strcpy(ov->pass, pass);

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
	retv = ovirt_session_logon(ov, 1);
	return retv;
}

void ovirt_logout(struct ovirt *ov)
{
	int retv;

	if (ov->version >= 4)
		retv = ovirt_oauth_logon(ov, ov->username, ov->pass,
				ov->domain);
	else
		retv = ovirt_basic_logon(ov, ov->username, ov->pass,
				ov->domain);
	if (retv < 0) {
		fprintf(stderr, "user credentials become invalid.\n");
		return;
	}
	if (ovirt_session_logon(ov, 0) < 0)
		fprintf(stderr, "Internal Error: " \
				"Cannot invalidate session cookie.\n");
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
	header = curl_slist_append(header, hd_prefer);
	header = curl_slist_append(header, hd_accept_xml);
	curl_easy_setopt(ov->curl, CURLOPT_HTTPHEADER, header);
	ov->dnlen = 0;
	ov->hdlen = 0;
	ov->errmsg[0] = 0;
	curl_easy_perform(ov->curl);
	ov->dndat[ov->dnlen] = 0;
	ov->hdbuf[ov->hdlen] = 0;
	curl_easy_setopt(ov->curl, CURLOPT_HTTPHEADER, NULL);
	curl_slist_free_all(header);
	retv = http_check_status(ov->hdbuf, ov->dndat);
	if (retv != 0) {
		fprintf(stderr, "Cannot fetch the oVirt version.\n");
		return retv;
	}
	oxml = ovirt_xml_init(ov->dndat, ov->dnlen);
	if (oxml) {
		len = xmlget_value(oxml, "/api/product_info/version/major",
				ov->dndat, ov->max_dnlen);
		ovirt_xml_exit(oxml);
		if (len > 0 && len < ov->max_dnlen) {
			ov->version = atoi(ov->dndat);
			retv = ov->version;
		}
	}
	return retv;
}

static int get_node_attribute(xmlNode *node, const char *attr_id,
		char *buf, int maxlen)
{
	const char *val;
	xmlAttr *prop;
	int len;

	len = 0;
	prop = node->properties;
	while (prop) {
		assert(prop->type == XML_ATTRIBUTE_NODE && prop->name);
		val = (const char *)prop->children->content;
		if (strcmp((const char *)prop->name, attr_id) == 0) {
			len = strlen(val);
			if (len < maxlen)
				strcpy(buf, val);
			break;
		}
		prop = prop->next;
	}
	return len;
}

static int xml_getvms(const char *xmlstr, int len, struct list_head *vmhead)
{
	struct ovirt_xml *oxml;
	xmlNode *node;
	int numvms;
	struct list_head *cur, *tmp;
	struct ovirt_vm *curvm;
	static const char xpath[] = "/vms/vm";
	char id[64];

	oxml = ovirt_xml_init(xmlstr, len);
	if (!oxml)
		return 0;
	node = xml_search_element(oxml, xpath);
	numvms = 0;
	while (node) {
		numvms += 1;
		len = get_node_attribute(node, "id", id, sizeof(id));
		assert(len < sizeof(curvm->id));
		list_for_each(cur, vmhead) {
			curvm = list_entry(cur, struct ovirt_vm, lst);
			if (strcmp(curvm->id, id) == 0) {
				curvm->hit = 1;
				break;
			}
		}
		if (cur == vmhead) {
			curvm = malloc(sizeof(struct ovirt_vm));
			INIT_LIST_HEAD(&curvm->lst);
			curvm->state[0] = 0;
			len = get_node_attribute(node, "href",
					curvm->href, sizeof(curvm->href));
			assert(len < sizeof(curvm->href));
			strcpy(curvm->id, id);
			list_add(&curvm->lst, vmhead);
			curvm->con = 0;
			curvm->hit = 1;
		}
		node = xml_next_element(node);
	}
	list_for_each_safe(cur, tmp, vmhead) {
		curvm = list_entry(cur, struct ovirt_vm, lst);
		if (curvm->hit == 0) {
			list_del(&curvm->lst, vmhead);
			free(curvm);
		} else
			curvm->hit = 0;
	}
	return numvms;
}

static const char ovirt_vms[] = "/ovirt-engine/api/vms";

int ovirt_list_vms(struct ovirt *ov, struct list_head *vmhead)
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
	curl_slist_free_all(header);
	retv = http_check_status(ov->hdbuf, ov->dndat);
	if (retv != 0) {
		fprintf(stderr, "Cannot list VMs.\n");
		return retv;
	}
	numvms = xml_getvms(ov->dndat, ov->dnlen, vmhead);
	return numvms;
}

static int match_vm_status(const char *st)
{
	static const char *vm_states[] = {
		"wait_for_launch", "down", "suspended", "powering_down",
		"reboot_in_progress", "saving_state", "powering_up",
		"restoring_state", "up", NULL
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

	strcpy(vm->state, "unknown");
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
	if (oxml) {
		len = xmlget_value(oxml, "/vm/status", vm->state,
				sizeof(vm->state));
		assert(len < sizeof(vm->state));
		vm->state[len] = 0;
		ovirt_xml_exit(oxml);
	}
	return match_vm_status(vm->state);
}

static const char action_empty[] = "<action/>";
static const int action_empty_len = 9;

int ovirt_vm_action(struct ovirt *ov, struct ovirt_vm *vm, const char *action)
{
	struct curl_slist *header = NULL;
	int retv;

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

static int xml_get_conlink(const char *xmlbuf, int len,
		char *conlink, int maxlen)
{
	struct ovirt_xml *oxml;
	int conlen;
	xmlNode *node, *proto;

	conlen = 0;
	oxml = ovirt_xml_init(xmlbuf, len);
	if (!oxml)
		return conlen;
	node = xml_search_element(oxml, "/graphics_consoles/graphics_console");
	if (!node) {
		fprintf(stderr, "No graphics console information.\n");
		goto exit_10;
	}

	do {
		proto = xml_search_siblings(node->children, "protocol");
		if (strcmp((const char *)proto->children->content, "spice") == 0)
			break;
		node = xml_next_element(node);
	} while (node);
	if (!node) {
		fprintf(stderr, "No spice graphics console information.\n");
		goto exit_10;
	}
	conlen = get_node_attribute(node, "href", conlink, maxlen);
	assert(conlen < maxlen);

exit_10:
	ovirt_xml_exit(oxml);
	return conlen;
}

int ovirt_download(struct ovirt *ov, const char *link)
{
	struct curl_slist *header = NULL;
	int retv, len;
	struct ovirt_xml *oxml;

	strcpy(ov->uri, ov->engine);
	strcat(ov->uri, link);
	header = curl_slist_append(header, hd_prefer);
	header = curl_slist_append(header, ov->token);
	header = curl_slist_append(header, hd_content_xml);
	header = curl_slist_append(header, hd_accept_xml);
	curl_easy_setopt(ov->curl, CURLOPT_URL, ov->uri);
	curl_easy_setopt(ov->curl, CURLOPT_HTTPHEADER, header);
	curl_easy_setopt(ov->curl, CURLOPT_POSTFIELDSIZE, action_empty_len);
	curl_easy_setopt(ov->curl, CURLOPT_POSTFIELDS, action_empty);
	ov->hdlen = 0;
	ov->dnlen = 0;
	ov->errmsg[0] = 0;
	curl_easy_perform(ov->curl);
	curl_easy_setopt(ov->curl, CURLOPT_HTTPHEADER, NULL);
	curl_easy_setopt(ov->curl, CURLOPT_POST, 0);
	ov->hdbuf[ov->hdlen] = 0;
	ov->dndat[ov->dnlen] = 0;
	curl_slist_free_all(header);
	retv = http_check_status(ov->hdbuf, ov->dndat);
	if (retv < 0)
		return retv;
	oxml = ovirt_xml_init(ov->dndat, ov->dnlen);
	if (!oxml) {
		fprintf(stderr, "Download corrrupt.\n%s\n", ov->dndat);
		return -(err_base + err_download);
	}
	len = xmlget_value(oxml, "/action/remote_viewer_connection_file",
			ov->dndat, ov->max_dnlen);
	return len;
}

int ovirt_get_vmconsole(struct ovirt *ov, struct ovirt_vm *vm, const char *vv)
{
	FILE *fout;
	struct curl_slist *header = NULL;
	int retv, len, num;
	char conlink[256];

	fout = fopen(vv, "wb");
	if (!fout) {
		fprintf(stderr, "Cannot open file %s: %s\n", vv,
				strerror(errno));
		return -(err_base + err_file);
	}
	strcpy(ov->uri, ov->engine);
	strcat(ov->uri, vm->href);
	strcat(ov->uri, "/graphicsconsoles");
	header = curl_slist_append(header, hd_prefer);
	header = curl_slist_append(header, ov->token);
	header = curl_slist_append(header, hd_content_xml);
	header = curl_slist_append(header, hd_accept_xml);
	curl_easy_setopt(ov->curl, CURLOPT_URL, ov->uri);
	curl_easy_setopt(ov->curl, CURLOPT_HTTPHEADER, header);
	ov->hdlen = 0;
	ov->dnlen = 0;
	ov->errmsg[0] = 0;
	curl_easy_perform(ov->curl);
	curl_easy_setopt(ov->curl,CURLOPT_HTTPHEADER, NULL);
	ov->hdbuf[ov->hdlen] = 0;
	ov->dndat[ov->dnlen] = 0;
	curl_slist_free_all(header);
	retv = http_check_status(ov->hdbuf, ov->dndat);
	if (retv < 0)
		goto exit_10;
	len = xml_get_conlink(ov->dndat, ov->dnlen, conlink, sizeof(conlink));
	assert(len < sizeof(conlink));
	if (len <= 0)
		goto exit_10;
	strcat(conlink, "/remoteviewerconnectionfile");
	len = ovirt_download(ov, conlink);
	if (len > 0) {
		num = fwrite(ov->dndat, 1, len, fout);
		if (num < len)
			fprintf(stderr, "File write not complete: %s\n",
					strerror(errno));
	}
	retv = len;

exit_10:
	fclose(fout);
	return retv;
}
