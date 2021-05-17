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

static const unsigned short err_base = 0x1000;
static const unsigned short err_file = 0x10;
static const unsigned short err_download = 0x11;
static const unsigned short err_busy = 0x12;
static const unsigned short err_unauth = 0x100;
static const unsigned short err_overflow = 0x105;
static const unsigned short err_auth_invalid = 0x106;
static const unsigned short err_no_auth = 0x107;
static const unsigned short err_no_jsonid = 0x108;
static const unsigned short err_other = 0x199;

static const char *vm_states[] = {
	"wait_for_launch", "down", "suspended", "powering_down",
	"reboot_in_progress", "saving_state", "powering_up",
	"restoring_state", "up", "unknown"
};

#define OVIRT_SIZE (4*1024*1024)
#define OVIRT_HEADER_SIZE	(1024*1024)

int ovirt_lock(struct ovirt *ov, unsigned int tries)
{
	int retv = 1;

	if (lock_lock(&ov->lock, tries) == 0) {
		fprintf(stderr, "Cannot obtain the lock.\n");
		retv = -(err_base + err_busy);
	}
	return retv;
}

void ovirt_unlock(struct ovirt *ov)
{
	lock_unlock(&ov->lock);
}

static size_t upload(char *buf, size_t siz, size_t nitems, void *usrdat)
{
	struct ovirt *ov = (struct ovirt *)usrdat;
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
	struct ovirt *ov = (struct ovirt *)usrdat;
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
	struct ovirt *ov = (struct ovirt *)usrdat;
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

	*buf = 0;
	iter = json_object_iter_init_default();
	iend = json_object_iter_init_default();
	json = json_tokener_parse(jtxt);
	if (!json) {
		fprintf(stderr, "OAUTH Response is not valid: %s\n", jtxt);
		return -(err_base + err_auth_invalid);
	}
	iter = json_object_iter_begin(json);
	iend = json_object_iter_end(json);
	if (json_object_iter_equal(&iter, &iend)) {
		fprintf(stderr, "OAUTH Response has no token: %s\n", jtxt);
		retv = -(err_base + err_no_auth);
		goto exit_10;
	}
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
	if ((int)strlen(val) + 22 >= buflen) {
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
	assert(len < (int)sizeof(ov->updat));
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

	ov = (struct ovirt *)mmap(NULL, OVIRT_SIZE + OVIRT_HEADER_SIZE,
			PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_ANONYMOUS, -1, 0);
	if (ov == MAP_FAILED) {
		fprintf(stderr, "Out of Memory!\n");
		return NULL;
	}
	ov->buflen = OVIRT_SIZE + OVIRT_HEADER_SIZE;
	ov->max_dnlen = OVIRT_SIZE - sizeof(struct ovirt);
	ov->max_hdlen = OVIRT_HEADER_SIZE;
	ov->hdbuf = ((char *)ov) + OVIRT_SIZE;
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
	curl_easy_setopt(ov->curl, CURLOPT_USERAGENT, "Lenovo oVirt Client 1.0");

	ov->auth = AUTH_NONE;
	ov->version = 0;
	ov->lock = 0;
	INIT_LIST_HEAD(&ov->vmhead);
	INIT_LIST_HEAD(&ov->vmpool);
	ov->numvms = 0;
	ov->numpools = 0;

	return ov;
}

void ovirt_exit(struct ovirt *ov)
{
	ovirt_vmlist_free(&ov->vmhead);
	ovirt_vmpool_free(&ov->vmpool);
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
			goto exit_5;
		}
	}
	if (passed == 0)
		retv = ovirt_basic_logon(ov, user, pass, domain);
	if (retv != CURLE_OK) {
		fprintf(stderr, "oVirt Logon failed.\n");
		goto exit_5;
	}
	retv = ovirt_session_logon(ov, 1);

exit_5:
	return retv;
}

int ovirt_logout(struct ovirt *ov)
{
	int retv = 0;

	if (ov->version >= 4)
		retv = ovirt_oauth_logon(ov, ov->username, ov->pass,
				ov->domain);
	else
		retv = ovirt_basic_logon(ov, ov->username, ov->pass,
				ov->domain);
	if (retv < 0) {
		fprintf(stderr, "user credentials become invalid.\n");
		goto exit_5;
	}
	if ((retv = ovirt_session_logon(ov, 0)) < 0)
		fprintf(stderr, "Internal Error: " \
				"Cannot invalidate session cookie.\n");

exit_5:
	return retv;
}
	
int ovirt_is_engine(struct ovirt *ov)
{
	int retv = 0;

	strcpy(ov->uri, ov->engine);
	strcat(ov->uri, ovirt_api);
	curl_easy_setopt(ov->curl, CURLOPT_URL, ov->uri);
	ov->dnlen = 0;
	ov->hdlen = 0;
	ov->errmsg[0] = 0;
	curl_easy_perform(ov->curl);
	ov->dndat[ov->dnlen] = 0;
	ov->hdbuf[ov->hdlen] = 0;
	retv = http_check_status(ov->hdbuf, ov->dndat);
	if (-retv == err_base + err_unauth)
		retv = 1;
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
		goto exit_5;
	}
	oxml = ovirt_xml_init(ov->dndat, ov->dnlen);
	if (oxml) {
		len = xml_get_value(oxml, "/api/product_info/version/major",
				ov->dndat, ov->max_dnlen);
		ovirt_xml_exit(oxml);
		if (len > 0 && (unsigned int)len < ov->max_dnlen) {
			ov->version = atoi(ov->dndat);
			retv = ov->version;
		}
	}

exit_5:
	return retv;
}

static void add_vm_node(xmlNode *node, const char *vmid,
		struct list_head *vmhead, struct list_head *vmpool)
{
	struct ovirt_vm *curvm;
	xmlNode *pool_node, *subn;
	char plid[64];
	struct list_head *cur;
	struct ovirt_pool *curpool;
	int len;

	curvm = (struct ovirt_vm *)malloc(sizeof(struct ovirt_vm));
	INIT_LIST_HEAD(&curvm->vm_link);
	INIT_LIST_HEAD(&curvm->nics);
	INIT_LIST_HEAD(&curvm->disks);
	curvm->state[0] = 0;
	len = xml_get_node_attr(node, "href", curvm->href, sizeof(curvm->href));
	assert((unsigned int)len < sizeof(curvm->href));
	strcpy(curvm->id, vmid);
	curvm->con = 0;
	curvm->hit = 1;
	curvm->removed = 0;
	curvm->pool = NULL;
	pool_node = xml_search_children(node, "vm_pool");
	if (pool_node) {
		len = xml_get_node_attr(pool_node, "id", plid, sizeof(plid));
		list_for_each(cur, vmpool) {
			curpool = list_entry(cur, struct ovirt_pool, pool_link);
			if (strcmp(curpool->id, plid) == 0)
				break;
		}
		if (cur != vmpool) {
			curvm->pool = curpool;
			curpool->vmsnow += 1;
		}
	}
	subn = xml_search_children(node, "name");
	if (subn)
		xml_get_node_value(subn, curvm->name, sizeof(curvm->name));
	list_add(&curvm->vm_link, vmhead);
}

static int xml_getvms(const char *xmlstr, int len, struct list_head *vmhead,
		struct list_head *vmpool)
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
		len = xml_get_node_attr(node, "id", id, sizeof(id));
		assert((unsigned int)len < sizeof(curvm->id));
		list_for_each(cur, vmhead) {
			curvm = list_entry(cur, struct ovirt_vm, vm_link);
			if (strcmp(curvm->id, id) == 0) {
				curvm->hit = 1;
				curvm->removed = 0;
				break;
			}
		}
		if (cur == vmhead)
			add_vm_node(node, id, vmhead, vmpool);
		node = xml_next_node(node);
	}
	ovirt_xml_exit(oxml);
	list_for_each_safe(cur, tmp, vmhead) {
		curvm = list_entry(cur, struct ovirt_vm, vm_link);
		if (curvm->hit == 0) {
			list_del(&curvm->vm_link, vmhead);
			if (curvm->pool)
				curvm->pool->vmsnow -= 1;
			free(curvm);
		} else
			curvm->hit = 0;
	}
	return numvms;
}

static const char ovirt_vms[] = "/ovirt-engine/api/vms";

int ovirt_list_vms(struct ovirt *ov, struct list_head *vmhead,
		struct list_head *vmpool)
{
	struct curl_slist *header = NULL;
	int retv, numvms = 0;


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
	if (retv != 0)
		fprintf(stderr, "Cannot list VMs. Error code: %x\n", -retv);
	else
		numvms = xml_getvms(ov->dndat, ov->dnlen, vmhead, vmpool);

	return numvms;
}

static int match_vm_status(const char *st)
{
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
		len = xml_get_value(oxml, "/vm/status", vm->state,
				sizeof(vm->state));
		assert((unsigned int)len < sizeof(vm->state));
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

	if (strcmp(action, "status") == 0) {
		retv = ovirt_vm_getstate(ov, vm);
		goto exit_5;
	}

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

exit_5:
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
		proto = xml_search_children(node, "protocol");
		if (strcmp((const char *)proto->children->content, "spice") == 0)
			break;
		node = xml_next_node(node);
	} while (node);
	if (!node) {
		fprintf(stderr, "No spice graphics console information.\n");
		goto exit_10;
	}
	conlen = xml_get_node_attr(node, "href", conlink, maxlen);
	assert(conlen < maxlen);

exit_10:
	ovirt_xml_exit(oxml);
	return conlen;
}

static int ovirt_download(struct ovirt *ov, const char *link)
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
		retv = -(err_base + err_download);
		return retv;
	}
	len = xml_get_value(oxml, "/action/remote_viewer_connection_file",
			ov->dndat, ov->max_dnlen);
	ovirt_xml_exit(oxml);
	return len;
}

static int xml_get_nics(const char *xmlstr, int len, struct list_head *nichead)
{
	struct ovirt_xml *oxml;
	xmlNode *node, *unod;
	int numnics;
	struct list_head *cur, *tmp;
	struct ovirt_vmnic *curnic;
	static const char xpath[] = "/nics/nic";
	char id[64];

	oxml = ovirt_xml_init(xmlstr, len);
	if (!oxml)
		return 0;
	node = xml_search_element(oxml, xpath);
	numnics = 0;
	while (node) {
		numnics += 1;
		len = xml_get_node_attr(node, "id", id, sizeof(id));
		assert((unsigned int)len < sizeof(curnic->id));
		list_for_each(cur, nichead) {
			curnic = list_entry(cur, struct ovirt_vmnic, nic_link);
			if (strcmp(curnic->id, id) == 0) {
				curnic->hit = 1;
				break;
			}
		}
		if (cur == nichead) {
			curnic = (struct ovirt_vmnic *)malloc(
					sizeof(struct ovirt_vmnic));
			INIT_LIST_HEAD(&curnic->nic_link);
			strcpy(curnic->id, id);
			list_add(&curnic->nic_link, nichead);
			curnic->hit = 1;
		}
		*curnic->name = 0;
		*curnic->interface = 0;
		*curnic->mac = 0;
		unod = xml_search_children(node, "name");
		if (unod)
			xml_get_node_value(unod, curnic->name,
					sizeof(curnic->name));
		unod = xml_search_children(node, "interface");
		if (unod)
			xml_get_node_value(unod, curnic->interface,
					sizeof(curnic->interface));
		unod = xml_search_children(node, "mac");
		if (unod) {
			unod = xml_search_children(unod, "address");
			if (unod)
				xml_get_node_value(unod, curnic->mac,
						sizeof(curnic->mac));
		}

		node = xml_next_node(node);
	}
	ovirt_xml_exit(oxml);

	list_for_each_safe(cur, tmp, nichead) {
		curnic = list_entry(cur, struct ovirt_vmnic, nic_link);
		if (curnic->hit == 0) {
			list_del(&curnic->nic_link, nichead);
			free(curnic);
		} else
			curnic->hit = 0;
	}

	return numnics;
}

int ovirt_get_vmnics(struct ovirt *ov, struct ovirt_vm *vm)
{
	struct curl_slist *header = NULL;
	int numnics = 0, retv;

	strcpy(ov->uri, ov->engine);
	strcat(ov->uri, vm->href);
	strcat(ov->uri, "/nics");
	curl_easy_setopt(ov->curl, CURLOPT_URL, ov->uri);

	header = curl_slist_append(header, hd_prefer);
	header = curl_slist_append(header, ov->token);
	header = curl_slist_append(header, hd_accept_xml);
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
		goto exit_5;
	numnics = xml_get_nics(ov->dndat, ov->dnlen, &vm->nics);

exit_5:
	return numnics;
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
		retv = -(err_base + err_file);
		goto exit_5;
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
	assert((unsigned int)len < sizeof(conlink));
	retv = len;
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
	if (retv <= 0)
		remove(vv);
exit_5:
	return retv;
}

static int xml_get_disks(const char *xmlbuf, int len, struct list_head *dskhead)
{
	struct ovirt_xml *oxml;
	int numdisks = 0, numb;
	xmlNode *node, *subn;
	struct list_head *curdsk, *savhd;
	struct ovirt_vmdisk *vmdsk;
	char id[64];

	oxml = ovirt_xml_init(xmlbuf, len);
	if (!oxml)
		return numdisks;
	node = xml_search_element(oxml, "/disk_attachments/disk_attachment");
	while (node) {
		numdisks += 1;
		id[0] = 0;
		numb = xml_get_node_attr(node, "id", id, sizeof(id));
		assert(numb > 0 && numb < (int)sizeof(id));
		list_for_each(curdsk, dskhead) {
			vmdsk = list_entry(curdsk, struct ovirt_vmdisk,
					dsk_link);
			if (strcmp(vmdsk->id, id) == 0) {
				vmdsk->hit = 1;
				break;
			}
		}
		if (curdsk == dskhead) {
			vmdsk = (struct ovirt_vmdisk *)malloc(sizeof(
						struct ovirt_vmdisk));
			vmdsk->hit = 1;
			INIT_LIST_HEAD(&vmdsk->dsk_link);
			list_add(&vmdsk->dsk_link, dskhead);
			strcpy(vmdsk->id, id);
		}
		vmdsk->interface[0] = 0;
		subn = xml_search_children(node, "interface");
		if (subn)
			numb = xml_get_node_value(subn, vmdsk->interface,
					sizeof(vmdsk->interface));
		vmdsk->href[0] = 0;
		subn = xml_search_children(node, "disk");
		if (subn)
			numb = xml_get_node_attr(subn, "href", vmdsk->href,
					sizeof(vmdsk->href));
		node = xml_next_node(node);
	}
	ovirt_xml_exit(oxml);
	list_for_each_safe(curdsk, savhd, dskhead) {
		vmdsk = list_entry(curdsk, struct ovirt_vmdisk, dsk_link);
		if (vmdsk->hit)
			vmdsk->hit = 0;
		else {
			list_del(curdsk, dskhead);
			free(vmdsk);
		}
	}
	return numdisks;
}

static void xml_fill_vmdisk(const char *xmlbuf, int len,
		struct ovirt_vmdisk *vmdsk)
{
	struct ovirt_xml *oxml;
	xmlNode *node, *subn;
	char buf[16];

	oxml = ovirt_xml_init(xmlbuf, len);
	if (!oxml)
		return;
	node = xml_search_element(oxml, "/disk");
	if (!node)
		goto exit_10;
	subn = xml_search_children(node, "name");
	if (subn)
		xml_get_node_value(subn, vmdsk->name, sizeof(vmdsk->name));
	subn = xml_search_children(node, "actual_size");
	buf[0] = 0;
	if (subn) {
		xml_get_node_value(subn, buf, sizeof(buf));
		vmdsk->actsiz = atol(buf);
	}
	vmdsk->format[0] = 0;
	subn = xml_search_children(node, "format");
	if (subn)
		xml_get_node_value(subn, vmdsk->format, sizeof(vmdsk->format));
	vmdsk->status[0] = 0;
	subn = xml_search_children(node, "status");
	if (subn)
		xml_get_node_value(subn, vmdsk->status, sizeof(vmdsk->status));

exit_10:
	ovirt_xml_exit(oxml);
}

static void ovirt_fill_vmdisk(struct ovirt *ov, struct ovirt_vmdisk *vmdsk)
{
	struct curl_slist *header = NULL;
	int retv;

	strcpy(ov->uri, ov->engine);
	strcat(ov->uri, vmdsk->href);
	curl_easy_setopt(ov->curl, CURLOPT_URL, ov->uri);
	header = curl_slist_append(header, hd_prefer);
	header = curl_slist_append(header, ov->token);
	header = curl_slist_append(header, hd_accept_xml);
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
		return;
	xml_fill_vmdisk(ov->dndat, ov->dnlen, vmdsk);
	return;
}

int ovirt_get_vmdisks(struct ovirt *ov, struct ovirt_vm *vm)
{
	struct curl_slist *header = NULL;
	int numdisks = 0, retv;
	struct list_head *curdsk;
	struct ovirt_vmdisk *vmdsk;

	strcpy(ov->uri, ov->engine);
	strcat(ov->uri, vm->href);
	strcat(ov->uri, "/diskattachments");
	curl_easy_setopt(ov->curl, CURLOPT_URL, ov->uri);

	header = curl_slist_append(header, hd_prefer);
	header = curl_slist_append(header, ov->token);
	header = curl_slist_append(header, hd_accept_xml);
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
		goto exit_5;
	numdisks = xml_get_disks(ov->dndat, ov->dnlen, &vm->disks);
	list_for_each(curdsk, &vm->disks) {
		vmdsk = list_entry(curdsk, struct ovirt_vmdisk, dsk_link);
		ovirt_fill_vmdisk(ov, vmdsk);
	}

exit_5:
	return numdisks;
}

static inline void ovirt_vmdisk_list_free(struct list_head *dskhead)
{
	struct list_head *cur, *n;
	struct ovirt_vmdisk *curdsk;

	list_for_each_safe(cur, n, dskhead) {
		curdsk = list_entry(cur, struct ovirt_vmdisk, dsk_link);
		list_del(cur, dskhead);
		free(curdsk);
	}
}

static inline void ovirt_vmnic_list_free(struct list_head *nichead)
{
	struct list_head *cur, *n;
	struct ovirt_vmnic *curnic;

	list_for_each_safe(cur, n, nichead) {
		curnic = list_entry(cur, struct ovirt_vmnic, nic_link);
		list_del(cur, nichead);
		free(curnic);
	}
}

void ovirt_vmlist_free(struct list_head *vmhead)
{
	struct list_head *cur, *n;
	struct ovirt_vm *curvm;

	list_for_each_safe(cur, n, vmhead) {
		curvm = list_entry(cur, struct ovirt_vm, vm_link);
		list_del(cur, vmhead);
		ovirt_vmnic_list_free(&curvm->nics);
		ovirt_vmdisk_list_free(&curvm->disks);
		if (curvm->pool)
			curvm->pool->vmsnow -= 1;
		free(curvm);
	}
}

void ovirt_vmpool_free(struct list_head *vmpool)
{
	struct ovirt_pool *curpool;
	struct list_head *cur, *tmp;

	list_for_each_safe(cur, tmp, vmpool) {
		curpool = list_entry(cur, struct ovirt_pool, pool_link);
		if (curpool->vmsnow != 0) {
			fprintf(stderr, "pool kept: %s\n", curpool->id);
			curpool->removed = 1;
			continue;
		}
		list_del(cur, vmpool);
		free(curpool);
	}
}

static int xml_get_vmpools(const char *xmlstr, int len,
		struct list_head *vmpool)
{
	struct list_head *cur, *tmp;
	struct ovirt_xml *oxml;
	struct ovirt_pool *curpool;
	xmlNode *node, *subnode, *lnknode;
	int numpools;
	static const char xpath[] = "/vm_pools/vm_pool";
	char id[64], vmsmax[4];

	oxml = ovirt_xml_init(xmlstr, len);
	if (!oxml)
		return 0;
	node = xml_search_element(oxml, xpath);
	numpools = 0;
	while (node) {
		numpools += 1;
		len = xml_get_node_attr(node, "id", id, sizeof(id));
		assert(len < (int)sizeof(curpool->id));
		list_for_each(cur, vmpool) {
			curpool = list_entry(cur, struct ovirt_pool, pool_link);
			if (strcmp(curpool->id, id) == 0) {
				curpool->hit = 1;
				curpool->removed = 0;
				break;
			}
		}
		if (cur == vmpool) {
			curpool = (struct ovirt_pool *)malloc(sizeof(
						struct ovirt_pool));
			assert(curpool != NULL);
			strcpy(curpool->id, id);
			subnode = xml_search_children(node, "name");
			curpool->name[0] = 0;
			xml_get_node_value(subnode, curpool->name, sizeof(curpool->name));
			vmsmax[0] = '0';
			vmsmax[1] = 0;
			subnode = xml_search_children(node, "max_user_vms");
			xml_get_node_value(subnode, vmsmax, sizeof(vmsmax));
			curpool->vmsmax = atoi(vmsmax);
			curpool->vmsnow = 0;
			curpool->removed = 0;
			curpool->hit = 1;
			INIT_LIST_HEAD(&curpool->pool_link);
			subnode = xml_search_children(node, "actions");
			lnknode = xml_search_children(subnode, "link");
			curpool->alloc[0] = 0;
			len = xml_get_node_attr(lnknode, "href",
					curpool->alloc, sizeof(curpool->alloc));
			list_add(&curpool->pool_link, vmpool);
		}
		node = xml_next_node(node);
	}
	ovirt_xml_exit(oxml);

	list_for_each_safe(cur, tmp, vmpool) {
		curpool = list_entry(cur, struct ovirt_pool, pool_link);
		if (curpool->hit == 0) {
			if (curpool->vmsnow > 0) {
				curpool->removed = 1;
			} else {
				list_del(cur, vmpool);
				free(curpool);
			}
		} else
			curpool->hit = 0;
	}
	return numpools;
}

static const char pools_path[] = "/ovirt-engine/api/vmpools";
int ovirt_list_vmpools(struct ovirt *ov, struct list_head *vmpool)
{
	struct curl_slist *header = NULL;
	int numpools = 0, retv;

	strcpy(ov->uri, ov->engine);
	strcat(ov->uri, pools_path);
	curl_easy_setopt(ov->curl, CURLOPT_URL, ov->uri);

	header = curl_slist_append(header, hd_prefer);
	header = curl_slist_append(header, ov->token);
	header = curl_slist_append(header, hd_accept_xml);
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
	if (retv == 0)
		numpools = xml_get_vmpools(ov->dndat, ov->dnlen, vmpool);

	return numpools;
}

int ovirt_pool_allocatvm(struct ovirt *ov, struct ovirt_pool *pool)
{
	struct curl_slist *header = NULL;
	int retv, numvm = 0;

	if (pool->vmsnow == pool->vmsmax)
		return numvm;

	strcpy(ov->uri, ov->engine);
	strcat(ov->uri, pool->alloc);
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
	if (retv == 0)
		numvm = 1;
	return numvm;
}

const char * ovirt_vm_status_internal(int sta)
{
	if (sta < 0 || sta >= sizeof(vm_states) / sizeof(char *))
		sta = sizeof(vm_states) / sizeof(char *) - 1;
	return vm_states[sta];
}
