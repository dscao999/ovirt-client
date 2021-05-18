#ifndef OVIRT_CLIENT_DSCAO__
#define OVIRT_CLIENT_DSCAO__

#ifdef __cplusplus
extern "C" {
#endif

struct ovirt;

int ovirt_valid(const char *host);
struct ovirt *ovirt_connect(const char *host, const char *user,
		const char *passwd, const char *domain);
void ovirt_disconnect(struct ovirt *ov);
int ovirt_major_version(struct ovirt *ov);

int ovirt_refresh_resources(struct ovirt *ov);

int ovirt_vmpool_getnum(const struct ovirt *ov);
int ovirt_vmpool_next(struct ovirt *ov, char *id, int buflen, void **context);
int ovirt_vmpool_name(struct ovirt *ov, const char *pool_id,
		char *name, int buflen);
int ovirt_vmpool_maxvms(struct ovirt *ov, const char *pool_id);
int ovirt_vmpool_curvms(struct ovirt *ov, const char *pool_id);
int ovirt_vmpool_grabvm(struct ovirt *ov, const char *pool_id);

int ovirt_vm_getnum(const struct ovirt *ov);
int ovirt_vm_next(struct ovirt *ov, char *id, int buflen, void **context);
int ovirt_vm_name(struct ovirt *ov, const char *vmid, char *name, int buflen);
int ovirt_vm_status_query(struct ovirt *ov, const char *vmid);
const char *ovirt_vm_status(int sta);
int ovirt_vm_start(struct ovirt *ov, const char *vmid);
int ovirt_vm_getvv(struct ovirt *ov, const char *vmid, const char *vvname);

#ifdef __cplusplus
}
#endif
#endif /* OVIRT_CLIENT_DSCAO__ */
