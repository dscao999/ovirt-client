#ifndef HTTP_CODES_DSCAO__
#define HTTP_CODES_DSCAO__

#define http_ok		200
#define http_no_content	204
#define http_unauth	401

#ifdef __cplusplus
extern "C" {
#endif

extern const unsigned char VM_LAUNCH;
extern const unsigned char VM_DOWN;
extern const unsigned char VM_SUSPEND;
extern const unsigned char VM_IN_DOWN;
extern const unsigned char VM_REBOOT;
extern const unsigned char VM_SAVE;
extern const unsigned char VM_IN_UP;
extern const unsigned char VM_RESTORE;
extern const unsigned char VM_UP;
extern const unsigned char VM_UNKNOWN;

#ifdef __cplusplus
}
#endif
#endif /*HTTP_CODES_DSCAO__ */
