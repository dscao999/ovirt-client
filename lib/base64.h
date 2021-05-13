#ifndef BASE64_DSCAO__
#define BASE64_DSCAO__

#ifdef __cplusplus
extern "C" {
#endif

int bin2str_b64(char *buf, int len, const unsigned char *bigones, int num);

int str2bin_b64(unsigned char bigones[], int num, const char *buf);

#ifdef __cplusplus
}
#endif
#endif /* BASE64_DSCAO__ */
