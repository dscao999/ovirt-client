#include <stdio.h>
#include <string.h>
#include "base64.h"

int main(int argc, char *argv[])
{
	char buf[256], bytes[256];
	const char *intxt;
	int len;

	memset(buf, 0, sizeof(buf));
	intxt = "abcdABCD";
	if (argc > 1)
		intxt = argv[1];
	len = bin2str_b64(buf, sizeof(buf),
			(const unsigned char *)intxt, strlen(intxt));
	printf("%s\n", buf);
	printf("Length: %d\n", len);
	len = str2bin_b64((unsigned char *)bytes, 256, buf);
	printf("%s\n", bytes);
	return 0;
}
