#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <assert.h>
#include "base64.h"

#define B64_BITS	6

static const char BASE64_CHAR[] = {
	'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', 'K', 'L', 'M',
	'N', 'O', 'P', 'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X', 'Y', 'Z',
	'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l', 'm',
	'n', 'o', 'p', 'q', 'r', 's', 't', 'u', 'v', 'w', 'x', 'y', 'z',
	'0', '1', '2', '3', '4', '5', '6', '7', '8', '9', '+', '/'
};

int str2bin_b64(unsigned char *binbytes, int num, const char *str)
{
	int bpos, bitpos, bbit;
	unsigned char nxtbyte, nchr;
	const char *pchr;
	unsigned short digit;

	bitpos = 0;
	pchr = str;
	while (*pchr != 0 && *pchr != '=') {
		nchr = *pchr++;
		if (nchr >= 'A' && nchr <= 'Z')
			digit = nchr - 'A';
		else if (nchr >= 'a' && nchr <= 'z')
			digit = (nchr - 'a') + 26;
		else if (nchr >= '0' && nchr <= '9')
			digit = (nchr - '0') + 52;
		else if (nchr == '+')
			digit = 62;
		else if (nchr == '/')
			digit = 63;
		else if ((nchr == '=') && *(pchr+1) == 0)
			break;
		else
			return -2;

		bpos = bitpos >> 3;
		if (bpos == num)
			return -1;
		nxtbyte = 255;
		bbit = bitpos & 7;
		switch(bbit) {
		case 0:
			binbytes[bpos] = (digit << 2);
			break;
		case 6:
			binbytes[bpos] |= (digit >> 4);
			nxtbyte = ((digit & 0x0f) << 4);
			break;
		case 4:
			binbytes[bpos] |= (digit >> 2);
			nxtbyte = ((digit & 3) << 6);
			break;
		case 2:
			binbytes[bpos] |= digit;
			break;
		default:
			assert(0);
		}
		if (nxtbyte != 255) {
			if (bpos + 1 < num)
				binbytes[bpos+1] = nxtbyte;
			else if (nxtbyte != 0 || *(pchr+1) != '=')
				return -1;
		}

		bitpos += B64_BITS;
	}
	return bpos + 1;
}

int bin2str_b64(char *strbuf, int len, const unsigned char *binbytes, int num)
{
	int i, idx;
	char *p64;
	unsigned char nxtbyte;
	int bpos, bbit;
	unsigned short tmpc;

	p64 = strbuf;
	for (i = 0; i < (num << 3) && (p64 - strbuf) < len; i += B64_BITS) {
		bpos = (i >> 3);
		bbit = i & 7;
		tmpc = binbytes[bpos];
		if (__builtin_expect(bpos + 1 < num, 1))
			nxtbyte = binbytes[bpos+1];
		else
			nxtbyte = 0;
		switch(bbit) {
		case 0:
			idx = tmpc >> 2;
			break;	
		case 6:
			idx = ((tmpc & 3) << 4) | (nxtbyte >> 4);
			break;
		case 4:
			idx = ((tmpc & 0x0f) << 2) | (nxtbyte >> 6);
			break;
		case 2:
			idx = tmpc & 0x3f;
			break;
		default:
			assert(0);
		}
		assert(idx < 64);
		*p64++ = BASE64_CHAR[idx];
	}
	if (p64 - strbuf == len)
		return len;
	if (bbit == 4 || bbit == 6) {
		if (p64 < strbuf + len)
			*p64++ = '=';
		if (bbit == 6)
			if (p64 < strbuf + len)
				*p64++ = '=';
	}
	if (p64 < strbuf + len)
		*p64 = 0;
	return (int)(p64 - strbuf);
}
