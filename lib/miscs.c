#include <stdio.h>
#include <time.h>
#include <string.h>
#include "miscs.h"

int elog(const char *fmt, ...)
{
	va_list va;
	int len;
	time_t curtm;
	char *datime, *ln;

	curtm = time(NULL);
	datime = ctime(&curtm);
	ln = strchr(datime, '\n');
	if (ln)
		*ln = 0;
	fprintf(stderr, "%s ", datime);
	va_start(va, fmt);
	len = vfprintf(stderr, fmt, va);
	va_end(va);
	return len;
}
