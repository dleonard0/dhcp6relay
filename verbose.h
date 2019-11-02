#include <stdio.h>

extern int verbose_level;
#define verbose(...) \
	do { if (verbose_level) fprintf(stderr, __VA_ARGS__); } while (0)
#define verbose2(...) \
	do { if (verbose_level > 1) fprintf(stderr, __VA_ARGS__); } while (0)
