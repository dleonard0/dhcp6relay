#include "dumphex.h"

/* Print hex dump of memory. Intended for debugging. */
void
dumphex(FILE *f, const char *label, const void *p, size_t n)
{
	size_t row;
	size_t i;

	if (label)
		fprintf(f, "%s:\n", label);
	for (row = 0; row < n; row += 16) {
		fprintf(f, " %04zx:", row);
		for (i = row; i < row + 16; i++) {
			if (!(i & 0x7))
				putc(' ', f);
			if (i < n)
				fprintf(f, " %02x",
				    ((unsigned char *)p)[i]);
			else
				fputs("   ", f);
		}
		putc(' ', f);
		for (i = row; i < row + 16 && i < n; i++) {
			unsigned char ch;
			if (!(i & 0x7))
				putc(' ', f);
			ch = ((unsigned char *)p)[i];
			if (ch < ' ' || ch > '~')
				ch = '.';
			putc(ch, f);
		}
		putc('\n', f);
	}
}
