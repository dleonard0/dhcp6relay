#include <err.h>
#include <limits.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include <unistd.h>

#include "ifc.h"
#include "loop.h"
#include "verbose.h"

/*
 * Lightweight DHCPv6 Relay Agent (RFC 6221) for Linux
 * David Leonard, 2019
 */

static void
on_sighup()
{
	loop_stop = 1;
}

/* Converts string to int, returning true on success */
static int
to_int(const char *arg, int *ret)
{
	char *e = NULL;
	long v = strtol(arg, &e, 0);
	if (!e || *e || v < INT_MIN || v > INT_MAX)
		return 0;
	*ret = v;
	return 1;
}

int
main(int argc, char *argv[])
{
	int error = 0;
	int ch;
	struct ifc *ifc = NULL;
	struct ifc *this_ifc = NULL;
	unsigned int nifc = 0;
	int i;

	while ((ch = getopt(argc, argv, "i:o:t:v")) != -1)
		switch (ch) {
		case 'i':
		case 'o':
			ifc = realloc(ifc, (nifc + 1) * sizeof *ifc);
			if (!ifc)
				err(1, "realloc");
			this_ifc = &ifc[nifc++];
			memset(this_ifc, 0, sizeof *this_ifc);
			this_ifc->name = optarg;
			this_ifc->side = ch == 'i' ? CLIENT : SERVER;
			break;
		case 't':
			if (!this_ifc || this_ifc->side != CLIENT) {
				error = 1;
				warnx("-t: must follow -i <interface>");
				break;
			}
			if (!to_int(optarg, &i) || i < 0 || i > 255) {
				error = 1;
				warnx("-t: expected number from 0..255 (%s)",
				    this_ifc->name);
				break;
			}
			this_ifc->trust_hops = i;
			break;
		case 'v':
			verbose_level++;
			break;
		default:
			error = 1;
		}

	if (optind != argc)
		error = 1;
	if (error) {
		fprintf(stderr, "usage: %s"
			" [-v]"
			" [-i interface [-t trust]]..."
			" [-o interface]..."
			"\n",
			argv[0]);
		exit(2);
	}

	if (signal(SIGHUP, on_sighup) == SIG_ERR)
		err(1, "signal SIGHUP");
	for (;;) {
		struct ifaddrs *ifaddrs;
		if (getifaddrs(&ifaddrs) == -1)
			err(1, "getifaddrs");
		for (unsigned int i = 0; i < nifc; i++)
			ifc_set_info(ifaddrs, &ifc[i]);
		freeifaddrs(ifaddrs);

		loop_stop = 0;
		relay_loop(ifc, nifc);
		verbose("reloading interfaces\n");
	}
}
