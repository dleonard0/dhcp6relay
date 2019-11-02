#include <err.h>
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

int
main(int argc, char *argv[])
{
	int error = 0;
	int ch;
	struct ifc *ifc = NULL;
	struct ifc *this_ifc = NULL;
	unsigned int nifc = 0;

	while ((ch = getopt(argc, argv, "i:o:v")) != -1)
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
			" [-i interface]..."
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
