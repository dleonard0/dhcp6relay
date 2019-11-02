#include <err.h>
#include <ifaddrs.h>
#include <string.h>

#include <net/if.h>
#include <netinet/in.h>

#include "ifc.h"

int
ifc_set_info(const struct ifaddrs *ifa, struct ifc *ifc)
{
	ifc->index = if_nametoindex(ifc->name);
	if (!ifc->index)
		warn("%s", ifc->name);

	for (; ifa; ifa = ifa->ifa_next)
		if (strncmp(ifc->name, ifa->ifa_name, IFNAMSIZ) == 0 &&
		    ifa->ifa_addr &&
		    ifa->ifa_addr->sa_family == AF_INET6)
		{
			struct sockaddr_in6 *sa6 =
			    (struct sockaddr_in6 *)ifa->ifa_addr;
			if (IN6_IS_ADDR_LINKLOCAL(&sa6->sin6_addr)) {
				ifc->addr = sa6->sin6_addr;
				return 0;
			}
		}
	warnx("%s: no IPv6 link local address, using ::", ifc->name);
	ifc->addr = in6addr_any;
	return -1;
}
