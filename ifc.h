#include <netinet/in.h>
#include <ifaddrs.h>

/* A system interface */
struct ifc {
	enum { NONE, CLIENT, SERVER } side;
	const char *name;
	unsigned char trust_hops;	/* Max number of client-side relays */
	unsigned int index;		/* ifindex, set by ifc_set_info() */
	struct in6_addr addr;		/* Link-local address, set by ifc_set_info() */
	const char *vendor_data;	/* Vendor-class info to add */
	unsigned vendor_len;
};

/* Sets an ifc's index LL-address using the list from getifaddrs() */
int ifc_set_info(const struct ifaddrs *ifa, struct ifc *ifc);
