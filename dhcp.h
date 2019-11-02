#include <net/if.h>

struct ifc;
struct pkt;

int dhcp_wrap(struct pkt *pkt, const struct ifc *ifc);
int dhcp_unwrap(struct pkt *pkt, const struct ifc *ifc,
        char ifname[IFNAMSIZ]);
