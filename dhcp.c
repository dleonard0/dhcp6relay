#include <err.h>

#include "dhcp.h"
#include "dumphex.h"
#include "ifc.h"
#include "pkt.h"
#include "verbose.h"

#define INET6_ADDRLEN	16

/* DHCP Relay packet header. This is different to normal DHCPv6 */
struct dhcp_relay_hdr {
	uint8_t msg_type;
#define DHCP_ADVERTISE    2
#define DHCP_REPLY        7
#define DHCP_RECONFIGURE 10
#define DHCP_RELAY_FORW  12
#define DHCP_RELAY_REPL  13
	uint8_t hop_count;
	uint8_t link_address[INET6_ADDRLEN];
	uint8_t peer_address[INET6_ADDRLEN];
};

/* DHCP option header. It's in network byte order. */
struct dhcp_opt {
	uint16_t code;
#define OPTION_RELAY_MSG	 9
#define OPTION_VENDOR_CLASS	16
#define OPTION_INTERFACE_ID	18
	uint16_t len;
	/* data follows, unpadded */
};

/* Wraps a client DHCPv6 packet into a RELAY-FORW message.
 * The source interface's name is used as the INTERFACE-ID option.
 * Returns 0 on success, otherwise -1 if the message should
 * be discarded. */
int
dhcp_wrap(struct pkt *pkt, const struct ifc *ifc)
{
	if (verbose_level > 1)
		dumphex(stderr, "before-wrap", pkt->data, pkt->datalen);

	/* Discard selected messages */
	struct dhcp_relay_hdr *dhcp = (struct dhcp_relay_hdr *)pkt->data;
	uint8_t hop_count = 0;
	if (pkt->datalen) {
		switch (pkt->data[0/*msg-type*/]) {
		case DHCP_ADVERTISE:
		case DHCP_REPLY:
		case DHCP_RECONFIGURE:
		case DHCP_RELAY_REPL:
			verbose2("%s: discarding message type %u\n",
			    ifc->name, *pkt->data);
			return -1;	/* Discard */
		case DHCP_RELAY_FORW:
			if (pkt->datalen < 2)
				return -1; /* malformed */
			if (pkt->data[1/*hop_count*/] >= ifc->trust_hops) {
				verbose(
				    "%s: too many nested forwards (%u) from %s",
				    ifc->name, dhcp->hop_count,
				    pkt_lladdr(pkt));
				return -1;
			}
			hop_count = pkt->data[1] + 1;
		}
	}

	struct dhcp_relay_hdr hdr = {
		.msg_type = DHCP_RELAY_FORW,
		.hop_count = hop_count,
		.link_address = {0} /* link-address field is :: */
		/* .peer_address = ip6_src */
	};
	memcpy(&hdr.peer_address, &pkt->ip6_hdr->ip6_src, INET6_ADDRLEN);

	struct dhcp_opt opt_vendor = {
		.code = htons(OPTION_VENDOR_CLASS),
		.len = htons(ifc->vendor_len)
	};
	uint16_t ifnamelen = strnlen(ifc->name, IFNAMSIZ);
	struct dhcp_opt opt_ifname = {
		.code = htons(OPTION_INTERFACE_ID),
		.len = htons(ifnamelen)
	};
	struct dhcp_opt opt_msg = {
		.code = htons(OPTION_RELAY_MSG),
		.len = htons(pkt->datalen)
	};

	/* Insert the relay header and options at the
	 * beginning of the UDP payload:
	 *    hdr
	 *    INTERFACE_ID: ifc->name
	 *    [VENDOR_CLASS: ifc->vendor]
	 *    RELAY_MSG: <original data goes here>
	 */
	unsigned int insert_len =
	    sizeof hdr +
	    sizeof opt_ifname + ifnamelen +
	    (ifc->vendor_len ? (sizeof opt_vendor + ifc->vendor_len) : 0) +
	    sizeof opt_msg;

	char *dst = pkt_insert_udp_data(pkt, 0, insert_len);
	if (!dst) {
		warnx("%s: big packet? from %s", ifc->name,
		    pkt_lladdr(pkt));
		return -1;
	}

	memcpy(dst, &hdr, sizeof hdr); dst += sizeof hdr;
	memcpy(dst, &opt_ifname, sizeof opt_ifname); dst += sizeof opt_ifname;
	memcpy(dst, ifc->name, ifnamelen); dst += ifnamelen;
	if (ifc->vendor_len) {
		memcpy(dst, &opt_vendor, sizeof opt_vendor); dst += sizeof opt_vendor;
		memcpy(dst, ifc->vendor_data, ifc->vendor_len); dst += ifc->vendor_len;
	}
	memcpy(dst, &opt_msg, sizeof opt_msg); dst += sizeof opt_msg;

	if (verbose_level > 1)
		dumphex(stderr, "after-wrap", pkt->data, pkt->datalen);
	return 0;
}

/* Unwraps a DHCPv6 RELAY-FORW message from a server.
 * The packet is unwrapped in-place, the IPv6 headers updated,
 * and the INTERFACE-ID is extracted into the ifname[] buffer.
 * Returns 0 on success, other -1 on error. */
int
dhcp_unwrap(struct pkt *pkt, const struct ifc *ifc,
	char ifname[IFNAMSIZ])
{
	struct dhcp_relay_hdr *dhcp = (struct dhcp_relay_hdr *)pkt->data;

	/* Sanity check header */
	if (pkt->datalen < sizeof *dhcp ||
	    dhcp->msg_type != DHCP_RELAY_REPL ||
	    memcmp(dhcp->link_address, &in6addr_any, INET6_ADDRLEN) != 0)
	{
		verbose("%s: bad DHCPv6 relay packet from %s\n",
		    ifc->name, pkt_lladdr(pkt));
		return -1;
	}

	/* Initialise with impossible values to detect missing options */
	unsigned int msg_offset = 0;
	unsigned int msg_len = 0;
	ifname[0] = '\0';

	/* Walk the options, looking for INTERFACE-ID and RELAY-MSG */
	const char *p = pkt->data + 2 + 16 + 16;
	const char *pmax = pkt->data + pkt->datalen;
	while (p + sizeof (struct dhcp_opt) < pmax) {
		/* Easier to copy into a stack var */
		struct dhcp_opt opt;
		memcpy(&opt, p, sizeof opt);
		opt.len = ntohs(opt.len);
		opt.code = ntohs(opt.code);
		if (!opt.code) {
			break;
		}
		verbose2("DHCPv6 relay packet option %d, offset %d, length %d\n", opt.code, (int) (p - pkt->data), opt.len);
		p += sizeof opt; /* Move to data */
		switch (opt.code) {
		case OPTION_INTERFACE_ID:
			/* Extract the interface name */
			if (opt.len > IFNAMSIZ) {
				warnx("%s: oversized interface-id from %s",
				    ifc->name, pkt_lladdr(pkt));
				return -1;
			}
			memset(ifname, 0, IFNAMSIZ);
			memcpy(ifname, p, opt.len);
			break;
		case OPTION_RELAY_MSG:
			msg_offset = p - pkt->data;
			msg_len = opt.len;
			break;
		/* Ignore other options */
		}
		p += opt.len;
	}
	/* If any required options were missing, its a fail */
	if (!msg_offset || !ifname[0]) {
		warnx("%s: missing relay options from %s",
		    ifc->name, pkt_lladdr(pkt));
		return -1;
	}

	/* Copy the peer-address into the ipv6 dst field */
	memcpy(&pkt->ip6_hdr->ip6_dst, dhcp->peer_address, INET6_ADDRLEN);

	/* Remove the wrapper */
	pkt_insert_udp_data(pkt, msg_offset, -msg_offset);
	if (pkt->datalen > msg_len)
		pkt_insert_udp_data(pkt, pkt->datalen, -(pkt->datalen - msg_len));
	return 0;
}
