/*
 * To relay DHCPv6 packets, this program must be able to
 *  - receive packets whose L2 destination is not ours, and
 *  - send packets with an L2 source that is not ours.
 * On Linux, only the AF_PACKET/SOCK_RAW socket allows this,
 * which means we need to be able to process the IPv6 and UDPv6
 * headers, as well as receive all packets ourselves. Linux
 * also provides a BPF-like filter to be attached to sockets,
 * for which tcpdump(8) -d can be used as a compiler.
 */

#include <string.h>
#include <sys/socket.h>
#include <net/ethernet.h>
#include <netinet/udp.h>
#include <netinet/ip6.h>
#include <arpa/inet.h>		/* htonl(), ntohl() */
#include <linux/if_packet.h>	/* sockaddr_ll */
#include <linux/if_ether.h>	/* ETH_P_* */
#include <linux/if_arp.h>	/* ARPHRD_* */

struct pkt {
	struct sockaddr_ll sll; /* (Not used when sending) */
	struct ip6_hdr *ip6_hdr;/* NULL or points into data */
	struct udphdr *udphdr;	/* NULL or points into data */
	char *data;		/* NULL or points into data */
	unsigned int datalen;
	unsigned int rawoff;    /* L2 padding offset */
	unsigned int rawlen;	/* L2 packet size (excludes rawoff) */
	char raw[65536+4];	/* L2 packet data (starts at rawoff) */
};
#define PKT_INIT { .rawoff = 0 }

/* Scans an L2 packet and sets the header pointers.
 * On entry, the sll, rawlen, rawoff and raw[] fields of pkt must be set.
 * On success the fields ip6_hdr, udphdr, data and datalen
 * will be set, and point into pkt->raw[].
 * Returns 0 on success, -1 if this is not a valid udp packet. */
int pkt_scan_udp(struct pkt *pkt);

/* Recieves from AF_PACKET into a packet structure.
 * Returns -1 on error, 0 if socket closed. */
int pkt_recv(int fd, struct pkt *pkt);

/* Updates UDP packet checksum and transmits it as L2 packet */
int pkt_send(int fd, struct pkt *pkt);

/* Inserts len bytes of data into the UDP payloat at offset off.
 * If len is negative, then removes the -len bytes before offset off.
 * Shifts remaining data and updates headers.
 * Returns NULL on error, or (if len>0) a pointer to insert len bytes of data,
 * otherwise a meaningless non-NULL pointer on success. */
void *pkt_insert_udp_data(struct pkt *pkt, unsigned int off, int len);

/* Returns pkt->sll.sll_addr as a static string */
const char *pkt_lladdr(const struct pkt *pkt);
