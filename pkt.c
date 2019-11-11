#include <errno.h>

#include "pkt.h"

/* Received into pkt->sll and pkt->raw[], using the previous alignment offset */
int
pkt_recv(int fd, struct pkt *pkt)
{
	socklen_t slen = sizeof pkt->sll;
	ssize_t len = recvfrom(fd, &pkt->raw[pkt->rawoff],
		sizeof pkt->raw - pkt->rawoff, 0,
		(struct sockaddr *)&pkt->sll, &slen);
	if (len >= 0)
		pkt->rawlen = len;

	/* Packet has not been scanned */
	pkt->ip6_hdr = NULL;
	pkt->udphdr = NULL;
	pkt->data = NULL;
	pkt->datalen = 0;

	return len;
}

/* One's checksum of 16-bit words. len must be even */
static uint32_t
sum16(const void *data, unsigned int len)
{
	uint32_t sum = 0;
	const uint16_t *p = data;

	while (len) {
		sum += *p++;
		len -= 2;
	}
	return sum;
}

/* Compute the IPv6 UDP checksum of the packet. */
uint16_t
udp6_checksum(const struct pkt *pkt)
{
	uint32_t sum;

	/* We can sum in network-endian, because math */
	sum = sum16(&pkt->ip6_hdr->ip6_src, 16) +
	      sum16(&pkt->ip6_hdr->ip6_dst, 16) +
	      sum16(&pkt->ip6_hdr->ip6_plen, 2) +
	      htons(IPPROTO_UDP) +
	      sum16(pkt->udphdr, 6) +
	      sum16(pkt->data, pkt->datalen & ~1);
	if (pkt->datalen & 1) {
		unsigned char last[2] = { pkt->data[pkt->datalen - 1], 0 };
		sum += sum16(last, sizeof last);
	}

	/* Roll over the carries */
	if (sum > 0xffff) {
		sum = (sum & 0xffff) + (sum >> 16);
		if (sum > 0xffff)
			sum = (sum & 0xffff) + 1;
	}
	sum ^= 0xffff;
	return sum ? sum : 0xffff;
}

/* Update checksum and send the packet */
int
pkt_send(int fd, struct pkt *pkt)
{
	if (pkt->udphdr)
		pkt->udphdr->check = udp6_checksum(pkt);
	return send(fd, &pkt->raw[pkt->rawoff], pkt->rawlen, 0);
}

/* Scan pkt for IPv6 and UDP headers, and update pointers */
int
pkt_scan_udp(struct pkt *pkt)
{
	unsigned int p = pkt->rawoff;
	unsigned int pmax = pkt->rawlen + pkt->rawoff;

	if (pkt->sll.sll_family != AF_PACKET ||
	    pkt->sll.sll_protocol != ntohs(ETH_P_IPV6))
		return -1;

	switch (pkt->sll.sll_hatype) {
	case ARPHRD_ETHER:
		p += ETHER_HDR_LEN;
		break;
	/* TODO: 802.11 */
	default:
		return -1;
	}
	if (p > pmax)
		return -1;

	/* Make sure that rawoff aligns the rest of the packet to
	 * a 4-byte boundary. */
	if (p & 3) {
		unsigned int newoff = 4 - ((p - pkt->rawoff) & 3);
		memmove(&pkt->raw[newoff], &pkt->raw[pkt->rawoff],
		    pkt->rawlen);
		p = p - pkt->rawoff + newoff;
		pkt->rawoff = newoff;
		pmax = pkt->rawlen + pkt->rawoff;
	}

	/* Expect IPv6/UDP without options */
	pkt->ip6_hdr = (struct ip6_hdr *)&pkt->raw[p];
	if ((p += sizeof (struct ip6_hdr)) > pmax)
		return -1;
	if (p + ntohs(pkt->ip6_hdr->ip6_plen) > pmax)
		return -1;
	pmax = p + ntohs(pkt->ip6_hdr->ip6_plen);
	if (pkt->ip6_hdr->ip6_nxt != IPPROTO_UDP)
		return -1;
	pkt->udphdr = (struct udphdr *)&pkt->raw[p];
	if (p + ntohs(pkt->udphdr->len) > pmax)
		return -1;
	if ((p += sizeof (struct udphdr)) > pmax)
		return -1;
	pkt->data = &pkt->raw[p];
	pkt->datalen = ntohs(pkt->udphdr->len) - sizeof (struct udphdr);

	if (udp6_checksum(pkt) != pkt->udphdr->check)
		return -1;

	return 0; // ntohs(pkt->udphdr->len);
}

/* Inserts len bytes of uninitialised data into the UDP payload
 * at offset off. Shifts other data upwards and updates length headers. */
void *
pkt_insert_udp_data(struct pkt *pkt, unsigned int off, int len)
{
	if ((int)off + len < 0) {
		errno = EINVAL;
		return NULL;
	}
	if (len > 0 && pkt->rawoff + pkt->rawlen + len > sizeof pkt->raw) {
		errno = ENOMEM;
		return NULL;
	}
	memmove(pkt->data + ((int)off + len), pkt->data + off,
		&pkt->raw[pkt->rawoff + pkt->rawlen] - (pkt->data + off));
	pkt->rawlen += len;
	pkt->datalen += len;
	pkt->udphdr->len = htons((int)ntohs(pkt->udphdr->len) + len);
	pkt->ip6_hdr->ip6_plen = htons((int)ntohs(pkt->ip6_hdr->ip6_plen) + len);
	return pkt->data + off;
}

const char *
pkt_lladdr(const struct pkt *pkt)
{
	static char buf[3 * 8];
	const char hex[] = "0123456789abcdef";
	unsigned int i;
	char *p;

	for (p = buf, i = 0; i < 8 && i < pkt->sll.sll_halen; i++) {
		if (i) *p++ = ':';
		*p++ = hex[(pkt->sll.sll_addr[i] >> 4) & 0xf];
		*p++ = hex[(pkt->sll.sll_addr[i] >> 0) & 0xf];
	}
	*p = '\0';
	return buf;
}
