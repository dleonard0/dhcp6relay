#include <assert.h>
#include <err.h>
#include <stdio.h>
#include <unistd.h>

#include <linux/filter.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <net/if.h> /* if_nameindex */
#include <sys/socket.h>
#include <sys/types.h>

#include "dumphex.h"
#include "pkt.h"

#define lengthof(A) (sizeof (A) / sizeof (A)[0])

/* Tests AF_PACKET sockets with a DHCPV6 filter */

int
main(int argc, char *argv[])
{
	int s;
	unsigned int i;
	struct sockaddr_ll sll;
	socklen_t slen = sizeof sll;
	const char *ifname;

	if (optind < argc)
		ifname = argv[optind++];
	else
		errx(1, "usage: %s interface\n", argv[0]);

	s = socket(AF_PACKET, SOCK_RAW, 0);
	if (s == -1)
		err(1, "socket");

	/* Bind to one interface */
	memset(&sll, 0, sizeof sll);
	sll.sll_family = AF_PACKET;
	sll.sll_protocol = htons(ETH_P_IPV6);
	sll.sll_ifindex = if_nametoindex(ifname);
	if (!sll.sll_ifindex)
		err(1, "%s", ifname);
	if (bind(s, (struct sockaddr *)&sll, sizeof sll) == -1)
		err(1, "bind");
	printf("%s: bound\n", ifname);

	/* Set to "promiscuous mode" */
	struct packet_mreq mreq = {
	    .mr_ifindex = sll.sll_ifindex, /* computed above */
	    .mr_type = PACKET_MR_PROMISC
	};
	if (setsockopt(s, SOL_PACKET, PACKET_ADD_MEMBERSHIP,
	    &mreq, sizeof mreq) == -1)
		err(1, "setsockopt MR_PROMISC");
	printf("%s: promisc\n", ifname);

	/* Attach a (classic BPF) filter */
	/* (generate with 'tcpdump -dd -i lo ...') */
	struct sock_filter filter[] = {
	    /* [ARPHRD_ETHER] ip6 dst ff02::1:2 && udp dst port 547 */
	    { 0x28, 0, 0, 0x0000000c },
	    { 0x15, 0, 13, 0x000086dd },
	    { 0x20, 0, 0, 0x00000026 },
	    { 0x15, 0, 11, 0xff020000 },
	    { 0x20, 0, 0, 0x0000002a },
	    { 0x15, 0, 9, 0x00000000 },
	    { 0x20, 0, 0, 0x0000002e },
	    { 0x15, 0, 7, 0x00000000 },
	    { 0x20, 0, 0, 0x00000032 },
	    { 0x15, 0, 5, 0x00010002 },
	    { 0x30, 0, 0, 0x00000014 },
	    { 0x15, 0, 3, 0x00000011 },
	    { 0x28, 0, 0, 0x00000038 },
	    { 0x15, 0, 1, 0x00000223 },
	    { 0x6, 0, 0, 0x00040000 },
	    { 0x6, 0, 0, 0x00000000 },
	};
	struct sock_fprog fprog = { lengthof(filter), filter };
	if (setsockopt(s, SOL_SOCKET, SO_ATTACH_FILTER, &fprog, sizeof fprog) == -1)
		err(1, "setsockopt SO_ATTACH_FILTER");

	for (;;) {
		static char buf[65536];
		ssize_t n;
		char ifnamebuf[IF_NAMESIZE];

		memset(&sll, 0, sizeof sll);
		n = recvfrom(s, buf, sizeof buf, 0,
		    (struct sockaddr *)&sll, &slen);
		if (n == -1)
			err(1, "recvfrom");

		assert(sll.sll_family == AF_PACKET);
		printf("recv %zd", n);
		printf(" proto %04x", ntohs(sll.sll_protocol));
		printf(" ifindex %d(%s)", sll.sll_ifindex,
			if_indextoname(sll.sll_ifindex, ifnamebuf));
		printf(" hatype %04x", ntohs(sll.sll_hatype));
		printf(" pktype %s",
		    sll.sll_pkttype == PACKET_HOST ? "HOST" :
		    sll.sll_pkttype == PACKET_BROADCAST ? "BROADCAST" :
		    sll.sll_pkttype == PACKET_MULTICAST ? "MULTICAST" :
		    sll.sll_pkttype == PACKET_OTHERHOST ? "OTHERHOST" :
		    sll.sll_pkttype == PACKET_OUTGOING ? "OUTGOING" :
		    "*UNKNOWN*");
		printf(" halen %u ", sll.sll_halen);
		for (i = 0; i < sll.sll_halen; i++)
			printf("%02x", sll.sll_addr[i]);
		putchar('\n');
		dumphex(stdout, NULL, buf, n);
	}
}
