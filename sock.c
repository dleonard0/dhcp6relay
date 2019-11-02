#include <err.h>
#include <errno.h>
#include <unistd.h>

#include <arpa/inet.h> /* htons */
#include <linux/filter.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <sys/socket.h>
#include <sys/types.h>

#include "sock.h"

#define lengthof(A) (sizeof (A) / sizeof (A)[0])

/*
 * DHCPv6 filter for client-facing ethernet interfaces.
 * [sll_hatype == ARPHRD_ETHER]
 */
static struct sock_filter ether_client_filter[] = {
	/* "ip6 dst ff02::1:2 && udp dst port 547" */
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
const struct sock_fprog ether_client_fprog = {
	lengthof(ether_client_filter),
	ether_client_filter
};

/*
 * DHCPv6 filter for server-facing ethernet interfaces
 * [sll_hatype == ARPHRD_ETHER]
 */
static struct sock_filter ether_server_filter[] = {
	/* "ip6 dst net fe80::/10 && ip6 src net fe80::/10 && udp dst port 547" */
	{ 0x28, 0, 0, 0x0000000c },
	{ 0x15, 0, 11, 0x000086dd },
	{ 0x20, 0, 0, 0x00000026 },
	{ 0x54, 0, 0, 0xffc00000 },
	{ 0x15, 0, 8, 0xfe800000 },
	{ 0x20, 0, 0, 0x00000016 },
	{ 0x54, 0, 0, 0xffc00000 },
	{ 0x15, 0, 5, 0xfe800000 },
	{ 0x30, 0, 0, 0x00000014 },
	{ 0x15, 0, 3, 0x00000011 },
	{ 0x28, 0, 0, 0x00000038 },
	{ 0x15, 0, 1, 0x00000223 },
	{ 0x6, 0, 0, 0x00040000 },
	{ 0x6, 0, 0, 0x00000000 },
};
const struct sock_fprog ether_server_fprog = {
	lengthof(ether_server_filter),
	ether_server_filter
};


int
sock_open(unsigned int ifindex, const struct sock_fprog *fprog)
{
	if (!ifindex) {
		errno = EINVAL;
		return -1;
	}

	int s = socket(AF_PACKET, SOCK_RAW, 0);
	if (s == -1) {
		warn("socket");
		return -1;
	}

	struct sockaddr_ll sll = {
	    .sll_family = AF_PACKET,
	    .sll_protocol = htons(ETH_P_IPV6),
	    .sll_ifindex = ifindex
	};
	if (bind(s, (struct sockaddr *)&sll, sizeof sll) == -1) {
		warn("bind");
		goto fail;
	}

	struct packet_mreq mreq = {
	    .mr_ifindex = ifindex,
	    .mr_type = PACKET_MR_PROMISC
	};
	if (setsockopt(s, SOL_PACKET, PACKET_ADD_MEMBERSHIP,
	    &mreq, sizeof mreq) == -1)
	{
		warn("setsockopt MR_PROMISC");
		goto fail;
	}

	if (fprog && setsockopt(s, SOL_SOCKET, SO_ATTACH_FILTER, fprog,
	    sizeof *fprog) == -1)
	{
		warn("setsockopt SO_ATTACH_FILTER");
		goto fail;
	}

	return s;

fail:
	(void) close(s);
	return -1;
}
