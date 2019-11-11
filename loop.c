#include <err.h>
#include <errno.h>
#include <ifaddrs.h>
#include <unistd.h>

#include <linux/if.h>
#include <netinet/in.h>
#include <sys/poll.h>
#include <sys/types.h>

#include "dhcp.h"
#include "ifc.h"
#include "loop.h"
#include "pkt.h"
#include "sock.h"
#include "verbose.h"

volatile int loop_stop;

/* Opens sockets on all interfaces, then
 * enters a loop relaying DHCPv6 packets
 * between them, until loop_stop is set. */
void
relay_loop(struct ifc *ifc, unsigned int nifc)
{
	/* A parallel array of poll structures */
	struct pollfd pfd[nifc];

	/* Connect each interface's packet socket */
	for (unsigned i = 0; i < nifc; i++) {
		pfd[i].revents = 0;
		pfd[i].fd = sock_open(ifc[i].index,
		    ifc[i].side == CLIENT
		    ? &ether_client_fprog
		    : &ether_server_fprog);
		if (pfd[i].fd == -1) {
			warnx("%s: ignored", ifc[i].name);
			pfd[i].fd = -1;
			pfd[i].events = 0;
		} else {
			pfd[i].events = POLLIN;
		}
	}

	struct pkt pkt = PKT_INIT;
	while (!loop_stop) {
		int n = poll(pfd, nifc, -1);
		if (n == -1) {
			if (errno == EINTR)
				continue;
			warn("poll");
			break;
		}

		for (unsigned i = 0; n && i < nifc; i++) {
			/* interface name for error messages */
			const char *ifname = ifc[i].name;
			short revents = pfd[i].revents;

			pfd[i].revents = 0;
			if (!revents)
				continue;
			n--;

			if (revents & (POLLERR|POLLHUP|POLLNVAL)) {
				/* Handle socket errors */
				warn("%s: error, closing", ifname);
close:
				/* Close the socket */
				close(pfd[i].fd);
				pfd[i].fd = -1;
				pfd[i].events = revents = 0;
			}
			if (!(revents & POLLIN))
				continue; /* Silent socket */

			/* Receive a UDPv6 packet */
			int len = pkt_recv(pfd[i].fd, &pkt);
			if (len <= 0) {
				if (len == 0)
				    warnx("%s recvfrom: closed", ifname);
				else
				    warn("%s recvfrom", ifname);
				goto close;
			}
			if (pkt_scan_udp(&pkt) == -1)
				continue; /* Not IPv6 UDP */

			switch (ifc[i].side) {
			case CLIENT:
				/* Handle client->server relay */
				if (dhcp_wrap(&pkt, &ifc[i]) == -1)
					continue;
				verbose2("%s: message from client %s\n",
				    ifc[i].name, pkt_lladdr(&pkt));
				for (unsigned j = 0; j < nifc; j++)
					if (ifc[j].side == SERVER &&
					    pfd[j].fd != -1)
					{
						verbose(
						    "%s->%s: relaying client %s\n",
						    ifc[i].name, ifc[j].name,
                                                    pkt_lladdr(&pkt));
						pkt.ip6_hdr->ip6_src = ifc[j].addr;
						pkt_send(pfd[j].fd, &pkt);
					}
				break;
			case SERVER: ;
				/* Handle server->client relay */
				char name[IFNAMSIZ];
				char addrbuf[INET6_ADDRSTRLEN];
				if (dhcp_unwrap(&pkt, &ifc[i], name) == -1)
					continue;
				verbose2("%s: message from server %s\n",
				    ifc[i].name, pkt_lladdr(&pkt));
				unsigned j;
				for (j = 0; j < nifc; j++)
					if (ifc[j].side == CLIENT &&
					    pfd[j].fd != -1 &&
					    strncmp(ifc[j].name, name,
					        IFNAMSIZ) == 0)
						    break;
				if (j < nifc) {
				        /* Found matching interface j */
					verbose(
					    "%s<-%s: server %s reply to %s\n",
					    ifc[j].name, ifc[i].name,
					    pkt_lladdr(&pkt),
					    inet_ntop(AF_INET6,
						&pkt.ip6_hdr->ip6_dst,
						addrbuf, sizeof addrbuf));
					pkt.ip6_hdr->ip6_src = ifc[j].addr;
					pkt_send(pfd[j].fd, &pkt);
				} else {
					warnx("%s: unexpected interface-id %.*s from %s",
					    ifc[i].name, IFNAMSIZ, name, pkt_lladdr(&pkt));
				}
				break;
			case NONE:
				; /* ignore */
			}
		}
	}

	/* Close everything */
	for (unsigned i = 0; i < nifc; i++)
		if (pfd[i].fd != -1)
			close(pfd[i].fd);

}
