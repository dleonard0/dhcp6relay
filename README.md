
Lightweight DHCPv6 Relay Agent
==

This is a stateless DHCPv6 relay for Linux.

Usage
---

	dhcp6relay [-v]
	     [-i <input-interface>]...
	     [-o <output-interface>]...

Operation
----

*dhcp6relay* listens for DHCPv6 clients on the named input interfaces and
relays their requests to the DHCPv6 servers on the output interfaces.

Eventually, successful clients will switch to communicating with the
servers using IPv6 unicast packets, which do not need relaying.

If *dhcp6relay* receives a SIGHUP signal, then it will re-open the interfaces,
refreshing the link-local addresses and interface indicies that it had found
before.

The `-v` option increases verbosity.

Filter rules
----

Because *dhcp6relay* uses Linux's `AF_PACKET` sockets, it will not subject to
firewall rules.  Instead, it uses the following filter processes.

A DHCPv6 client packet is only accepted on an input interface for relaying
when it has:
 * destination address ff02::1:2
 * protocol UDP
 * destination port 547
 * message-type is not one of ADVERTISE(2), REPLY(7), RECONFIGURE(10),
   or RELAY-REPL(13).

A DHCPv6 server reply packet from an output interface is only relayed back to
a client if it has:
 * a link-local scoped source address
 * a link-local scoped dest address
 * protocol UDP
 * destination port 547
 * message-type RELAY-REPLY(13)
 * an interface-ID option matching a listed input-interface
 * link-address field set to ::

