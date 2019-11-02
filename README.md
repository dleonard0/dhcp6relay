
Lightweight DHCPv6 Relay Agent
==

This is a stateless DHCPv6 relay for Linux

Usage
---

	dhcp6relay [-v]
	     -i <input-interface>
	     -o <output-interface>

Operation
----

DHCPv6 client on input interfaces will be relayed to servers on
output interfaces.  See RFC 6221 for details.

If the process receives a SIGHUP, it will re-read the interfaces
to update the link-local addresses and interface indicies.


Packet requirements
----

A client packet is relayed to all servers interfaces if it has:
 * destination ff02::1:2
 * protocol UDP
 * destination port 547
 * and are not one of ADVERTISE(2), REPLY(7), RECONFIGURE(10), RELAY-REPL(13).

A server's reply is relayed to a client if it has:
 * a link-local scoped source address
 * a link-local scoped dest address
 * protocol UDP
 * destination port 547
 * DHCPv6 message-type RELAY-REPLY (13)
 * an interface-ID option matching an input-interface
 * link-address == ::

When the client receives this message, it will switch to communicating
to the server with unicast packets.

