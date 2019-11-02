
Relay message format
--
	u8    msg-type
	u8    hop-count
	ip6   link-address
	ip6   peer-address
	...   options

DHCP options are of the form
	u16   option-code
	u16   option-len
	...   option data

Input (client) interface operation
--
Listens on the input interface for DHCPv6 messages, then
resends them wrapped in a Relay-Forward message onto each
output-interface.

Only processes received traffic on input interfaces that has:
 * destination ff02::1:2
 * protocol UDP
 * destination port 547

For ethernet interfaces, this struct sock_filter can be used:
    # tcpdump -dd -i enp4s0 'ip6 dst ff02::1:2 && udp dst port 547'
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

These DHCP packet types are discarded:
ADVERTISE(2), REPLY(7), RECONFIGURE(10), RELAY-REPL(13).

RELAY-FORW(12) is also discarded unless the `-t` (trust) option is supplied,
and the hop limit (default 255) is higher than the received hop-count.
Otherwise, RELAY-FORW packets are nested, with the wrapping hop-count being
set to one more than the nested packet. (hop-count is 0 for other messages)

The Relay-forward packet always contains an `OPTION_RELAY_MSG(9)` option
containing the verbatim content of the the relayed message.

Ldra inserts the following options when forwarding messages:
  * option-18 (Interface ID)    - interface id, eg "eth0"
  * option-16 (Vendor ID)       - string describing the ldra vendor
  * option-9  (Relay Msg)       - payload of relayed message

The link-address of a constructed RELAY-FORW packet is usually :: to
comply with the RFC, but may be forced to an explicit value.
(The ldra relies on option-18 being preserved in Relay-Reply messages
to determine which interface to relay replies out on).

The wrapped packet's peer-address field is set to the source address
of the received packet.

The Relay-Forward packet transmitted to the output interface always
uses the same IP destination and link-layer source and destinations
(ie ethernet MACs) copied from the input packet. (The IPv6 source address
is a link-local address of the output interface).

Note: LDRA expects servers to unicast their Relay-reply packets back
to the link-local source address.

The packet transmitted to the output interface:
    L2 src:        <copied>
    L2 dest:       <copied>
    IPv6 src:      <local>
    IPv6 dest:     <copied>
    UDP src port:  547
    UDP dest port: 547
        u8 msg-type     = RELAY-FORW (12)
	u8 hop-count    = 0 or copy+1
	ip link-address = :: (unless overridden)
	ip peer-address = <copied from client packet src IP>
	option 9:  <copied-payload>
	option 16: <vendor-id>
	option 18: <input-interface>

Output (server) interface operation
--
The LDRA listens on the output interfaces for Relay-Reply messages,
unwraps them and resends them to the identified input interface.

LDRA only processes traffic that has:
 * a link-local scoped source address
 * a link-local scoped dest address
 * protocol UDP
 * destination port 547
And has:
 * message-type RELAY-REPLY (13)
 * an interface-ID option matching an input-interface
 * peer-address == dest address
 * link-address == :: or the overridden value

    # tcpdump -dd -i enp4s0 'ip6 dst net fe80::/10 && ip6 src net fe80::/10 && udp dst port 547'
    { 0x28, 0,  0, 0x0000000c },	/*     ldh [12] */
    { 0x15, 0, 11, 0x000086dd },	/*     jeq #0x86dd f:13 */
    { 0x20, 0,  0, 0x00000026 },	/*     ld  [38] */
    { 0x54, 0,  0, 0xffc00000 },	/*     and #0xffc00000 */
    { 0x15, 0,  8, 0xfe800000 },	/*     jeq #0xfe800000 f:13 */
    { 0x20, 0,  0, 0x00000016 },	/*     ld  [22] */
    { 0x54, 0,  0, 0xffc00000 },        /*     and #0xffc00000 */
    { 0x15, 0,  5, 0xfe800000 },	/*     jeq #0xfe800000 f:13 */
    { 0x30, 0,  0, 0x00000014 },	/*     ldb [20] */
    { 0x15, 0,  3, 0x00000011 },	/*     jeq #0x11 f:13 */
    { 0x28, 0,  0, 0x00000038 },	/*     ldh [56] */
    { 0x15, 0,  1, 0x00000223 },	/*     jeq #0x0223 f:13 */
    { 0x06, 0,  0, 0x00040000 },	/*     ret #262144 */
    { 0x06, 0,  0, 0x00000000 },	/* 13: ret #0 */

Note: the destination L2 (ethernet) address will be that of the
actual client.

LDRA always unwraps the payload, and re-sends it as a UDP/547 packet
to the peer-address. It also reuses the Relay-Reply's ipv6 source and
link-layer (ethernet) source and destination addresses in the transmitted
packet.

The packet transmitted to the input (client) interfaces:
    L2 src:        <copied>
    L2 dest:       <copied>
    IPv6 src:      <local>
    IPv6 dest:     <copied from peer-address>
    UDP src port:  547
    UDP dest port: 547
        <option-9 payload>
