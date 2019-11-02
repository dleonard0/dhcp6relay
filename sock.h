struct sock_fprog;

/* 802.3 packet filters for DHCPv6 client and server messages */
extern const struct sock_fprog ether_client_fprog;
extern const struct sock_fprog ether_server_fprog;

/* Opens an AF_PACKET socket on the interface and attaches a packet filter */
int sock_open(unsigned int ifindex, const struct sock_fprog *fprog);
