#ifndef _ICMP_H_
#define _ICMP_H_

#include "lib.h"
#include "protocols.h"

#include <string.h>

void send_icmp_pkt(uint8_t type, void *old_pkt, bool error, int interface);

void init_eth(struct ether_header *eth_hdr, struct ether_header *old_eth_hdr);

void init_ipv4(struct iphdr *ip_hdr, struct iphdr *old_ip_hdr);

void init_icmp(struct icmphdr *icmp_hdr, uint8_t type);


#endif