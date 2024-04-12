#ifndef _IPV4_H_
#define _IPV4_H_

#include "protocols.h"
#include "lib.h"
#include "queue.h"
#include "icmp.h"
#include "lpm.h"
#include "arp.h"

#include <string.h>

void handle_ipv4(void *recv_packet, int recv_len, int interface);

bool bad_checksum(struct iphdr *ip_hdr);

char *alloc_packet(void *recv_packet, int recv_len);

#endif
