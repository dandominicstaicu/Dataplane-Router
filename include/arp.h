#ifndef _ARP_H_
#define _ARP_H_

#include "protocols.h"
#include "lib.h"
#include "lpm.h"
#include "queue.h"

#include <string.h>

struct arp_table_entry *get_arp_entry(uint32_t given_ip);

void send_arp_broadcast(void *old_packet, int interface);

void handle_arp(void *old_packet, int interface);

void arp_reply_handler(void *old_packet);

void arp_request_handler(struct arp_header *old_arp_hdr, void *old_packet, int interface);



#endif