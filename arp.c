#include "arp.h"

/* ARP table */
extern struct arp_table_entry *arp_table;
extern int arp_table_capacity;
extern int arp_table_size;

extern queue packet_q;

struct arp_table_entry *get_arp_entry(uint32_t ip)
{
	// Iterate through the ARP table and search for the IP
	for (int i = 0; i < arp_table_size; ++i)
		if (arp_table[i].ip == ip)
			return &arp_table[i];

	return NULL;
}

void send_arp_broadcast(void *old_pkt, int interface)
{
	// create ARP request packet
	char new_arp_packet[MAX_PACKET_LEN];

	// ether header
	struct ether_header *eth_hdr = (struct ether_header *)new_arp_packet;
	eth_hdr->ether_type = htons(ETHERTYPE_ARP);
	get_interface_mac(interface, eth_hdr->ether_shost);

	// broadcast MAC address
	for (int i = 0; i < MAC_SIZE; i++)
		eth_hdr->ether_dhost[i] = 0xFF;

	// ARP header
	struct arp_header arp_hdr;
	arp_hdr.htype = htons(REQUEST_OP);
	arp_hdr.ptype = htons(ETHERTYPE_IP);
	arp_hdr.hlen = 6;
	arp_hdr.plen = 4;
	arp_hdr.op = htons(1);
	memcpy(arp_hdr.sha, eth_hdr->ether_shost, sizeof(uint8_t) * MAC_SIZE);
	arp_hdr.spa = inet_addr(get_interface_ip(interface));
	memset(arp_hdr.tha, 0, sizeof(uint8_t) * MAC_SIZE);
	struct iphdr *ip_hdr = (struct iphdr *)(old_pkt + sizeof(struct ether_header));
	struct route_table_entry *entry_rtable = lpm(ip_hdr->daddr);
	arp_hdr.tpa = entry_rtable->next_hop;

	memcpy(new_arp_packet + sizeof(struct ether_header), &arp_hdr, sizeof(struct arp_header));

	int len = sizeof(struct ether_header) + sizeof(struct arp_header);

	// send ARP packet
	send_to_link(entry_rtable->interface, new_arp_packet, len);
}

void handle_arp(void *old_pkt, int interface)
{
	struct arp_header *old_arp_hdr = (struct arp_header *)(old_pkt + sizeof(struct ether_header));

	// reply packet
	if (old_arp_hdr->op == htons(REPLY_OP)) {
		arp_reply_handler(old_pkt);
	} else if (old_arp_hdr->op == htons(REQUEST_OP)) {
		arp_request_handler(old_arp_hdr, old_pkt, interface);
	}
}

void arp_request_handler(struct arp_header *old_arp_hdr, void *old_packet, int interface)
{
	if (old_arp_hdr->tpa != inet_addr(get_interface_ip(interface)))
		return;

	char reply_arp_packet[MAX_PACKET_LEN];

	struct ether_header *eth_hdr = (struct ether_header *)reply_arp_packet;
	struct ether_header *old_eth_hdr = (struct ether_header *)old_packet;
	eth_hdr->ether_type = htons(ETHERTYPE_ARP);
	get_interface_mac(interface, eth_hdr->ether_shost);
	memcpy(eth_hdr->ether_dhost, old_eth_hdr->ether_shost, sizeof(u_int8_t) * MAC_SIZE);

	// arp header
	struct arp_header arp_hdr;
	arp_hdr.htype = htons(1);
	arp_hdr.ptype = htons(ETHERTYPE_IP);
	arp_hdr.hlen = 6;
	arp_hdr.plen = 4;
	arp_hdr.op = htons(REPLY_OP);
	memcpy(arp_hdr.sha, eth_hdr->ether_shost, sizeof(uint8_t) * MAC_SIZE);
	arp_hdr.spa = inet_addr(get_interface_ip(interface));
	memcpy(arp_hdr.tha, old_arp_hdr->sha, sizeof(uint8_t) * MAC_SIZE);
	arp_hdr.tpa = old_arp_hdr->spa;

	memcpy(reply_arp_packet, eth_hdr, sizeof(struct ether_header));
	memcpy(reply_arp_packet + sizeof(struct ether_header), &arp_hdr, sizeof(struct arp_header));

	// send packet
	int len = sizeof(struct ether_header) + sizeof(struct arp_header);
	send_to_link(interface, reply_arp_packet, len);
	return;
}

void update_arp_table(void *packet)
{
	// update local arp table
	struct arp_header *arp_hdr = (struct arp_header *)(packet + sizeof(struct ether_header));
	arp_table[arp_table_size].ip = arp_hdr->spa;
	memcpy(arp_table[arp_table_size].mac, arp_hdr->sha, sizeof(uint8_t) * MAC_SIZE);

	// check capacity of arp table
	arp_table_size++;
	if (arp_table_capacity == arp_table_size) {
		void *aux = realloc(arp_table, 2 * arp_table_capacity * sizeof(struct arp_table_entry));
		DIE(aux == NULL, "realloc");
		arp_table_capacity *= 2;
		arp_table = (struct arp_table_entry *)aux;
	}
}

void arp_reply_handler(void *incoming_packet) {
    update_arp_table(incoming_packet);

    // Processing each packet in the queue
    while (!queue_empty(packet_q)) {
        char *current_packet = (char *)queue_deq(packet_q);

        // Extract the Ethernet and IP headers from the packet
        struct ether_header *eth_hdr = (struct ether_header *)current_packet;
        struct iphdr *ip_header = (struct iphdr *)(current_packet + sizeof(struct ether_header));

        // Find the routing table entry using the destination IP address
        struct route_table_entry *route_entry = lpm(ip_header->daddr);

        // Recalculate the IP header checksum
        ip_header->check = 0; // Reset checksum to 0 before calculation
        uint16_t check_sum = checksum((uint16_t *)ip_header, sizeof(struct iphdr));
		ip_header->check = htons(check_sum);

        // Attempt to find a corresponding ARP entry
        struct arp_table_entry *arp_entry = get_arp_entry(route_entry->next_hop);

		if (arp_entry) {
            // Update the destination MAC address in the Ethernet header
            memcpy(eth_hdr->ether_dhost, arp_entry->mac, MAC_SIZE * sizeof(uint8_t));

            // Calculate the total length of the packet
            int total_length = sizeof(struct ether_header) + sizeof(struct iphdr) + sizeof(struct icmphdr);
            
            // Send the packet over the specified interface
            send_to_link(route_entry->interface, current_packet, total_length);

            // Free the memory allocated for the packet and exit the loop
            free(current_packet);
            break; // Exit after processing the first matching packet
        }
    }
}

