#include "queue.h"
#include "lib.h"
#include "protocols.h"
#include "ipv4.h"

// ARP table
struct arp_entry *arp_table;
int arp_table_capacity;
int arp_table_size;

/* Routing table */
struct route_table_entry rtable[800000];
int rtable_len;


queue packet_q;

bool bad_dest_addr(struct ether_header *eth_hdr, uint8_t *mac) {
	for (int i = 0; i < MAC_SIZE; i++) {
		if (eth_hdr->ether_dhost[i] != mac[i] &&
			eth_hdr->ether_dhost[i] != 0xFF)
			return true;
	}

	return false;
}

// Compare function for routing table sort
int sort_rtable_entries(const void *elem1, const void *elem2)
{
    struct route_table_entry *entry1 = (struct route_table_entry *)elem1;
    struct route_table_entry *entry2 = (struct route_table_entry *)elem2;
    uint32_t masked_prefix1 = entry1->prefix & entry1->mask;
    uint32_t masked_prefix2 = entry2->prefix & entry2->mask;

    // First, compare the masked prefixes
    if (masked_prefix1 < masked_prefix2) {
        return -1;
    } else if (masked_prefix1 > masked_prefix2) {
        return 1;
    } else {
        // If the prefixes are equal, compare the masks
        if (entry1->mask < entry2->mask) {
            return -1;
        } else if (entry1->mask > entry2->mask) {
            return 1;
        } else {
            return 0;
        }
    }
}


int main(int argc, char *argv[])
{
	char buf[MAX_PACKET_LEN];

	packet_q = queue_create();

	// Do not modify this line
	init(argc - 2, argv + 2);

	// alloc mem for the route table
	arp_table_capacity = ARP_CAPACITY_DEFAULT;
	arp_table = malloc(sizeof(struct arp_entry *) * arp_table_capacity);
	DIE(arp_table == NULL, "malloc");

	rtable_len = read_rtable(argv[1], rtable);
	qsort(rtable, rtable_len, sizeof(struct route_table_entry), sort_rtable_entries);

	while (1) {

		int interface;
		size_t len;

		interface = recv_from_any_link(buf, &len);
		DIE(interface < 0, "recv_from_any_links");

		struct ether_header *eth_hdr = (struct ether_header *) buf;

		uint16_t ether_type = ntohs(eth_hdr->ether_type);
		if (ether_type != ETHERTYPE_IP && ether_type != ETHERTYPE_ARP) {
			continue;
		}

		uint8_t mac[MAC_SIZE] = {0};
		get_interface_mac(interface, mac);
		
		if (bad_dest_addr(eth_hdr, mac)) {
			continue;
		}

		if (ether_type == ETHERTYPE_IP) {
			handle_ipv4(buf, len, interface);


		} else if (ether_type == ETHERTYPE_ARP) {
			// handle_arp(buf, len, interface);
			handle_arp(buf, interface);

			
			continue;
		}


	}

	return 0;
}

