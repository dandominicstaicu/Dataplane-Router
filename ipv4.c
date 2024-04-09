#include "ipv4.h"

extern queue packet_q;

bool bad_checksum(struct iphdr *ip_hdr)
{
    uint16_t old_checksum = ntohs(ip_hdr->check);
    ip_hdr->check = 0;
    uint16_t new_checksum = checksum((uint16_t *)ip_hdr, sizeof(struct iphdr));

    return old_checksum != new_checksum;
}

void handle_ttl(struct iphdr *ip_hdr, char *packet, int interface)
{
    if (ip_hdr->ttl <= 1) {
        // send ICMP Time Exceeded
        send_icmp_pkt(ICMP_TIME_EXCEEDED, packet, true, interface);

        return;
    }

    ip_hdr->ttl--;
}

void handle_ipv4(void *recv_packet, int recv_len, int interface)
{
    char *packet = malloc(recv_len);
    memcpy(packet, recv_packet, recv_len);

    struct ether_header *eth_hdr = (struct ether_header *)packet;
    struct iphdr *ip_hdr = (struct iphdr *)(packet + sizeof(struct ether_header));

    if (bad_checksum(ip_hdr)) {
        // drop packet
        return;
    }

    // handle_ttl(ip_hdr, packet, interface);
    if (ip_hdr->ttl <= 1) {
        // send ICMP Time Exceeded
        send_icmp_pkt(ICMP_TIME_EXCEEDED, packet, true, interface);

        return;
    }

    ip_hdr->ttl--;

    if (ip_hdr->daddr == inet_addr(get_interface_ip(interface))) {
        // send ICMP Echo Reply
        send_icmp_pkt(ICMP_ECHO, packet, false, interface);

        return;
    }

    // search in route table
    struct route_table_entry *bst_route = lpm(ip_hdr->daddr);
    if (!bst_route) {
        // send ICMP Destination Unreachable
        send_icmp_pkt(ICMP_DEST_UNREACH, packet, false, interface);

        return;
    }

    // update ip_hdr->check
    ip_hdr->check = 0;
    uint16_t check_sum = checksum((uint16_t *)ip_hdr, sizeof(struct iphdr));
    ip_hdr->check = htons(check_sum);

    // write new address
    struct arp_table_entry *arp_entry = get_arp_entry(bst_route->next_hop);
    get_interface_mac(bst_route->interface, eth_hdr->ether_shost);

    // send ARP Request if mac cannot be found in the table
    if (!arp_entry) {
        queue_enq(packet_q, packet);
        send_arp_broadcast(packet, bst_route->interface);

        return;
    }
    memcpy(eth_hdr->ether_dhost, arp_entry->mac, MAC_SIZE * sizeof(uint8_t));

    // send packet
    send_to_link(bst_route->interface, packet, recv_len);
}

