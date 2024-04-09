#include "icmp.h"

void init_eth(struct ether_header *eth_hdr, struct ether_header *old_eth_hdr)
{
    char d_mac[MAC_SIZE], s_mac[MAC_SIZE];
    memcpy(d_mac, old_eth_hdr->ether_dhost, sizeof(char) * MAC_SIZE);
    memcpy(s_mac, old_eth_hdr->ether_shost, sizeof(char) * MAC_SIZE);

    memcpy(eth_hdr->ether_dhost, s_mac, sizeof(char) * MAC_SIZE);
	memcpy(eth_hdr->ether_shost, d_mac, sizeof(char) * MAC_SIZE);
	eth_hdr->ether_type = htons(ETHERTYPE_IP);
}

void init_ipv4(struct iphdr *ip_hdr, struct iphdr *old_ip_hdr)
{
	memset(ip_hdr, 0, sizeof(struct iphdr));
	memcpy(&ip_hdr->daddr, &old_ip_hdr->saddr, sizeof(uint32_t));
	memcpy(&ip_hdr->saddr, &ip_hdr->daddr, sizeof(uint32_t));
	ip_hdr->ihl = 5;
	ip_hdr->id = htons(1);
	ip_hdr->version = 4;

    size_t tot_len = sizeof(struct iphdr) + sizeof(struct icmphdr);

	ip_hdr->tot_len = htons(tot_len);
	ip_hdr->ttl = 64;
	ip_hdr->protocol = 1;
}

void init_icmp(struct icmphdr *icmp_hdr, uint8_t type)
{
    memset(icmp_hdr, 0, sizeof(struct icmphdr));
	icmp_hdr->type = type;
	icmp_hdr->checksum = htons(checksum((uint16_t *)icmp_hdr, sizeof(struct icmphdr)));

}

void send_icmp_pkt(uint8_t type, void *old_pkt, bool error, int interface) {
    int total_len = 0;

    // Create a new ICMP packet
    char icmp_packet_buf[MAX_PACKET_LEN];

    // Ethernet header setup
    struct ether_header *new_eth_hdr = (struct ether_header *)icmp_packet_buf;
    struct ether_header *old_eth_hdr = (struct ether_header *)old_pkt;
    
    init_eth(new_eth_hdr, old_eth_hdr);

    size_t offset_eth = sizeof(struct ether_header);

    // IPv4 header setup
    struct iphdr *new_ip_hdr = (struct iphdr *)(icmp_packet_buf + offset_eth);
    struct iphdr *old_ip_hdr = (struct iphdr *)((char *)old_pkt + offset_eth);

    init_ipv4(new_ip_hdr, old_ip_hdr);

    size_t offset_ip = offset_eth + sizeof(struct iphdr);

    // ICMP header setup
    struct icmphdr *new_icmp_hdr = (struct icmphdr *)(icmp_packet_buf + offset_ip);

    init_icmp(new_icmp_hdr, type);

    size_t offset_icmp = offset_ip + sizeof(struct icmphdr);

    uint16_t checksum_val = 0;

    // Depending on the error flag, prepare the ICMP message body differently
    if (error) {
        total_len = 8; // Initial extra data length
        memcpy(icmp_packet_buf + offset_icmp, old_ip_hdr, sizeof(struct iphdr));
        memcpy(icmp_packet_buf + offset_icmp + sizeof(struct iphdr), old_ip_hdr + 1, 8); // Copy the first 8 bytes of the original payload
        new_ip_hdr->tot_len = htons(sizeof(struct iphdr) + sizeof(struct icmphdr) + total_len);
    } else {
        struct icmphdr *old_icmp_hdr = (struct icmphdr *)((char *)old_ip_hdr + sizeof(struct iphdr));
        new_icmp_hdr->un.echo.id = old_icmp_hdr->un.echo.id;
        new_icmp_hdr->un.echo.sequence = old_icmp_hdr->un.echo.sequence;

        checksum_val = checksum((uint16_t *)new_icmp_hdr, sizeof(struct icmphdr));
        new_icmp_hdr->checksum = htons(checksum_val);
    }

    new_ip_hdr->check = 0;
    checksum_val = checksum((uint16_t *)new_ip_hdr, sizeof(struct iphdr));
    new_ip_hdr->check = htons(checksum_val);

    // Calculate the total length of the ICMP packet and send it
    total_len += sizeof(struct ether_header) + sizeof(struct iphdr) + sizeof(struct icmphdr);
    send_to_link(interface, icmp_packet_buf, total_len);
}

