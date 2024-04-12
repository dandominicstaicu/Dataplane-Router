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
	memset(ip_hdr, 0, IPHDR_LEN);

	ip_hdr->ihl = 5;

    size_t tot_len = IPHDR_LEN + ICMPHDR_LEN;

	ip_hdr->tot_len = htons(tot_len);
	ip_hdr->id = htons(1);
	ip_hdr->ttl = TTL;
	ip_hdr->protocol = 1;

	memcpy(&ip_hdr->daddr, &old_ip_hdr->saddr, sizeof(uint32_t));
	memcpy(&ip_hdr->saddr, &ip_hdr->daddr, sizeof(uint32_t));
}

void init_icmp(struct icmphdr *icmp_hdr, uint8_t type)
{
    memset(icmp_hdr, 0, ICMPHDR_LEN);
	icmp_hdr->type = type;
	icmp_hdr->checksum = htons(checksum((uint16_t *)icmp_hdr, ICMPHDR_LEN));

}

void send_icmp_pkt(uint8_t type, void *old_pkt, bool error, int interface) {
    int total_len = 0;

    // Create a new ICMP packet
    char icmp_packet_buf[MAX_PACKET_LEN];

    // Ethernet header setup
    struct ether_header *new_eth_hdr = (struct ether_header *)icmp_packet_buf;
    struct ether_header *old_eth_hdr = (struct ether_header *)old_pkt;
    
    init_eth(new_eth_hdr, old_eth_hdr);

    // IPv4 header setup
    struct iphdr *new_ip_hdr = (struct iphdr *)(icmp_packet_buf + ETH_LEN);
    struct iphdr *old_ip_hdr = (struct iphdr *)((char *)old_pkt + ETH_LEN);

    init_ipv4(new_ip_hdr, old_ip_hdr);

    size_t offset_ip = ETH_LEN + IPHDR_LEN;

    // ICMP header setup
    struct icmphdr *new_icmp_hdr = (struct icmphdr *)(icmp_packet_buf + offset_ip);

    init_icmp(new_icmp_hdr, type);

    size_t offset_icmp = offset_ip + ICMPHDR_LEN;

    uint16_t checksum_val = 0;

    // Depending on the error flag, prepare the ICMP message body differently
    if (error) {
        total_len = 8; // Initial extra data length
        memcpy(icmp_packet_buf + offset_icmp, old_ip_hdr, IPHDR_LEN);
        memcpy(icmp_packet_buf + offset_icmp + IPHDR_LEN, old_ip_hdr + 1, 8); // Copy the first 8 bytes of the original payload
        new_ip_hdr->tot_len = htons(IPHDR_LEN + ICMPHDR_LEN + total_len);
    } else {
        struct icmphdr *old_icmp_hdr = (struct icmphdr *)((char *)old_ip_hdr + IPHDR_LEN);
        new_icmp_hdr->un.echo.id = old_icmp_hdr->un.echo.id;
        new_icmp_hdr->un.echo.sequence = old_icmp_hdr->un.echo.sequence;

        checksum_val = checksum((uint16_t *)new_icmp_hdr, ICMPHDR_LEN);
        new_icmp_hdr->checksum = htons(checksum_val);
    }

    new_ip_hdr->check = 0;
    checksum_val = checksum((uint16_t *)new_ip_hdr, IPHDR_LEN);
    new_ip_hdr->check = htons(checksum_val);

    // Calculate the total length of the ICMP packet and send it
    total_len += ETH_LEN + IPHDR_LEN + ICMPHDR_LEN;
    send_to_link(interface, icmp_packet_buf, total_len);
}
