# Dataplane Router

### Copyright
**Dan-Dominic Staicu**
**321CAb**

## Description
This project focuses on implementing a router, as per the following tasks that have been completed:

- Routing process
- ARP (Address Resolution Protocol)
- ICMP (Internet Control Message Protocol)
- Longest Prefix Match (LPM) efficiency using Binary Search

## Implementation

When recieving a packet, the program extracts the Ether Header and checks:
1. Packet's destination, whether it's for the router or is a broadcast;
2. If the packet has an IPv4 or ARP protocol.

## IPv4 packet

- When the router recieves an IP message, check the integrity;
- Verify the **checksum**: recalculate the checksum of the packet and drop it if the newly computed checksum doesn't match;
- Check the **TTL** field of the IP header; if it's <= 1, drop the packet and send back an error ICMP - *"Time exceeded"*;
- Check if the router is the destination, or it has to forward the packet;
- If the router is the destination => it was an **ICMP echo request (ping)**; the router has to create an ICMP **(echo reply)** and send it back to the host;
- In order to forward the packet to the destination, update the **L2 header** by decrementing the *TTL* and recalculating the *checksum* and find the best route by using the **LMP** algorithm;
- If no route is found, the router sends an **ICMP destination unreachable** error packet;
- Else, the router needs the *MAC address* for the next hop of the packet;
- If the *MAC address* is not available in the routing table, the router sends an *ARP request*;
- Else, just send the packet forward to the next hop

## ARP

- **ARP REPLY** 
    - If an *ARP REPLY* packet is recieved by the router the *IP* address and *MAC* address of the sender will be added to the *ARP table* of the router;
    - The router checks the queue of the waiting packets and forwards the packets with known *MAC* addresses of the next hop;

- **ARP REQUEST**
    - The router sends an *ARP reply* with its *MAC* address to the host

- **ARP REQUEST BROADCAST**
    - The *MAC* address of the next hop is not found in the *ARP table* so the router has to send a request on the interface of the best route in order to get the necesary *MAC* addresses

## ICMP

- There are 3 posssible scenarios when an ICMP is sent:
    1. Timeout;
    2. Destination unreachable;
    3. Echo reply;

- The structure of an ICMP packet contains an *ethernet header, ip header and an ICMP header*;

## Longest Prefix Match

- This uses binery search in order to find the match in the routing table faster than linear seach;

- The routing table sorts the entries based on their masked prefixes and in case these are equal by the mask value itself;


