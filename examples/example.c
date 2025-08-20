/**
 * @file example.c
 * @brief file in example usage
 */

#include <stdio.h>
#include <arp_parser.h>

/** Two test packages */
uint8_t test_arp_packet[] = {
    0x00, 0x01, 0x08, 0x00, 0x06, 0x04, 0x00, 0x01,
    0x08, 0x00, 0x27, 0x12, 0x34, 0x56, 0xC0, 0xA8,
    0x01, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0xC0, 0xA8, 0x01, 0x02
};

uint8_t arp_req[] = {
    0x00, 0x01,             // htype = Ethernet
    0x08, 0x00,             // ptype = IPv4
    0x06,                   // hlen = 6 (MAC)
    0x04,                   // plen = 4 (IPv4)
    0x00, 0x01,             // opcode = 1 (ARP Request)
    0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, // sha (sender MAC)
    192, 168, 0, 10,        // spa = 192.168.0.10
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // tha = 00:00:00:00:00:00
    192, 168, 0, 1          // tpa = 192.168.0.1
};

int main(void)
{
    arp_packet_t packet_1;
    arp_packet_t packet_2;

    /** Parse packets and output data in a readable from */
    if (parse_arp(arp_req, sizeof(arp_req), &packet_2) == ARP_OK)
        print_arp(&packet_2);

    if (parse_arp(test_arp_packet, sizeof(test_arp_packet), &packet_1) == ARP_OK)
        print_arp(&packet_1);

    return 0;
}
