/**
 * @file test_packets.h
 * @brief Examples of ARP packets for testing.
 */

#ifndef TEST_PACKETS_H
#define TEST_PACKETS_H

/** Test ARP packet from akber-soft */
uint8_t test_arp_packet[] = {
    0x00, 0x01, 0x08, 0x00, 0x06, 0x04, 0x00, 0x01,
    0x08, 0x00, 0x27, 0x12, 0x34, 0x56, 0xC0, 0xA8,
    0x01, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0xC0, 0xA8, 0x01, 0x02
};

/** Correct ARP request */
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

/** Correct ARP reply */
uint8_t arp_rep[] = {
    0x00, 0x01,             // Ethernet
    0x08, 0x00,             // IPv4
    0x06,                   // hlen
    0x04,                   // plen
    0x00, 0x02,             // opcode = 2 (ARP Reply)
    0x11, 0x22, 0x33, 0x44, 0x55, 0x66, // sha
    192, 168, 0, 1,         // spa
    0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, // tha
    192, 168, 0, 10         // tpa
};

/** Broken ARP packet (too short) */
uint8_t arp_bad_short[] = {
    0x00, 0x01, 0x08, 0x00, 0x06, 0x04, 0x00, 0x01,
    0xaa, 0xbb
};

/** ARP packet with unsupported hardware type */
uint8_t arp_bad_htype[] = {
    0x00, 0x02,             // htype = 2 (Not Ethernet)
    0x08, 0x00,             // IPv4
    0x06,                   // hlen
    0x04,                   // plen
    0x00, 0x01,             // ARP Request
    0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff,
    192, 168, 0, 10,
    0, 0, 0, 0, 0, 0,
    192, 168, 0, 1
};

/** ARP packet with unsupported protocol type */
uint8_t arp_bad_ptype[] = {
    0x00, 0x01,             // Ethernet
    0x86, 0xdd,             // IPv6 (Not IPv4)
    0x06,                   // hlen
    0x04,                   // plen
    0x00, 0x01,             // ARP Request
    0xde, 0xad, 0xbe, 0xef, 0x00, 0x01,
    192, 168, 1, 5,
    0, 0, 0, 0, 0, 0,
    192, 168, 1, 1
};

/** ARP packet with unknown opcode */
uint8_t arp_bad_opcode[] = {
    0x00, 0x01,
    0x08, 0x00,
    0x06,
    0x04,
    0x00, 0x05,             // opcode = 5
    0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff,
    192, 168, 0, 10,
    0, 0, 0, 0, 0, 0,
    192, 168, 0, 1
};

#endif /** TEST_PACKETS_H */
