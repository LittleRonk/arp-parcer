/**
 * @file main_tests.c
 * @brief Testing the parser.
 */

#include <stdio.h>
#include <assert.h>
#include <arp_parser.h>
#include "test_packets.h"

int main(void)
{
    arp_packet_t pct;

    assert(parse_arp(test_arp_packet, sizeof(test_arp_packet), &pct) == ARP_OK);
    assert(parse_arp(arp_req, sizeof(arp_req), &pct) == ARP_OK);
    assert(parse_arp(arp_rep, sizeof(arp_rep), &pct) == ARP_OK);
    printf("Parsing valid ARP packets: OK\n");

    assert(parse_arp(arp_bad_short, sizeof(arp_bad_short), &pct) == ARP_ERR_TOO_SHORT);
    printf("Parsing a broken ARP packet (too short): OK\n");

    assert(parse_arp(arp_bad_htype, sizeof(arp_bad_htype), &pct) == ARP_ERR_UNSUPPORTED);
    assert(parse_arp(arp_bad_ptype, sizeof(arp_bad_ptype), &pct) == ARP_ERR_UNSUPPORTED);
    printf("Parsing ARP packets of unsupported type: OK\n");

    assert(parse_arp(arp_bad_opcode, sizeof(arp_bad_opcode), &pct) == ARP_ERR_INVALID);
    printf("Parcing ARP packet with invalid opcode: OK\n");

    printf("All tests passed.\n");

    return 0;
}
