/**
 * @file arp_parser.c
 * @brief Parser implementation
 */

#include <stdio.h>
#include <stddef.h>
#include <netinet/in.h>
#include <arp_parser.h>

/** ARP Protocol Operation Codes */
#define ARP_REQUEST 1
#define ARP_REPLY 2
#define RARP_REQUEST 3
#define RARP_REPLY 4
#define INARP_REQUEST 8
#define INARP_REPLY 9

/** Used as the return value of the check_opcode function
 * if the opcode could not be identified */
#define ARP_UNKNOWN 0

/** Lines with decoding of operation codes
 * (for beautiful output) */
char *opcode_str[] = {
    [1] = "ARP Request",
    "ARP Reply",
    "RARP Request",
    "RARP Reply",
    [8] = "INARP Request",
    "INARP Reply"
};

/**
 * @brief Check the validity of the operation code.
 * @internal
 *
 * @param opcode Operation code to be checked.
 *
 * @return Operation code if the check is successful, otherwise 0.
 */
uint16_t check_opcode(uint16_t opcode)
{
    switch (opcode) {
        case 1: return ARP_REQUEST;
        case 2: return ARP_REPLY;
        case 3: return RARP_REQUEST;
        case 4: return RARP_REPLY;
        case 8: return INARP_REQUEST;
        case 9: return INARP_REPLY;
        default: return ARP_UNKNOWN;
    }
}

arp_status_t parse_arp(const uint8_t *buf, size_t len, arp_packet_t *packet)
{
    if (!buf || !packet)
        return ARP_ERR_NULL_PTR;
 
    /** Check buffer length */
    if (len < ARP_ETH_IPV4_SIZE)
        return ARP_ERR_TOO_SHORT;

    /** We read the values and immediatelly translate the
     * network byte order into the host byte order */
    uint16_t hardware_type = ntohs(*(uint16_t *) (buf + 0));
    uint16_t protocol_type = ntohs(*(uint16_t *) (buf + 2));
    uint16_t opcode = ntohs(*(uint16_t *) (buf + 6));

    /** - Hardware type for Ethernet is always 1
     *  - Protocol type for IPv4 is always 0x0800 */
    if (hardware_type != 1 || protocol_type != 0x0800)
        return ARP_ERR_UNSUPPORTED;

    /** Check opcode */
    if (!check_opcode(opcode))
        return ARP_ERR_INVALID;

    uint8_t hardware_size = *(buf + 4);
    uint8_t protocol_size = *(buf + 5);

    /** Hardware size for Ethernet/IPv4 = 6
     *  Protocol size for Ethernet/IPv4 = 4 */
    if (hardware_size != 6 || protocol_size != 4)
        return ARP_ERR_UNSUPPORTED;

    /** Filling the ARP packet structure */
    packet->hardware_type = hardware_type;
    packet->protocol_type = protocol_type;
    packet->hardware_size = hardware_size;
    packet->protocol_size = protocol_size;
    packet->opcode = opcode;
    memcpy(packet->sha, buf + 8, 6);
    memcpy(packet->spa, buf + 14, 4);
    memcpy(packet->tha, buf + 18, 6);
    memcpy(packet->tpa, buf + 24, 4);

    return ARP_OK;
}

void print_arp(const arp_packet_t *packet)
{
    printf("ARP Packet:\n"
            "    %-20s %u\n"
            "    %-20s 0x%04x\n"
            "    %-20s %u\n"
            "    %-20s %u\n",
            "Hardvare type:", packet->hardware_type,
            "Protocol type:", packet->protocol_type,
            "Hardware size:", packet->hardware_size,
            "Protocol size:", packet->protocol_size);

    printf("    %-20s %u (%s)\n", "Opcode:",
            packet->opcode, opcode_str[packet->opcode]);

    printf("    %-20s %02x:%02x:%02x:%02x:%02x:%02x\n"
            "    %-20s %u.%u.%u.%u\n"
            "    %-20s %02x:%02x:%02x:%02x:%02x:%02x\n"
            "    %-20s %u.%u.%u.%u\n\n",
            "Sender MAC:", packet->sha[0], packet->sha[1], packet->sha[2],
                packet->sha[3], packet->sha[4], packet->sha[5],
            "Sender IP:", packet->spa[0], packet->spa[1], packet->spa[2],
                packet->spa[3],
            "Target MAC:", packet->tha[0], packet->tha[1], packet->tha[2],
                packet->tha[3], packet->tha[4], packet->tha[5],
            "Target IP:", packet->tpa[0], packet->tpa[1], packet->tpa[2],
                packet->tpa[3]);
}
