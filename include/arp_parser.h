/**
 * @file arp_parser.h
 * @brief Declarations of structures and functions for the ARP packet parser.
 */

#ifndef ARP_PARSER_H
#define ARP_PARSER_H

#include <stddef.h>
#include <string.h>
#include <stdint.h>

/** ARP packet length when using Ethernet/IPv4 */
#define ARP_ETH_IPV4_SIZE 28

/** Parsing function status codes */
typedef enum {
    ARP_OK = 0,             /** Successful parsing */
    ARP_ERR_NULL_PTR,       /** Pointer to NULL passed */
    ARP_ERR_TOO_SHORT,      /** Buffer is less than minimum size */
    ARP_ERR_UNSUPPORTED,    /** Unsupported hardware_size/protocol_size */
    ARP_ERR_INVALID         /** Broken or invalid packet */
} arp_status_t;

/**
 * @brief Strructure for representing an ARP packet.
 *
 * Resructions:
 * - Hardware size (hardware_size) is assumed to be = 6 (MAC-address).
 * - Protocol size (protocol_size) is assumed to be = 4 (IPv4)
 */
typedef struct {
    uint16_t hardware_type;
    uint16_t protocol_type;
    uint8_t hardware_size;      /** Hardware address length */
    uint8_t protocol_size;      /** Protocol address length */
    uint16_t opcode;            /** Operation code */
    uint8_t sha[6];             /** Sender hardware address (MAC) */
    uint8_t spa[4];             /** Sender protocol address (IPv4) */
    uint8_t tha[6];             /** Target hardware address (MAC) */
    uint8_t tpa[4];             /** Target protocol address (IPv4) */
} arp_packet_t;

/**
 * @brief Parses ARP packet from buffer.
 *
 * Expecting ARP for Ethernet/IPv4.
 *
 * @param buf Pointer to the start of the ARP
 * payload (after the Ethernet header).
 * @param len Length of the buffer (must be >= minimum ARP length)
 * @param packet Pointer to the structure to fill.
 * @return 0 on success, otherwise an error code.
 */
arp_status_t parse_arp(const uint8_t *buf, size_t len, arp_packet_t *packet);

/**
 * @brief Prints ARP packet in human readable from (stdout).
 *
 * @param packet Pointer to the parsed ARP packet.
 */
void print_arp(const arp_packet_t *packet);

#endif  /** ARP_PARSER_H */
