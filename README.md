# ARP packet parser in C

## Limitations

The parser only supports classic ARP over Ethernet/IPv4:
- **Hardware type:** - 1 (Ethernet)
- **Protocol type:** - 0x0800 (IPv4)

Packets with other types of channel or network protocol
are considered unsupported and are treated as errors.

## Usage

### Building the Project

To build the project, use the following commands:

```bash
mkdir build
cd build
cmake ..
make
```

### Running the Example

```bash
cd examples
./example
```

### Example Code

```c

#include <stdio.h>
#include <arp_parser.h>

/** test package */
uint8_t test_arp_packet[] = {
    0x00, 0x01, 0x08, 0x00, 0x06, 0x04, 0x00, 0x01,
    0x08, 0x00, 0x27, 0x12, 0x34, 0x56, 0xC0, 0xA8,
    0x01, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0xC0, 0xA8, 0x01, 0x02
};

int main(void)
{
    arp_packet_t packet_1;

    /** Parse packets and output data in a readable from */
    if (parse_arp(test_arp_packet, sizeof(test_arp_packet), &packet_1) == ARP_OK)
        print_arp(&packet_1);

    return 0;
}
```

### API Overview

- **parse_arp**: Parsing ARP packet.

- **print_arp**: Prints ARP packet in human readable from.
