# IEEE 802.15.4 Sniffer

Sniffer for IEEE 802.15.4 packets that can write to pcap for analyzing with Wireshark.

To decrypt Zigbee packets in Wireshark, add the following keys:

| Key                                             | Byte Order | Label
|-------------------------------------------------|------------|----------------------
| 5A:69:67:42:65:65:41:6C:6C:69:61:6E:63:65:30:39 | Normal     | Trust Center Link Key
| (Your network key)                              | Normal     | Network Key

## Features
* Write to pcap
* Simple packet dissection to the text console
* Support for Zigbee packets

## Supported Platforms
All platforms for which Ieee802154Radio is implemented, see README.md of coco-ieee802154
