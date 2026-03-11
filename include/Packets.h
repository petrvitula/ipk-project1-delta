#pragma once

#include <cstdint>
#include <cstddef>
#include <vector>

// Ethernet II header (14 bytes)
struct __attribute__((packed)) EthHeader {
    std::uint8_t  dstMac[6];
    std::uint8_t  srcMac[6];
    std::uint16_t etherType;
};

#define ETHERTYPE_ARP  0x0806
#define ETHERTYPE_IP   0x0800
#define ETHERTYPE_IPV6 0x86DD

// ARP header for Ethernet + IPv4 (RFC 826), 28 bytes
struct __attribute__((packed)) ArpPacket {
    std::uint16_t hwType;      // 1 = Ethernet
    std::uint16_t protoType;   // 0x0800 = IPv4
    std::uint8_t  hwLen;       // 6
    std::uint8_t  protoLen;    // 4
    std::uint16_t op;          // 1 = request, 2 = reply
    std::uint8_t  senderMac[6];
    std::uint8_t  senderIp[4];
    std::uint8_t  targetMac[6];
    std::uint8_t  targetIp[4];
};

#define ARP_OP_REQUEST 1
#define ARP_OP_REPLY   2

// IPv4 header (minimal, 20 bytes for no options)
struct __attribute__((packed)) Ipv4Header {
    std::uint8_t  versionIhl;  // 4 bits version, 4 bits IHL
    std::uint8_t  tos;
    std::uint16_t totalLength;
    std::uint16_t id;
    std::uint16_t flagsFrag;
    std::uint8_t  ttl;
    std::uint8_t  protocol;
    std::uint16_t checksum;
    std::uint8_t  srcAddr[4];
    std::uint8_t  dstAddr[4];
};

// ICMPv4 Echo Request/Reply (RFC 792)
struct __attribute__((packed)) Icmpv4Header {
    std::uint8_t  type;
    std::uint8_t  code;
    std::uint16_t checksum;
    std::uint16_t id;
    std::uint16_t sequence;
};

#define ICMPV4_ECHO_REQUEST 8
#define ICMPV4_ECHO_REPLY    0

// IPv6 header (40 bytes)
struct __attribute__((packed)) Ipv6Header {
    std::uint32_t versionTrafficFlow;  // 4 bits version, 8 traffic class, 20 flow label
    std::uint16_t payloadLength;
    std::uint8_t  nextHeader;
    std::uint8_t  hopLimit;
    std::uint8_t  srcAddr[16];
    std::uint8_t  dstAddr[16];
};

// ICMPv6 header (RFC 4443)
struct __attribute__((packed)) Icmpv6Header {
    std::uint8_t  type;
    std::uint8_t  code;
    std::uint16_t checksum;
};

#define ICMPV6_ECHO_REQUEST 128
#define ICMPV6_ECHO_REPLY    129
#define ICMPV6_NDP_NS       135   // Neighbor Solicitation
#define ICMPV6_NDP_NA       136   // Neighbor Advertisement

// ICMPv6 Neighbor Solicitation (RFC 4861), after Icmpv6Header
struct __attribute__((packed)) NdSolicit {
    std::uint32_t reserved;
    std::uint8_t  targetAddr[16];
    // optional TLVs follow (e.g. Source Link-Layer Address)
};

// ICMPv6 Neighbor Advertisement (RFC 4861), after Icmpv6Header
struct __attribute__((packed)) NdAdvert {
    std::uint32_t flagsReserved;  // R=1, S=2, O=4
    std::uint8_t  targetAddr[16];
    // optional TLVs follow
};

// Checksum helpers
std::uint16_t inetChecksum(const void *data, std::size_t len);
std::uint16_t icmpv6Checksum(const void *ipv6Header, std::size_t payloadLen,
                             const void *payload);

// Build full Ethernet+ARP request frame (dst MAC = broadcast). Returns 14+28 bytes.
std::vector<std::uint8_t> buildArpRequestFrame(const std::uint8_t ourMac[6],
                                               const std::uint8_t ourIp[4],
                                               const std::uint8_t targetIp[4]);

// ICMPv4 Echo Request (8 bytes), checksum filled.
std::vector<std::uint8_t> buildIcmpv4EchoRequest(std::uint16_t id, std::uint16_t seq);

// ICMPv6 Neighbor Solicitation for target IPv6; ourMac in Source Link-Layer option.
// Uses solicited-node multicast; caller must send to that address.
void buildNdSolicitation(const std::uint8_t ourIpv6[16], const std::uint8_t targetIpv6[16],
                         const std::uint8_t ourMac[6], std::uint8_t *out, std::size_t *outLen);
std::uint16_t getNdSolicitationChecksum(const std::uint8_t ourIpv6[16],
                                        const std::uint8_t solicitedNode[16],
                                        const std::uint8_t *icmpPayload, std::size_t len);

// ICMPv6 Echo Request; checksum over pseudo-header (ourIpv6, targetIpv6, len).
std::vector<std::uint8_t> buildIcmpv6EchoRequest(std::uint16_t id, std::uint16_t seq);
void setIcmpv6EchoChecksum(const std::uint8_t ourIpv6[16], const std::uint8_t targetIpv6[16],
                           std::uint8_t *icmpPayload, std::size_t len);

// Solicited-node multicast address from target IPv6 (caller provides 16-byte buffer).
void getSolicitedNodeMulticast(const std::uint8_t targetIpv6[16], std::uint8_t out[16]);
