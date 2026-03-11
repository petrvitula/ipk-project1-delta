#include "Packets.h"
#include <cstring>
#include <arpa/inet.h>
#include <algorithm>

namespace {

std::uint32_t addChecksumWords(const std::uint16_t *words, std::size_t count) {
    std::uint32_t sum = 0;
    for (std::size_t i = 0; i < count; ++i) {
        sum += ntohs(words[i]);
    }
    while (sum >> 16) {
        sum = (sum & 0xFFFFu) + (sum >> 16);
    }
    return sum;
}

} // namespace

// generic internet checksum (rfc 1071) used for icmpv4 and other headers
std::uint16_t inetChecksum(const void *data, std::size_t len) {
    const auto *words = static_cast<const std::uint16_t *>(data);
    std::size_t count = len / 2;
    std::uint32_t sum = addChecksumWords(words, count);
    if (len & 1) {
        sum += static_cast<const std::uint8_t *>(data)[len - 1] << 8;
    }
    while (sum >> 16) {
        sum = (sum & 0xFFFFu) + (sum >> 16);
    }
    std::uint16_t result = static_cast<std::uint16_t>(~sum);
    return result ? result : 0xFFFF;
}

// compute icmpv6 checksum including ipv6 pseudo‑header
std::uint16_t icmpv6Checksum(const void *ipv6Header, std::size_t payloadLen,
                              const void *payload) {
    const auto *ip6 = static_cast<const std::uint8_t *>(ipv6Header);
    std::uint32_t sum = 0;

    // Pseudo-header: src (16 bytes = 8 words) + dst (16 bytes = 8 words)
    sum += addChecksumWords(reinterpret_cast<const std::uint16_t *>(ip6 + 8), 8);
    sum += addChecksumWords(reinterpret_cast<const std::uint16_t *>(ip6 + 24), 8);
    sum += static_cast<std::uint32_t>(payloadLen >> 16) & 0xFFFF;
    sum += static_cast<std::uint32_t>(payloadLen) & 0xFFFF;
    sum += 58; // next header = ICMPv6

    const auto *p = static_cast<const std::uint16_t *>(payload);
    std::size_t n = payloadLen / 2;
    sum += addChecksumWords(p, n);
    if (payloadLen & 1) {
        sum += static_cast<const std::uint8_t *>(payload)[payloadLen - 1] << 8;
    }

    while (sum >> 16) {
        sum = (sum & 0xFFFFu) + (sum >> 16);
    }
    std::uint16_t result = static_cast<std::uint16_t>(~sum);
    return result ? result : 0xFFFF;
}

// --- build helpers -----------------------------------------------------------

static const std::uint8_t ETH_BROADCAST[6] = {0xff, 0xff, 0xff, 0xff, 0xff, 0xff};

// build complete ethernet + arp request frame for a given ipv4 target
std::vector<std::uint8_t> buildArpRequestFrame(const std::uint8_t ourMac[6],
                                                 const std::uint8_t ourIp[4],
                                                 const std::uint8_t targetIp[4]) {
    std::vector<std::uint8_t> frame(14 + 28);
    auto *eth = reinterpret_cast<EthHeader *>(frame.data());
    std::memcpy(eth->dstMac, ETH_BROADCAST, 6);
    std::memcpy(eth->srcMac, ourMac, 6);
    eth->etherType = htons(ETHERTYPE_ARP);

    auto *arp = reinterpret_cast<ArpPacket *>(frame.data() + 14);
    arp->hwType = htons(1);
    arp->protoType = htons(ETHERTYPE_IP);
    arp->hwLen = 6;
    arp->protoLen = 4;
    arp->op = htons(ARP_OP_REQUEST);
    std::memcpy(arp->senderMac, ourMac, 6);
    std::memcpy(arp->senderIp, ourIp, 4);
    std::memset(arp->targetMac, 0, 6);
    std::memcpy(arp->targetIp, targetIp, 4);

    return frame;
}

// build icmpv4 echo request (without ip header)
std::vector<std::uint8_t> buildIcmpv4EchoRequest(std::uint16_t id, std::uint16_t seq) {
    // Match typical ping behaviour: ICMP header (8 bytes) + small payload so that
    // total packet length is non-trivial (some devices are picky about zero-length payloads).
    static const char payload[] = "ipk-l2l3-scan-payload";
    const std::size_t payloadLen = sizeof(payload) - 1; // without terminating '\0'

    std::vector<std::uint8_t> buf(sizeof(Icmpv4Header) + payloadLen);
    auto *icmp = reinterpret_cast<Icmpv4Header *>(buf.data());
    icmp->type = ICMPV4_ECHO_REQUEST;
    icmp->code = 0;
    icmp->checksum = 0;
    icmp->id = htons(id);
    icmp->sequence = htons(seq);

    // Copy payload right after the header
    std::memcpy(buf.data() + sizeof(Icmpv4Header), payload, payloadLen);

    // Checksum over entire ICMP message (header + payload)
    icmp->checksum = inetChecksum(buf.data(), buf.size());
    return buf;
}

// compute solicited‑node multicast address ff02::1:ffxx:xxxx from a target ipv6
void getSolicitedNodeMulticast(const std::uint8_t targetIpv6[16], std::uint8_t out[16]) {
    // ff02::1:ffxx:xxxx – last 24 bits of the target ipv6 address
    static const std::uint8_t prefix[13] = {
        0xff, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0xff
    };
    std::memcpy(out, prefix, 13);
    // last 3 bytes (24 bits) of the target address
    out[13] = targetIpv6[13];
    out[14] = targetIpv6[14];
    out[15] = targetIpv6[15];
}

// helper for computing checksum of ndp neighbor solicitation packets
std::uint16_t getNdSolicitationChecksum(const std::uint8_t ourIpv6[16],
                                        const std::uint8_t solicitedNode[16],
                                        const std::uint8_t *icmpPayload, std::size_t len) {
    Ipv6Header pseudo{};
    pseudo.versionTrafficFlow = htonl(0x60000000u);
    pseudo.payloadLength = htons(static_cast<std::uint16_t>(len));
    pseudo.nextHeader = IPPROTO_ICMPV6;
    std::memcpy(pseudo.srcAddr, ourIpv6, 16);
    std::memcpy(pseudo.dstAddr, solicitedNode, 16);
    std::uint8_t temp[40 + 256];
    std::memcpy(temp, &pseudo, 40);
    std::memcpy(temp + 40, icmpPayload, len);
    return icmpv6Checksum(temp, len, temp + 40);
}

// build icmpv6 neighbor solicitation payload (without ipv6 header)
void buildNdSolicitation(const std::uint8_t ourIpv6[16], const std::uint8_t targetIpv6[16],
                         const std::uint8_t ourMac[6], std::uint8_t *out, std::size_t *outLen) {
    // 4 (icmp header) + 4 (reserved) + 16 (target) + 8 (option) = 32 bytes
    const std::size_t len = 32;
    *outLen = len;

    std::memset(out, 0, len);

    // icmpv6 header
    out[0] = ICMPV6_NDP_NS; // type 135
    out[1] = 0;             // code 0
    // out[2..3] checksum is filled in later

    // reserved (4 bytes) are already zero (out[4..7])

    // target address (16 bytes) starting at offset 8
    std::memcpy(out + 8, targetIpv6, 16);

    // source link‑layer address option
    std::uint8_t *opt = out + 24; // 8 (hdr+res) + 16 (target)
    opt[0] = 1; // type
    opt[1] = 1; // length (1*8 bytes)
    std::memcpy(opt + 2, ourMac, 6);

    // checksum over pseudo‑header + icmpv6 payload
    std::uint8_t solicited[16];
    getSolicitedNodeMulticast(targetIpv6, solicited);
    std::uint16_t csum = getNdSolicitationChecksum(ourIpv6, solicited, out, len);

    // store checksum byte by byte (network order)
    out[2] = static_cast<std::uint8_t>((csum >> 8) & 0xFF);
    out[3] = static_cast<std::uint8_t>(csum & 0xFF);
}

// build icmpv6 echo request payload (without ipv6 header)
std::vector<std::uint8_t> buildIcmpv6EchoRequest(std::uint16_t id, std::uint16_t seq) {
    std::vector<std::uint8_t> buf(8);
    auto *icmp = reinterpret_cast<Icmpv6Header *>(buf.data());
    icmp->type = ICMPV6_ECHO_REQUEST;
    icmp->code = 0;
    icmp->checksum = 0;
    *reinterpret_cast<std::uint16_t *>(buf.data() + 4) = htons(id);
    *reinterpret_cast<std::uint16_t *>(buf.data() + 6) = htons(seq);
    return buf;
}

// fill correct checksum into icmpv6 echo request payload
void setIcmpv6EchoChecksum(const std::uint8_t ourIpv6[16], const std::uint8_t targetIpv6[16],
                           std::uint8_t *icmpPayload, std::size_t len) {
    Ipv6Header pseudo{};
    pseudo.versionTrafficFlow = htonl(0x60000000u);
    pseudo.payloadLength = htons(static_cast<std::uint16_t>(len));
    pseudo.nextHeader = IPPROTO_ICMPV6; 
    std::memcpy(pseudo.srcAddr, ourIpv6, 16);
    std::memcpy(pseudo.dstAddr, targetIpv6, 16);
    std::uint16_t csum = icmpv6Checksum(&pseudo, len, icmpPayload);
    *reinterpret_cast<std::uint16_t *>(icmpPayload + 2) = csum;
}
