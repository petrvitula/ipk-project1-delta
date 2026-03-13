/**
 * @file Scanner.cpp
 * @brief Implementation file for the Scanner class
 * @author Petr Vitula (xvitulp00)
 */
 
#include "Scanner.h"
#include "SignalHandler.h"

#include <iostream>
#include <stdexcept>
#include <sstream>
#include <limits>
#include <cstring>
#include <thread>
#include <chrono>

// posix / linux networking
#include <arpa/inet.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <ifaddrs.h>
#include <netpacket/packet.h>
#include <linux/if_ether.h>
#include <sys/select.h>
#include <unistd.h>

#include <pcap.h>

namespace {

// information about the selected interface needed to build frames and sockets
struct InterfaceInfo {
    std::uint8_t mac[6]{};
    bool hasIpv4{false};
    struct in_addr ipv4{};
    bool hasIpv6{false};
    struct in6_addr ipv6{};
    int ifindex{-1};
};

// obtains mac, ipv4, ipv6 and interface index via ioctl/getifaddrs
InterfaceInfo getInterfaceInfo(const std::string &iface) {
    InterfaceInfo info{};
    const int fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd < 0) {
        throw std::runtime_error("socket() failed");
    }

    struct ifreq ifr{};
    if (iface.size() >= sizeof(ifr.ifr_name)) {
        close(fd);
        throw std::runtime_error("interface name too long");
    }
    std::strncpy(ifr.ifr_name, iface.c_str(), sizeof(ifr.ifr_name) - 1);
    ifr.ifr_name[sizeof(ifr.ifr_name) - 1] = '\0';

    if (ioctl(fd, SIOCGIFHWADDR, &ifr) != 0) {
        close(fd);
        throw std::runtime_error("SIOCGIFHWADDR failed for " + iface);
    }
    std::memcpy(info.mac, ifr.ifr_hwaddr.sa_data, 6);

    if (ioctl(fd, SIOCGIFINDEX, &ifr) != 0) {
        close(fd);
        throw std::runtime_error("SIOCGIFINDEX failed for " + iface);
    }
    info.ifindex = ifr.ifr_ifindex;

    if (ioctl(fd, SIOCGIFADDR, &ifr) == 0) {
        auto *sa = reinterpret_cast<struct sockaddr_in *>(&ifr.ifr_addr);
        if (sa->sin_family == AF_INET) {
            info.hasIpv4 = true;
            info.ipv4 = sa->sin_addr;
        }
    }
    close(fd);

    struct ifaddrs *ifa = nullptr;
    if (getifaddrs(&ifa) != 0) {
        return info;
    }
    for (struct ifaddrs *p = ifa; p != nullptr; p = p->ifa_next) {
        if (p->ifa_addr == nullptr || std::strcmp(p->ifa_name, iface.c_str()) != 0) {
            continue;
        }
        if (p->ifa_addr->sa_family == AF_INET6) {
            auto *sa6 = reinterpret_cast<struct sockaddr_in6 *>(p->ifa_addr);
            if (!IN6_IS_ADDR_UNSPECIFIED(&sa6->sin6_addr) && !IN6_IS_ADDR_LOOPBACK(&sa6->sin6_addr)) {
                info.hasIpv6 = true;
                info.ipv6 = sa6->sin6_addr;
                break;
            }
        }
    }
    freeifaddrs(ifa);
    return info;
}

// converts mac address to xx-xx-xx-xx-xx-xx format as required by the assignment
std::string formatMac(const std::uint8_t mac[6]) {
    char buf[18];
    std::snprintf(buf, sizeof(buf), "%02x-%02x-%02x-%02x-%02x-%02x",
                  mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
    return std::string(buf);
}

} // namespace

Scanner::Scanner(const std::string &iface, int timeoutMs)
    : interface_(iface), timeoutMs_(timeoutMs) {}

Scanner::~Scanner() {
    if (pcapHandle_ != nullptr) {
        pcap_close(pcapHandle_);
        pcapHandle_ = nullptr;
    }
}

// expands all configured ranges into concrete host ip addresses
std::vector<std::string> Scanner::generateHostIps() const {
    std::vector<std::string> hosts;
    hosts.reserve(128); // small initial reserve; will grow as needed

    for (const auto &range : ranges_) {
        if (range.usableHostCount == 0) {
            continue;
        }
        if (range.isIPv6) {
            appendIpv6Hosts(range, hosts);
        } else {
            appendIpv4Hosts(range, hosts);
        }
    }

    return hosts;
}

// adds a subnet to the scanner
void Scanner::addSubnet(const std::string &cidr) {
    ranges_.push_back(parseCidr(cidr));
}

// prints the scanning summary
void Scanner::printScanningSummary(std::ostream &os) const {
    os << "Scanning ranges:\n";
    for (const auto &range : ranges_) {
        os << range.networkAddress << " " << range.usableHostCount << "\n";
    }
}

// opens a libpcap handle on the chosen interface for passive receive
void Scanner::initializePcap() {
    if (interface_.empty()) {
        throw std::runtime_error("No interface specified for pcap initialization");
    }

    char errbuf[PCAP_ERRBUF_SIZE];
    std::memset(errbuf, 0, sizeof(errbuf));

    // Snapshot length: BUFSIZ, promiscuous mode: 1.
    // Use a short read timeout (e.g. 100 ms) so packets are delivered promptly regardless of -w.
    // -w controls how long run() waits for replies, not how long pcap blocks per read.
    const int pcapReadTimeoutMs = 100;
    pcapHandle_ = pcap_open_live(interface_.c_str(), BUFSIZ, 1, pcapReadTimeoutMs, errbuf);
    if (!pcapHandle_) {
        std::ostringstream oss;
        oss << "pcap_open_live failed on interface '" << interface_ << "': " << errbuf;
        throw std::runtime_error(oss.str());
    }
}

// runs the actual scan: initializes results, starts send + pcap threads
// and stops receiving after the configured timeout
void Scanner::run() {
    const auto hosts = generateHostIps();
    for (const auto &ip : hosts) {
        const bool isIPv6 = (ip.find(':') != std::string::npos);
        results_.initHost(ip, isIPv6);
    }

    stopRequested_ = false;
    linkType_ = pcap_datalink(pcapHandle_);

    std::thread pcapThread(&Scanner::pcapLoop, this);

    // Give pcap_loop time to start capturing before we send packets (avoids losing early replies)
    std::this_thread::sleep_for(std::chrono::milliseconds(50));

    std::thread senderThread(&Scanner::sendLoop, this);

    senderThread.join();

    // Wait for replies after all packets are sent; respect SIGINT/SIGTERM during wait
    const int stepMs = 50;
    int waited = 0;
    while (waited < timeoutMs_ && !stopRequested_.load()) {
        if (gTerminate.load()) {
            break;
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(stepMs));
        waited += stepMs;
    }

    stopRequested_ = true;
    if (pcapHandle_ != nullptr) {
        pcap_breakloop(pcapHandle_);
    }
    pcapThread.join();
}

// walks all hosts, builds arp/ndp + icmp probes and sends them via raw sockets
void Scanner::sendLoop() {
    InterfaceInfo ifinfo;
    try {
        ifinfo = getInterfaceInfo(interface_);
    } catch (const std::exception &) {
        return;
    }

    const auto hosts = generateHostIps();
    int arpFd = -1, icmp4Fd = -1, icmp6Fd = -1;

    if (ifinfo.ifindex >= 0) {
        arpFd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ARP));
    }
    if (ifinfo.hasIpv4) {
        icmp4Fd = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
        if (icmp4Fd >= 0) {
            // Bind ICMPv4 socket to the selected interface
            struct ifreq ifr{};
            std::strncpy(ifr.ifr_name, interface_.c_str(), IFNAMSIZ - 1);
            ifr.ifr_name[IFNAMSIZ - 1] = '\0';
            setsockopt(icmp4Fd, SOL_SOCKET, SO_BINDTODEVICE,
                       &ifr, sizeof(ifr));

            // Bind socket to our IPv4 address on that interface
            struct sockaddr_in src{};
            src.sin_family = AF_INET;
            src.sin_addr = ifinfo.ipv4;
            bind(icmp4Fd, reinterpret_cast<struct sockaddr *>(&src), sizeof(src));
        }
    }
    if (ifinfo.hasIpv6) {
        icmp6Fd = socket(AF_INET6, SOCK_RAW, IPPROTO_ICMPV6);
        if (icmp6Fd >= 0) {
            struct sockaddr_in6 bind6{};
            bind6.sin6_family = AF_INET6;
            bind6.sin6_addr = ifinfo.ipv6;
            bind6.sin6_scope_id = ifinfo.ifindex;
            bind(icmp6Fd, reinterpret_cast<struct sockaddr *>(&bind6), sizeof(bind6));
        }
    }

    std::uint16_t icmpId = static_cast<std::uint16_t>(getpid() & 0xFFFF);
    for (std::size_t i = 0; i < hosts.size() && !stopRequested_.load(); ++i) {
        const std::string &ip = hosts[i];
        const bool isIPv6 = (ip.find(':') != std::string::npos);

        if (!isIPv6 && ifinfo.hasIpv4 && arpFd >= 0) {
            struct in_addr targetIp{};
            if (inet_pton(AF_INET, ip.c_str(), &targetIp) != 1) { continue; }
            auto frame = buildArpRequestFrame(ifinfo.mac,
                                              reinterpret_cast<const std::uint8_t *>(&ifinfo.ipv4.s_addr),
                                              reinterpret_cast<const std::uint8_t *>(&targetIp.s_addr));
            struct sockaddr_ll ll{};
            ll.sll_family = AF_PACKET;
            ll.sll_ifindex = ifinfo.ifindex;
            ll.sll_protocol = htons(ETH_P_ARP);
            sendto(arpFd, frame.data(), frame.size(), 0,
                   reinterpret_cast<struct sockaddr *>(&ll), sizeof(ll));

            if (icmp4Fd >= 0) {
                auto payload = buildIcmpv4EchoRequest(icmpId, static_cast<std::uint16_t>(i));
                struct sockaddr_in dst{};
                dst.sin_family = AF_INET;
                dst.sin_addr = targetIp;
                sendto(icmp4Fd, payload.data(), payload.size(), 0,
                       reinterpret_cast<struct sockaddr *>(&dst), sizeof(dst));
            }
        } else if (isIPv6 && ifinfo.hasIpv6 && icmp6Fd >= 0) {
            struct in6_addr targetAddr{};
            if (inet_pton(AF_INET6, ip.c_str(), &targetAddr) != 1) {
                continue;
            }

            // ndp query for mac (uses s6_addr directly)
            std::uint8_t ndpBuf[70];
            std::size_t ndpLen = 0;
            buildNdSolicitation(ifinfo.ipv6.s6_addr, targetAddr.s6_addr,
                                ifinfo.mac, ndpBuf, &ndpLen);

            // solicited‑node multicast ff02::1:ffxx:xxxx – built manually in dst6.sin6_addr.s6_addr
            struct sockaddr_in6 dst6{};
            dst6.sin6_family = AF_INET6;
            dst6.sin6_scope_id = ifinfo.ifindex;
            dst6.sin6_addr.s6_addr[0] = 0xff;
            dst6.sin6_addr.s6_addr[1] = 0x02;
            dst6.sin6_addr.s6_addr[11] = 0x01;
            dst6.sin6_addr.s6_addr[12] = 0xff;
            dst6.sin6_addr.s6_addr[13] = targetAddr.s6_addr[13];
            dst6.sin6_addr.s6_addr[14] = targetAddr.s6_addr[14];
            dst6.sin6_addr.s6_addr[15] = targetAddr.s6_addr[15];

            sendto(icmp6Fd, ndpBuf, ndpLen, 0,
                   reinterpret_cast<struct sockaddr *>(&dst6), sizeof(dst6));

            // icmpv6 echo request – unicast to target address
            auto echoPayload = buildIcmpv6EchoRequest(icmpId, static_cast<std::uint16_t>(i));
            setIcmpv6EchoChecksum(ifinfo.ipv6.s6_addr, targetAddr.s6_addr,
                                  echoPayload.data(), echoPayload.size());
            dst6.sin6_addr = targetAddr;
            dst6.sin6_scope_id = ifinfo.ifindex;
            sendto(icmp6Fd, echoPayload.data(), echoPayload.size(), 0,
                   reinterpret_cast<struct sockaddr *>(&dst6), sizeof(dst6));
        }
    }

    if (arpFd >= 0) { close(arpFd); }
    if (icmp4Fd >= 0) { close(icmp4Fd); }
    if (icmp6Fd >= 0) { close(icmp6Fd); }
}

// blocking libpcap loop that forwards each captured packet to pcapCallback
void Scanner::pcapLoop() {
    if (pcapHandle_ == nullptr) {
        return;
    }
    pcap_loop(pcapHandle_, -1, &Scanner::pcapCallback, reinterpret_cast<u_char *>(this));
}

// Additional ethertype used when handling 802.1Q VLAN encapsulation
namespace {
const std::uint16_t ETHERTYPE_VLAN = 0x8100;
}

// static callback used by libpcap for each captured frame
// inspects ethertype/headers, recognizes replies and updates resultsStore
// supports Ethernet (DLT_EN10MB), 802.1Q VLAN, and Linux cooked (DLT_LINUX_SLL)
void Scanner::pcapCallback(u_char *user, const struct pcap_pkthdr *h, const u_char *bytes) {
    auto *self = reinterpret_cast<Scanner *>(user);
    if (self->stopRequested_.load() || gTerminate.load()) {
        return;
    }
    const std::size_t len = static_cast<std::size_t>(h->caplen);

    std::size_t l2_start = 0;
    std::uint16_t etherType = 0;

    // Read EtherType in network byte order and convert to host for comparison
    auto readEtherType = [](const u_char *p) -> std::uint16_t {
        return ntohs(static_cast<std::uint16_t>((static_cast<std::uint16_t>(p[0]) << 8) | p[1]));
    };

    if (self->linkType_ == DLT_LINUX_SLL2) {
        // Linux cooked v2: 20-byte header, protocol (EtherType) at bytes 0-1, payload at 20
        if (len < 20) { return; }
        l2_start = 20;
        etherType = readEtherType(bytes + 0);
    } else if (self->linkType_ == DLT_LINUX_SLL) {
        // Linux cooked v1: 16-byte header, protocol at bytes 14-15, payload at 16
        if (len < 16) { return; }
        l2_start = 16;
        etherType = readEtherType(bytes + 14);
    } else {
        // DLT_EN10MB (Ethernet) or unknown: assume 14-byte Ethernet
        if (len < 14) { return; }
        l2_start = 14;
        etherType = readEtherType(bytes + 12);
        // 802.1Q VLAN: skip 4 bytes and read inner etherType
        if (etherType == ntohs(ETHERTYPE_VLAN) && len >= 18) {
            l2_start = 18;
            etherType = readEtherType(bytes + 16);
        }
    }

    // if the ethertype is arp and the length is greater than or equal to 28, update the l2 status to ok
    if (etherType == ntohs(ETHERTYPE_ARP) && len >= l2_start + 28) {
        const auto *arp = reinterpret_cast<const ArpPacket *>(bytes + l2_start);
        if (ntohs(arp->op) != ARP_OP_REPLY) { return; }
        char ipStr[INET_ADDRSTRLEN];
        if (inet_ntop(AF_INET, arp->senderIp, ipStr, sizeof(ipStr)) == nullptr) { return; }
        self->results_.updateL2Ok(ipStr, formatMac(arp->senderMac));
        return;
    }

    // if the ethertype is ip and the length is greater than or equal to 20, update the l3 status to ok
    if (etherType == ntohs(ETHERTYPE_IP) && len >= l2_start + 20) {
        const auto *ip4 = reinterpret_cast<const Ipv4Header *>(bytes + l2_start);

        // 1. Check version and protocol
        if ((ip4->versionIhl >> 4) != 4 || ip4->protocol != IPPROTO_ICMP) { return; }

        std::size_t ipLen = (ip4->versionIhl & 0x0f) * 4u;
        if (len < l2_start + ipLen + 8) { return; }

        const auto *icmp = reinterpret_cast<const Icmpv4Header *>(bytes + l2_start + ipLen);

        // 2. Must be Echo Reply (0), not Echo Request (8)
        if (icmp->type != 0) { return; }

        // 3. ID must match what we sent
        std::uint16_t myId = static_cast<std::uint16_t>(getpid() & 0xFFFF);
        if (ntohs(icmp->id) != myId) { return; }

        char ipStr[INET_ADDRSTRLEN];
        if (inet_ntop(AF_INET, ip4->srcAddr, ipStr, sizeof(ipStr)) != nullptr) {
            self->results_.updateL3Ok(ipStr);
        }
        return;
    }

    // if the ethertype is ipv6 and the length is greater than or equal to 40, update the l3 status to ok
    if (etherType == ntohs(ETHERTYPE_IPV6) && len >= l2_start + 40) {
        const auto *ip6 = reinterpret_cast<const Ipv6Header *>(bytes + l2_start);
        if ((ntohl(ip6->versionTrafficFlow) >> 28) != 6 || ip6->nextHeader != IPPROTO_ICMPV6) { return; }
        if (len < l2_start + 40 + 8) { return; }
        const auto *icmp6 = reinterpret_cast<const Icmpv6Header *>(bytes + l2_start + 40);
        if (icmp6->type == ICMPV6_NDP_NA) {
            // ICMPv6 header (4 bytes) + flags (4 bytes) + target address (16 bytes)
            if (len < l2_start + 40 + 4 + 4 + 16) { return; }
            const std::size_t na_target_offset = l2_start + 40 + 4 + 4;
            char targetIpStr[INET6_ADDRSTRLEN];
            if (inet_ntop(AF_INET6, bytes + na_target_offset, targetIpStr, sizeof(targetIpStr)) == nullptr) { return; }
            // Parse NDP options to find Target Link-Layer Address (type 2)
            std::string mac;
            const std::size_t options_offset = na_target_offset + 16;
            if (len > options_offset + 2) {
                std::size_t off = options_offset;
                while (off + 2 <= len) {
                    std::uint8_t optType = bytes[off];
                    std::uint8_t optLenUnits = bytes[off + 1]; // in units of 8 bytes
                    if (optLenUnits == 0) {
                        break;
                    }
                    std::size_t optTotalLen = static_cast<std::size_t>(optLenUnits) * 8u;
                    if (off + optTotalLen > len) {
                        break;
                    }
                    if (optType == 2 && optTotalLen >= 8) { // Target Link-Layer Address
                        mac = formatMac(bytes + off + 2);
                        break;
                    }
                    off += optTotalLen;
                }
            }
            // Fallback: if we did not find a TLV with MAC, use link-layer source
            if (mac.empty()) {
                mac = formatMac(bytes + 6);
            }
            self->results_.updateL2Ok(targetIpStr, mac);
            return;
        }
        if (icmp6->type == ICMPV6_ECHO_REPLY) {
            char ipStr[INET6_ADDRSTRLEN];
            if (inet_ntop(AF_INET6, ip6->srcAddr, ipStr, sizeof(ipStr)) == nullptr) { return; }
            self->results_.updateL3Ok(ipStr);
        }
    }
}

// lists all the interfaces
void Scanner::listInterfaces(std::ostream &os) {
    char errbuf[PCAP_ERRBUF_SIZE];
    std::memset(errbuf, 0, sizeof(errbuf));

    pcap_if_t *alldevs = nullptr;
    if (pcap_findalldevs(&alldevs, errbuf) == -1) {
        os << "Error listing interfaces: " << errbuf << "\n";
        return;
    }

    for (pcap_if_t *d = alldevs; d != nullptr; d = d->next) {
        if (d->flags & PCAP_IF_LOOPBACK) {
            continue; // skip loopback, optional
        }
        if (d->name) {
            os << d->name;
            if (d->description) {
                os << " (" << d->description << ")";
            }
            os << "\n";
        }
    }

    pcap_freealldevs(alldevs);
}

// Maximum hosts per subnet to avoid OOM/hang on huge ranges (e.g. 10.0.0.0/8)
constexpr std::uint64_t MAX_HOSTS_PER_SUBNET = 65536;

NetworkRange Scanner::parseCidr(const std::string &cidr) const {
    auto slashPos = cidr.find('/');
    if (slashPos == std::string::npos) {
        throw std::invalid_argument("CIDR must be in form address/prefix: " + cidr);
    }

    std::string addrPart = cidr.substr(0, slashPos);
    std::string prefixPart = cidr.substr(slashPos + 1);

    if (addrPart.empty() || prefixPart.empty()) {
        throw std::invalid_argument("CIDR is missing address or prefix: " + cidr);
    }

    char *endptr = nullptr;
    long prefix = std::strtol(prefixPart.c_str(), &endptr, 10);
    if (*endptr != '\0' || prefix < 0 || prefix > 128) {
        throw std::invalid_argument("Invalid prefix length in CIDR: " + cidr);
    }

    // Try IPv4 first
    struct in_addr v4addr;
    if (inet_pton(AF_INET, addrPart.c_str(), &v4addr) == 1) {
        if (prefix > 32) {
            throw std::invalid_argument("IPv4 prefix out of range in CIDR: " + cidr);
        }
        return parseIpv4Cidr(addrPart, static_cast<std::uint8_t>(prefix));
    }

    // Try IPv6
    struct in6_addr v6addr;
    if (inet_pton(AF_INET6, addrPart.c_str(), &v6addr) == 1) {
        return parseIpv6Cidr(addrPart, static_cast<std::uint8_t>(prefix));
    }

    throw std::invalid_argument("Address is neither valid IPv4 nor IPv6: " + cidr);
}

// parses the ipv4 cidr
NetworkRange Scanner::parseIpv4Cidr(const std::string &addrPart, std::uint8_t prefixLen) {
    struct in_addr addr{};
    if (inet_pton(AF_INET, addrPart.c_str(), &addr) != 1) {
        throw std::invalid_argument("Invalid IPv4 address: " + addrPart);
    }

    std::uint32_t a = ntohl(addr.s_addr);
    std::uint32_t mask = (prefixLen == 0) ? 0 : (0xFFFFFFFFu << (32 - prefixLen));
    std::uint32_t network = a & mask;

    addr.s_addr = htonl(network);
    char buf[INET_ADDRSTRLEN];
    if (!inet_ntop(AF_INET, &addr, buf, sizeof(buf))) {
        throw std::runtime_error("inet_ntop failed for IPv4");
    }

    NetworkRange range;
    range.originalCidr = addrPart + "/" + std::to_string(prefixLen);
    range.isIPv6 = false;
    range.prefixLength = prefixLen;

    // Usable hosts according to prefix:
    // - /32: exactly one host (the address itself)
    // - /31: RFC 3021 point-to-point – both addresses usable → 2 hosts
    // - otherwise: 2^(32-prefix) - 2 (exclude network and broadcast)
    if (prefixLen == 32) {
        range.usableHostCount = 1;
    } else if (prefixLen == 31) {
        range.usableHostCount = 2;
    } else {
        std::uint32_t hostBits = 32 - prefixLen;
        std::uint64_t total = (1ULL << hostBits);
        range.usableHostCount = (total >= 2) ? total - 2 : 0;
    }

    if (range.usableHostCount > MAX_HOSTS_PER_SUBNET) {
        throw std::invalid_argument("Subnet too large (max " + std::to_string(MAX_HOSTS_PER_SUBNET) + " hosts per -s): " + addrPart + "/" + std::to_string(prefixLen));
    }

    std::ostringstream oss;
    oss << buf << "/" << static_cast<int>(prefixLen);
    range.networkAddress = oss.str();

    return range;
}

// parses the ipv6 cidr
NetworkRange Scanner::parseIpv6Cidr(const std::string &addrPart, std::uint8_t prefixLen) {
    struct in6_addr addr{};
    if (inet_pton(AF_INET6, addrPart.c_str(), &addr) != 1) {
        throw std::invalid_argument("Invalid IPv6 address: " + addrPart);
    }

    // Zero out host bits
    std::uint8_t fullBytes = prefixLen / 8;
    std::uint8_t remainingBits = prefixLen % 8;

    for (std::size_t i = fullBytes; i < sizeof(addr.s6_addr); ++i) {
        std::uint8_t mask = (i == fullBytes && remainingBits != 0)
                                ? static_cast<std::uint8_t>(0xFF << (8 - remainingBits))
                                : 0x00;
        addr.s6_addr[i] &= mask;
    }

    char buf[INET6_ADDRSTRLEN];
    if (!inet_ntop(AF_INET6, &addr, buf, sizeof(buf))) {
        throw std::runtime_error("inet_ntop failed for IPv6");
    }

    NetworkRange range;
    range.originalCidr = addrPart + "/" + std::to_string(prefixLen);
    range.isIPv6 = true;
    range.prefixLength = prefixLen;

    // Usable hosts count for IPv6.
    // We only support reasonably small ranges so that the result fits into uint64_t.
    std::uint32_t hostBits = 128 - prefixLen;
    if (hostBits >= 63) {
        throw std::invalid_argument("IPv6 prefix too short for this scanner implementation: " + std::to_string(prefixLen));
    }
    std::uint64_t total = (1ULL << hostBits);
    if (prefixLen == 128) {
        // Single host – scan exactly this one address.
        range.usableHostCount = 1;
    } else {
        // Match README example for /126: 2^(hostBits) - 1 usable hosts (skip network).
        range.usableHostCount = (total >= 1) ? total - 1 : 0;
    }

    if (range.usableHostCount > MAX_HOSTS_PER_SUBNET) {
        throw std::invalid_argument("Subnet too large (max " + std::to_string(MAX_HOSTS_PER_SUBNET) + " hosts per -s): " + addrPart + "/" + std::to_string(prefixLen));
    }

    std::ostringstream oss;
    oss << buf << "/" << static_cast<int>(prefixLen);
    range.networkAddress = oss.str();

    return range;
}

// appends the ipv4 hosts to the vector
void Scanner::appendIpv4Hosts(const NetworkRange &range, std::vector<std::string> &out) {
    auto slashPos = range.networkAddress.find('/');
    std::string addrPart = (slashPos == std::string::npos)
                               ? range.networkAddress
                               : range.networkAddress.substr(0, slashPos);

    struct in_addr addr{};
    if (inet_pton(AF_INET, addrPart.c_str(), &addr) != 1) {
        throw std::runtime_error("appendIpv4Hosts: invalid IPv4 network address stored");
    }

    std::uint32_t base = ntohl(addr.s_addr);

    // For /32 we interpret usableHostCount == 1 as single host equal to network address.
    if (range.prefixLength == 32) {
        char buf[INET_ADDRSTRLEN];
        if (!inet_ntop(AF_INET, &addr, buf, sizeof(buf))) {
            throw std::runtime_error("inet_ntop failed in appendIpv4Hosts");
        }
        out.emplace_back(buf);
        return;
    }

    // For /31 (RFC 3021): both addresses are usable – base+0 and base+1
    if (range.prefixLength == 31) {
        for (std::uint32_t i = 0; i <= 1; ++i) {
            struct in_addr h{};
            h.s_addr = htonl(base + i);
            char buf[INET_ADDRSTRLEN];
            if (!inet_ntop(AF_INET, &h, buf, sizeof(buf))) {
                throw std::runtime_error("inet_ntop failed in appendIpv4Hosts");
            }
            out.emplace_back(buf);
        }
        return;
    }

    if (range.usableHostCount == 0) {
        return;
    }

    // For prefixes <= 30 we used usableHostCount = 2^(32-prefix) - 2.
    // Hosts are network+1 .. network+usableHostCount.
    for (std::uint64_t i = 1; i <= range.usableHostCount; ++i) {
        std::uint32_t hostAddr = base + static_cast<std::uint32_t>(i);
        struct in_addr h{};
        h.s_addr = htonl(hostAddr);

        char buf[INET_ADDRSTRLEN];
        if (!inet_ntop(AF_INET, &h, buf, sizeof(buf))) {
            throw std::runtime_error("inet_ntop failed in appendIpv4Hosts");
        }
        out.emplace_back(buf);
    }
}

// appends the ipv6 hosts to the vector
void Scanner::appendIpv6Hosts(const NetworkRange &range, std::vector<std::string> &out) {
    auto slashPos = range.networkAddress.find('/');
    std::string addrPart = (slashPos == std::string::npos)
                               ? range.networkAddress
                               : range.networkAddress.substr(0, slashPos);

    struct in6_addr net{};
    if (inet_pton(AF_INET6, addrPart.c_str(), &net) != 1) {
        throw std::runtime_error("appendIpv6Hosts: invalid IPv6 network address stored");
    }

    // For /128 we interpret usableHostCount == 1 as single host equal to network address.
    if (range.prefixLength == 128) {
        char buf[INET6_ADDRSTRLEN];
        if (!inet_ntop(AF_INET6, &net, buf, sizeof(buf))) {
            throw std::runtime_error("inet_ntop failed in appendIpv6Hosts");
        }
        out.emplace_back(buf);
        return;
    }

    if (range.usableHostCount == 0) {
        return;
    }

    // We limited hostBits < 63 when computing usableHostCount,
    // so usableHostCount fits safely into uint64_t and also into low 64 bits.
    // For prefixes < 128 we use usableHostCount = 2^(hostBits) - 1 and
    // generate hosts network+1 .. network+usableHostCount.
    for (std::uint64_t i = 1; i <= range.usableHostCount; ++i) {
        struct in6_addr addr = net;

        // Interpret the last 8 bytes as a big-endian uint64 and add i.
        std::uint64_t low = 0;
        for (int b = 8; b < 16; ++b) {
            low = (low << 8) | addr.s6_addr[b];
        }
        low += i;
        for (int b = 15; b >= 8; --b) {
            addr.s6_addr[b] = static_cast<std::uint8_t>(low & 0xFF);
            low >>= 8;
        }

        char buf[INET6_ADDRSTRLEN];
        if (!inet_ntop(AF_INET6, &addr, buf, sizeof(buf))) {
            throw std::runtime_error("inet_ntop failed in appendIpv6Hosts");
        }
        out.emplace_back(buf);
    }
}


