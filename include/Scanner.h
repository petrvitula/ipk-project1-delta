#pragma once

#include <string>
#include <vector>
#include <cstdint>
#include <iosfwd>
#include <thread>
#include <atomic>

#include "Results.h"
#include "Packets.h"

// forward declarations from libpcap
struct pcap_if;
struct pcap;
struct pcap_pkthdr;

// represents one parsed subnet (ipv4 or ipv6) to be scanned
struct NetworkRange {
    // original cidr string as provided by user, e.g. "192.168.0.0/30"
    std::string originalCidr;
    // normalized network address with prefix, e.g. "192.168.0.0/30" or "fd00::/126"
    std::string networkAddress;
    bool isIPv6{false};
    std::uint8_t prefixLength{0};
    // number of hosts that will actually be scanned (according to assignment rules)
    std::uint64_t usableHostCount{0};
};

// high‑level orchestrator for the whole l2/l3 scan on a single interface
class Scanner {
public:
    Scanner(const std::string &iface, int timeoutMs);
    ~Scanner();

    Scanner(const Scanner &) = delete;
    Scanner &operator=(const Scanner &) = delete;

    // parse and store subnet; throws std::invalid_argument on bad cidr
    void addSubnet(const std::string &cidr);

    // print "scanning ranges:" and the summary lines
    void printScanningSummary(std::ostream &os) const;

    // initialize libpcap on the chosen interface
    void initializePcap();

    // generate list of all host ip addresses across all configured ranges
    // order is not specified, but will be deterministic for the same ranges
    std::vector<std::string> generateHostIps() const;

    // main entry point: starts sender + pcap threads, waits timeout, then prints results
    void run();

    // access to results store (to be filled by scan logic)
    ResultsStore &results() { return results_; }
    const ResultsStore &results() const { return results_; }

    // list active interfaces using libpcap
    static void listInterfaces(std::ostream &os);

private:
    std::string interface_;
    int timeoutMs_{1000};
    pcap *pcapHandle_{nullptr};
    std::vector<NetworkRange> ranges_;
    ResultsStore results_;
    std::atomic<bool> stopRequested_{false};

    void sendLoop();
    void pcapLoop();
    static void pcapCallback(u_char *user, const struct pcap_pkthdr *h, const u_char *bytes);

    NetworkRange parseCidr(const std::string &cidr) const;
    static NetworkRange parseIpv4Cidr(const std::string &addrPart, std::uint8_t prefixLen);
    static NetworkRange parseIpv6Cidr(const std::string &addrPart, std::uint8_t prefixLen);

    static void appendIpv4Hosts(const NetworkRange &range, std::vector<std::string> &out);
    static void appendIpv6Hosts(const NetworkRange &range, std::vector<std::string> &out);
};

