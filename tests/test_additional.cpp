/**
 * @file test_additional.cpp
 * @brief Additional tests for the ipk-L2L3-scan program
 * @author Petr Vitula (xvitulp00)
 */
 

#include "Scanner.h"
#include "Results.h"
#include "Packets.h"

#include <cassert>
#include <iostream>
#include <sstream>
#include <string>
#include <cstring>
#include <vector>
#include <arpa/inet.h>

// TEST/TEST_OK/TEST_FAIL are defined in test_main.cpp
extern int tests_run;
extern int tests_failed;

#define TEST(name) do { \
    ++tests_run; \
    std::cout << "  [TEST] " << (name) << " ... "; \
    std::cout.flush(); \
} while(0)

#define TEST_OK() do { std::cout << "OK\n"; } while(0)
#define TEST_FAIL(msg) do { ++tests_failed; std::cout << "FAIL: " << (msg) << "\n"; } while(0)

// =============================================================================
// 1. CIDR normalization
// =============================================================================

// README explicitly mentions: "192.168.0.5/25" -> network "192.168.0.0/25"
static void test_cidr_normalization_ipv4() {
    TEST("CIDR normalization: 192.168.0.5/25 → network address 192.168.0.0/25");
    try {
        Scanner sc("lo", 1000);
        sc.addSubnet("192.168.0.5/25");
        std::ostringstream os;
        sc.printScanningSummary(os);
        std::string s = os.str();
        if (s.find("192.168.0.0/25") == std::string::npos) {
            TEST_FAIL("expected '192.168.0.0/25', got: " + s);
            return;
        }
        if (s.find("192.168.0.5") != std::string::npos) {
            TEST_FAIL("original address 192.168.0.5 must not be in summary");
            return;
        }
        TEST_OK();
    } catch (const std::exception &e) {
        TEST_FAIL(e.what());
    }
}

// /31 is RFC 3021 – both hosts are usable (base+0 and base+1)
static void test_cidr_ipv4_31() {
    TEST("CIDR 10.0.0.0/31 → 2 hosts: 10.0.0.0 a 10.0.0.1");
    try {
        Scanner sc("lo", 1000);
        sc.addSubnet("10.0.0.0/31");
        auto hosts = sc.generateHostIps();
        if (hosts.size() != 2u) {
            TEST_FAIL("expected 2 hosts, got " + std::to_string(hosts.size()));
            return;
        }
        bool has0 = (hosts[0] == "10.0.0.0" || hosts[1] == "10.0.0.0");
        bool has1 = (hosts[0] == "10.0.0.1" || hosts[1] == "10.0.0.1");
        if (!has0 || !has1) {
            TEST_FAIL("expected 10.0.0.0 and 10.0.0.1, got: " + hosts[0] + ", " + hosts[1]);
            return;
        }
        TEST_OK();
    } catch (const std::exception &e) {
        TEST_FAIL(e.what());
    }
}

// /29 → hosts .1 to .6, .0 (network) and .7 (broadcast) must not be included
static void test_cidr_ipv4_29_host_range() {
    TEST("CIDR 10.0.0.0/29 → hosts .1 to .6, without .0 and .7");
    try {
        Scanner sc("lo", 1000);
        sc.addSubnet("10.0.0.0/29");
        auto hosts = sc.generateHostIps();
        if (hosts.size() != 6u) {
            TEST_FAIL("expected 6 hosts, got " + std::to_string(hosts.size()));
            return;
        }
        for (auto &h : hosts) {
            if (h == "10.0.0.0") { TEST_FAIL("network address 10.0.0.0 must not be in list"); return; }
            if (h == "10.0.0.7") { TEST_FAIL("broadcast 10.0.0.7 must not be in list"); return; }
        }
        TEST_OK();
    } catch (const std::exception &e) {
        TEST_FAIL(e.what());
    }
}

// /25 → 126 hosts (README example)
static void test_cidr_ipv4_25_count() {
    TEST("CIDR 192.168.0.0/25 → 126 hosts (README example)");
    try {
        Scanner sc("lo", 1000);
        sc.addSubnet("192.168.0.0/25");
        auto hosts = sc.generateHostIps();
        if (hosts.size() != 126u) {
            TEST_FAIL("expected 126 hosts, got " + std::to_string(hosts.size()));
            return;
        }
        TEST_OK();
    } catch (const std::exception &e) {
        TEST_FAIL(e.what());
    }
}

// /128 → exactly 1 host = the same address
static void test_cidr_ipv6_128() {
    TEST("CIDR fd00::cafe/128 → 1 host = fd00::cafe");
    try {
        Scanner sc("lo", 1000);
        sc.addSubnet("fd00::cafe/128");
        auto hosts = sc.generateHostIps();
        if (hosts.size() != 1u) {
            TEST_FAIL("expected 1 host, got " + std::to_string(hosts.size()));
            return;
        }
        if (hosts[0] != "fd00::cafe") {
            TEST_FAIL("expected fd00::cafe, got " + hosts[0]);
            return;
        }
        TEST_OK();
    } catch (const std::exception &e) {
        TEST_FAIL(e.what());
    }
}

// IPv6 summary line v printScanningSummary
static void test_cidr_ipv6_summary() {
    TEST("printScanningSummary obsahuje IPv6 subnet s počtem hostů");
    try {
        Scanner sc("lo", 1000);
        sc.addSubnet("fd00::/126");
        std::ostringstream os;
        sc.printScanningSummary(os);
        std::string s = os.str();
        // inet_ntop compresses, so "fd00::/126"
        if (s.find("/126 3") == std::string::npos) {
            TEST_FAIL("expected '/126 3' in summary, got: " + s);
            return;
        }
        TEST_OK();
    } catch (const std::exception &e) {
        TEST_FAIL(e.what());
    }
}

// =============================================================================
// 2. ResultsStore: combination of L2/L3 states
// =============================================================================

// arp OK but icmpv4 FAIL (common case – host exists but blocks ping)
static void test_results_arp_ok_icmp_fail() {
    TEST("ResultsStore: arp OK + icmpv4 FAIL → correct output");
    try {
        ResultsStore r;
        r.initHost("10.0.0.1", false);
        r.updateL2Ok("10.0.0.1", "de-ad-be-ef-00-01");
        // L3 remains FAIL (initHost defaults to FAIL)

        std::ostringstream os;
        r.print(os);
        std::string s = os.str();

        if (s.find("arp OK (de-ad-be-ef-00-01)") == std::string::npos) {
            TEST_FAIL("expected 'arp OK (de-ad-be-ef-00-01)'");
            return;
        }
        if (s.find("icmpv4 FAIL") == std::string::npos) {
            TEST_FAIL("expected 'icmpv4 FAIL'");
            return;
        }
        TEST_OK();
    } catch (const std::exception &e) {
        TEST_FAIL(e.what());
    }
}

// arp FAIL but icmpv4 OK (less common but valid case)
static void test_results_arp_fail_icmp_ok() {
    TEST("ResultsStore: arp FAIL + icmpv4 OK → correct output");
    try {
        ResultsStore r;
        r.initHost("10.0.0.2", false);
        r.updateL3Ok("10.0.0.2");
        // L2 zůstane FAIL

        std::ostringstream os;
        r.print(os);
        std::string s = os.str();

        if (s.find("arp FAIL") == std::string::npos) {
            TEST_FAIL("expected 'arp FAIL'");
            return;
        }
        if (s.find("icmpv4 OK") == std::string::npos) {
            TEST_FAIL("expected 'icmpv4 OK'");
            return;
        }
        TEST_OK();
    } catch (const std::exception &e) {
        TEST_FAIL(e.what());
    }
}

// MAC must be lowercase and separated by hyphens (not colons)
static void test_results_mac_format() {
    TEST("ResultsStore: MAC format is lowercase hex with hyphens (00-1a-2b-3c-4d-5e)");
    try {
        ResultsStore r;
        r.initHost("10.1.1.1", false);
        r.updateL2Ok("10.1.1.1", "00-1a-2b-3c-4d-5e");

        std::ostringstream os;
        r.print(os);
        std::string s = os.str();

        if (s.find("00-1a-2b-3c-4d-5e") == std::string::npos) {
            TEST_FAIL("expected lowercase dash-separated MAC, got: " + s);
            return;
        }
        // Must not contain colons
        if (s.find("00:1a") != std::string::npos) {
            TEST_FAIL("MAC must not contain colons");
            return;
        }
        TEST_OK();
    } catch (const std::exception &e) {
        TEST_FAIL(e.what());
    }
}

// Multiple hosts – each on its own line
static void test_results_multiple_hosts() {
    TEST("ResultsStore: multiple hosts → each on its own line");
    try {
        ResultsStore r;
        r.initHost("10.0.0.1", false);
        r.initHost("10.0.0.2", false);
        r.initHost("10.0.0.3", false);
        r.updateL2Ok("10.0.0.1", "aa-bb-cc-dd-ee-01");
        r.updateL3Ok("10.0.0.2");

        std::ostringstream os;
        r.print(os);
        std::string s = os.str();

        // Count lines – must be 3
        int lines = 0;
        for (char c : s) if (c == '\n') ++lines;
        if (lines != 3) {
            TEST_FAIL("expected 3 lines, got " + std::to_string(lines) + ": " + s);
            return;
        }
        TEST_OK();
    } catch (const std::exception &e) {
        TEST_FAIL(e.what());
    }
}

// =============================================================================
// 3. Packet building
// =============================================================================

// ARP frame must have the correct length and broadcast dst MAC
static void test_arp_frame_structure() {
    TEST("buildArpRequestFrame: length 42B, dst=broadcast, ethertype=0x0806");
    try {
        std::uint8_t ourMac[6]    = {0x52, 0x54, 0x00, 0x12, 0x34, 0x56};
        std::uint8_t ourIp[4]     = {10, 0, 0, 1};
        std::uint8_t targetIp[4]  = {10, 0, 0, 2};

        auto frame = buildArpRequestFrame(ourMac, ourIp, targetIp);

        if (frame.size() != 42u) {
            TEST_FAIL("expected 42 bytes, got " + std::to_string(frame.size()));
            return;
        }
        // dst MAC = broadcast
        for (int i = 0; i < 6; ++i) {
            if (frame[i] != 0xff) {
                TEST_FAIL("dst MAC byte " + std::to_string(i) + " is not 0xff");
                return;
            }
        }
        // EtherType = 0x0806 (ARP) in network byte order = [0x08, 0x06]
        if (frame[12] != 0x08 || frame[13] != 0x06) {
            TEST_FAIL("EtherType mismatch: expected 08 06");
            return;
        }
        // ARP op = request (1) in network order = [0x00, 0x01]
        if (frame[20] != 0x00 || frame[21] != 0x01) {
            TEST_FAIL("ARP op mismatch: expected 00 01 (request)");
            return;
        }
        TEST_OK();
    } catch (const std::exception &e) {
        TEST_FAIL(e.what());
    }
}

// ICMPv4 echo request must have type=8, code=0, non-zero checksum
static void test_icmpv4_echo_request_structure() {
    TEST("buildIcmpv4EchoRequest: type=8, code=0, checksum≠0");
    try {
        auto buf = buildIcmpv4EchoRequest(0x1234, 1);

        if (buf.size() < 8u) {
            TEST_FAIL("buffer too short: " + std::to_string(buf.size()));
            return;
        }
        if (buf[0] != 8) {
            TEST_FAIL("type != 8 (ECHO_REQUEST), got " + std::to_string(buf[0]));
            return;
        }
        if (buf[1] != 0) {
            TEST_FAIL("code != 0, got " + std::to_string(buf[1]));
            return;
        }
        uint16_t checksum = (static_cast<uint16_t>(buf[2]) << 8) | buf[3];
        if (checksum == 0) {
            TEST_FAIL("checksum is 0 (probably not calculated)");
            return;
        }
        // Verification: checksum through the entire packet must give 0 (RFC 1071)
        uint32_t sum = 0;
        for (size_t i = 0; i + 1 < buf.size(); i += 2) {
            sum += (static_cast<uint16_t>(buf[i]) << 8) | buf[i+1];
        }
        if (buf.size() & 1) sum += static_cast<uint16_t>(buf.back()) << 8;
        while (sum >> 16) sum = (sum & 0xFFFF) + (sum >> 16);
        uint16_t result = static_cast<uint16_t>(~sum);
        if (result != 0 && result != 0xFFFF) {
            TEST_FAIL("checksum verification failed, result=0x" + 
                      std::to_string(result));
            return;
        }
        TEST_OK();
    } catch (const std::exception &e) {
        TEST_FAIL(e.what());
    }
}

// inetChecksum: verification using known-good ICMP Echo Request value
static void test_checksum_known_value() {
    TEST("inetChecksum: known-good ICMP Echo Request → checksum verified");
    // ICMP Echo Request: type=8, code=0, csum=0, id=0x0001, seq=0x0001, data="Hello"
    // Correct checksum calculated manually
    std::uint8_t pkt[] = {
        0x08, 0x00,  // type=8, code=0
        0x00, 0x00,  // checksum placeholder
        0x00, 0x01,  // id=1
        0x00, 0x01,  // seq=1
        0x48, 0x65, 0x6c, 0x6c, 0x6f  // "Hello"
    };
    std::uint16_t csum = inetChecksum(pkt, sizeof(pkt));
    // Insert checksum and verify
    pkt[2] = (csum >> 8) & 0xFF;
    pkt[3] = csum & 0xFF;
    std::uint16_t verify = inetChecksum(pkt, sizeof(pkt));
    if (verify != 0xFFFF && verify != 0x0000) {
        std::ostringstream msg;
        msg << "checksum verification failed: 0x" << std::hex << verify;
        TEST_FAIL(msg.str());
        return;
    }
    TEST_OK();
}

// =============================================================================
// 4. Output format edge cases
// =============================================================================

// Empty ResultsStore → empty output (no hosts)
static void test_results_empty_store() {
    TEST("ResultsStore: empty store → empty output");
    try {
        ResultsStore r;
        std::ostringstream os;
        r.print(os);
        if (!os.str().empty()) {
            TEST_FAIL("expected empty output, got: " + os.str());
            return;
        }
        TEST_OK();
    } catch (const std::exception &e) {
        TEST_FAIL(e.what());
    }
}

// Scanning ranges header must start exactly with "Scanning ranges:\n"
static void test_summary_header_format() {
    TEST("printScanningSummary: starts exactly with 'Scanning ranges:\\n'");
    try {
        Scanner sc("lo", 1000);
        sc.addSubnet("10.0.0.0/30");
        std::ostringstream os;
        sc.printScanningSummary(os);
        std::string s = os.str();
        if (s.substr(0, 17) != "Scanning ranges:\n") {
            TEST_FAIL("header mismatch: '" + s.substr(0, 20) + "'");
            return;
        }
        TEST_OK();
    } catch (const std::exception &e) {
        TEST_FAIL(e.what());
    }
}

// =============================================================================
// Entry point for additional tests
// =============================================================================

void run_additional_tests() {
    std::cout << "\n--- Additional tests (CIDR, ResultsStore, Packets) ---\n";

    // CIDR
    test_cidr_normalization_ipv4();
    test_cidr_ipv4_31();
    test_cidr_ipv4_29_host_range();
    test_cidr_ipv4_25_count();
    test_cidr_ipv6_128();
    test_cidr_ipv6_summary();

    // ResultsStore
    test_results_arp_ok_icmp_fail();
    test_results_arp_fail_icmp_ok();
    test_results_mac_format();
    test_results_multiple_hosts();

    // Packets
    test_arp_frame_structure();
    test_icmpv4_echo_request_structure();
    test_checksum_known_value();

    // Output format
    test_results_empty_store();
    test_summary_header_format();
}
