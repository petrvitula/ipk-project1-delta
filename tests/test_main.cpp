/**
 * @file test_main.cpp
 * @brief Main tests for the ipk-L2L3-scan program
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

int tests_run = 0;
int tests_failed = 0;

#define TEST(name) do { \
    ++tests_run; \
    std::cout << "  [TEST] " << (name) << " ... "; \
    std::cout.flush(); \
} while(0)

#define TEST_OK() do { std::cout << "OK\n"; } while(0)
#define TEST_FAIL(msg) do { ++tests_failed; std::cout << "FAIL: " << (msg) << "\n"; } while(0)

// Additional tests implemented in separate translation unit.
// Declared here so we can call them from main().
void run_additional_tests();

// --- 1. Parsing CIDR ------------------------------------------------------

// Basic IPv4 /30 range – verify that network and broadcast are excluded
static void test_cidr_ipv4_30() {
    TEST("CIDR 192.168.1.0/30 → 2 hosts (without network and broadcast)");
    try {
        Scanner sc("lo", 1000);
        sc.addSubnet("192.168.1.0/30");
        auto hosts = sc.generateHostIps();
        if (hosts.size() != 2u) {
            TEST_FAIL("expected 2 addresses, got " + std::to_string(hosts.size()));
            return;
        }
        bool has1 = (hosts[0] == "192.168.1.1" || hosts[1] == "192.168.1.1");
        bool has2 = (hosts[0] == "192.168.1.2" || hosts[1] == "192.168.1.2");
        if (!has1 || !has2) {
            TEST_FAIL("expected 192.168.1.1 and 192.168.1.2");
            return;
        }
        TEST_OK();
    } catch (const std::exception &e) {
        TEST_FAIL(e.what());
    }
}

// Single-host IPv4 /32 range – exactly one concrete host
static void test_cidr_ipv4_32() {
    TEST("CIDR 10.0.0.5/32 → 1 host");
    try {
        Scanner sc("lo", 1000);
        sc.addSubnet("10.0.0.5/32");
        auto hosts = sc.generateHostIps();
        if (hosts.size() != 1u) {
            TEST_FAIL("expected 1 address, got " + std::to_string(hosts.size()));
            return;
        }
        if (hosts[0] != "10.0.0.5") {
            TEST_FAIL("expected 10.0.0.5, got " + hosts[0]);
            return;
        }
        TEST_OK();
    } catch (const std::exception &e) {
        TEST_FAIL(e.what());
    }
}

// IPv6 /126 range – number of usable hosts taken from README example
static void test_cidr_ipv6_126() {
    TEST("CIDR fd00::1/126 → 3 hosts (according to README)");
    try {
        Scanner sc("lo", 1000);
        sc.addSubnet("fd00::1/126");
        auto hosts = sc.generateHostIps();
        if (hosts.size() != 3u) {
            TEST_FAIL("expected 3 addresses, got " + std::to_string(hosts.size()));
            return;
        }
        TEST_OK();
    } catch (const std::exception &e) {
        TEST_FAIL(e.what());
    }
}

// Summary lines must contain correct usable host counts for two IPv4 ranges
static void test_cidr_summary_counts() {
    TEST("Scanning ranges: number of hosts /30=2, /29=6");
    try {
        Scanner sc("lo", 1000);
        sc.addSubnet("192.168.0.0/30");
        sc.addSubnet("192.168.0.128/29");
        std::ostringstream os;
        sc.printScanningSummary(os);
        std::string s = os.str();
        if (s.find("192.168.0.0/30 2") == std::string::npos) {
            TEST_FAIL("expected line '192.168.0.0/30 2'");
            return;
        }
        if (s.find("192.168.0.128/29 6") == std::string::npos) {
            TEST_FAIL("expected line '192.168.0.128/29 6'");
            return;
        }
        TEST_OK();
    } catch (const std::exception &e) {
        TEST_FAIL(e.what());
    }
}

// --- 2. ResultsStore: overwrite at the same IP, no duplicates -----------------

// When the same IPv4 host is updated multiple times, only one line should be printed
static void test_results_store_update_no_duplicate() {
    TEST("ResultsStore: same IP twice → overwrites, one line in output");
    try {
        ResultsStore r;
        r.initHost("192.168.1.1", false);
        r.updateL2Ok("192.168.1.1", "aa-bb-cc-dd-ee-ff");
        r.updateL3Ok("192.168.1.1");
        r.updateL2Ok("192.168.1.1", "11-22-33-44-55-66"); // overwrite MAC
        std::ostringstream os;
        r.print(os);
        std::string s = os.str();
        if (s.find("192.168.1.1") == std::string::npos) {
            TEST_FAIL("missing 192.168.1.1 in output");
            return;
        }
        if (s.find("arp OK") == std::string::npos) {
            TEST_FAIL("missing arp OK in output");
            return;
        }
        if (s.find("icmpv4 OK") == std::string::npos) {
            TEST_FAIL("missing icmpv4 OK in output");
            return;
        }
        // Number of lines containing 192.168.1.1 should be 1 (no duplicates)
        size_t count = 0;
        for (size_t i = 0; (i = s.find("192.168.1.1", i)) != std::string::npos; ++i, ++count) {}
        if (count != 1u) {
            TEST_FAIL("expected 1 line with 192.168.1.1, found " + std::to_string(count));
            return;
        }
        TEST_OK();
    } catch (const std::exception &e) {
        TEST_FAIL(e.what());
    }
}

// IPv4 host with explicit FAIL statuses on both layers uses arp/icmpv4 literals
static void test_results_store_fail_ipv4() {
    TEST("ResultsStore: IPv4 host with L2/L3 FAIL printed with arp/icmpv4 FAIL");
    try {
        ResultsStore r;
        r.initHost("192.168.1.10", false);
        // Explicitly set both layers to FAIL to make intent clear, even though
        // initHost already initializes them to FAIL.
        r.updateL2Fail("192.168.1.10");
        r.updateL3Fail("192.168.1.10");

        std::ostringstream os;
        r.print(os);
        std::string s = os.str();

        if (s.find("192.168.1.10") == std::string::npos) {
            TEST_FAIL("missing 192.168.1.10 in output");
            return;
        }
        if (s.find("arp FAIL") == std::string::npos) {
            TEST_FAIL("expected 'arp FAIL' for IPv4 host");
            return;
        }
        if (s.find("icmpv4 FAIL") == std::string::npos) {
            TEST_FAIL("expected 'icmpv4 FAIL' for IPv4 host");
            return;
        }
        TEST_OK();
    } catch (const std::exception &e) {
        TEST_FAIL(e.what());
    }
}

// IPv6 host – check that ndp/icmpv6 literals are used and statuses are OK
static void test_results_store_ipv6_ok() {
    TEST("ResultsStore: IPv6 host uses ndp/icmpv6 literals");
    try {
        ResultsStore r;
        r.initHost("fd00::1", true);
        r.updateL2Ok("fd00::1", "aa-bb-cc-dd-ee-ff");
        r.updateL3Ok("fd00::1");

        std::ostringstream os;
        r.print(os);
        std::string s = os.str();

        if (s.find("fd00::1") == std::string::npos) {
            TEST_FAIL("missing fd00::1 in output");
            return;
        }
        if (s.find("ndp OK") == std::string::npos) {
            TEST_FAIL("expected 'ndp OK' for IPv6 host");
            return;
        }
        if (s.find("icmpv6 OK") == std::string::npos) {
            TEST_FAIL("expected 'icmpv6 OK' for IPv6 host");
            return;
        }
        TEST_OK();
    } catch (const std::exception &e) {
        TEST_FAIL(e.what());
    }
}

// --- 3. Checksum -------------------------------------------------------------

static void test_checksum_zeros() {
    TEST("inetChecksum: 8 zero bytes → 0xFFFF (RFC 1071)");
    std::uint8_t zeros[8] = {0, 0, 0, 0, 0, 0, 0, 0};
    std::uint16_t csum = inetChecksum(zeros, 8);
    if (csum != 0xFFFF) {
        std::ostringstream msg;
        msg << "expected 0xFFFF, got 0x" << std::hex << csum;
        TEST_FAIL(msg.str());
        return;
    }
    TEST_OK();
}

static void test_checksum_icmp_echo_request() {
    TEST("inetChecksum: známý ICMP Echo Request (type=8, code=0, csum=0, id=1, seq=0)");
    // After calculating the checksum, the packet should be valid; we check that the function returns a consistent value
    std::uint8_t icmp[8] = { 8, 0, 0, 0, 0, 1, 0, 0 }; // id=1, seq=0 v network order
    std::uint16_t csum = inetChecksum(icmp, 8);
    (void)csum;
    // Check: checksum must not be 0 (because then it would be invalid)
    if (csum == 0) {
        TEST_FAIL("checksum 0 is invalid for ICMP");
        return;
    }
    TEST_OK();
}

// --- 4. Invalid arguments (logic in main – test via exceptions / Scanner) --

// Completely invalid IPv4 address and prefix should be rejected
static void test_invalid_cidr_throws() {
    TEST("Invalid CIDR 999.999.999.999/99 → exception");
    try {
        Scanner sc("lo", 1000);
        sc.addSubnet("999.999.999.999/99");
        TEST_FAIL("expected exception when invalid IP");
    } catch (const std::exception &) {
        TEST_OK();
    }
}

// CIDR string without slash should be rejected
static void test_invalid_cidr_no_slash() {
    TEST("CIDR without slash → exception");
    try {
        Scanner sc("lo", 1000);
        sc.addSubnet("192.168.1.1");
        TEST_FAIL("expected exception when missing prefix");
    } catch (const std::exception &) {
        TEST_OK();
    }
}

// Prefix length outside valid IPv4 range (0–32) should cause an exception
static void test_invalid_cidr_prefix_too_large() {
    TEST("CIDR with prefix > 32 for IPv4 → exception");
    try {
        Scanner sc("lo", 1000);
        sc.addSubnet("192.168.0.0/33");
        TEST_FAIL("expected exception when prefix length is too large");
    } catch (const std::exception &) {
        TEST_OK();
    }
}

// Combined output format: "Scanning ranges" header, empty line, then host results
static void test_combined_output_format() {
    TEST("Combined output format: ranges summary, empty line, then per-host results");
    try {
        Scanner sc("lo", 1000);
        sc.addSubnet("192.168.0.0/30");

        std::ostringstream os;
        sc.printScanningSummary(os);
        os << "\n";

        // Simulate one host result: arp OK with MAC, icmpv4 FAIL
        ResultsStore &res = sc.results();
        res.initHost("192.168.0.1", false);
        res.updateL2Ok("192.168.0.1", "00-11-22-33-44-55");
        res.updateL3Fail("192.168.0.1");
        res.print(os);

        std::string s = os.str();

        // The very first line must be the literal "Scanning ranges:"
        std::istringstream is(s);
        std::string firstLine;
        std::getline(is, firstLine);
        if (firstLine != "Scanning ranges:") {
            TEST_FAIL("first line must be exactly 'Scanning ranges:'");
            return;
        }

        // There must be an empty line separating summary and results section
        if (s.find("\n\n192.168.0.1") == std::string::npos) {
            TEST_FAIL("expected empty line between summary and first host result");
            return;
        }

        // Host result line must follow the exact format from README
        if (s.find("192.168.0.1 arp OK (00-11-22-33-44-55), icmpv4 FAIL") == std::string::npos) {
            TEST_FAIL("host result line does not match expected format");
            return;
        }

        TEST_OK();
    } catch (const std::exception &e) {
        TEST_FAIL(e.what());
    }
}

// -----------------------------------------------------------------------------

int main() {
    std::cout << "Unit tests – IPK L2/L3 Scanner\n";
    std::cout << "----------------------------------------\n";

    test_cidr_ipv4_30();
    test_cidr_ipv4_32();
    test_cidr_ipv6_126();
    test_cidr_summary_counts();
    test_results_store_update_no_duplicate();
    test_results_store_fail_ipv4();
    test_results_store_ipv6_ok();
    test_checksum_zeros();
    test_checksum_icmp_echo_request();
    test_invalid_cidr_throws();
    test_invalid_cidr_no_slash();
    test_invalid_cidr_prefix_too_large();
    test_combined_output_format();

    // Run any additional tests defined in tests/test_additional.cpp
    run_additional_tests();

    std::cout << "----------------------------------------\n";
    std::cout << "Total: " << tests_run << " tests, " << tests_failed << " failed.\n";
    return tests_failed ? 1 : 0;
}
