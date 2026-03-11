/**
 * Unit tests for IPK L2/L3 Scanner.
 * Run via: make test
 * No sudo or network interface needed (except for integration tests).
 */

#include "Scanner.h"
#include "Results.h"
#include "Packets.h"

#include <cassert>
#include <iostream>
#include <sstream>
#include <string>
#include <cstring>

static int tests_run = 0;
static int tests_failed = 0;

#define TEST(name) do { \
    ++tests_run; \
    std::cout << "  [TEST] " << (name) << " ... "; \
    std::cout.flush(); \
} while(0)

#define TEST_OK() do { std::cout << "OK\n"; } while(0)
#define TEST_FAIL(msg) do { ++tests_failed; std::cout << "FAIL: " << (msg) << "\n"; } while(0)

// --- 1. Parsing CIDR ------------------------------------------------------

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

// -----------------------------------------------------------------------------

int main() {
    std::cout << "Unit tests – IPK L2/L3 Scanner\n";
    std::cout << "----------------------------------------\n";

    test_cidr_ipv4_30();
    test_cidr_ipv4_32();
    test_cidr_ipv6_126();
    test_cidr_summary_counts();
    test_results_store_update_no_duplicate();
    test_checksum_zeros();
    test_checksum_icmp_echo_request();
    test_invalid_cidr_throws();
    test_invalid_cidr_no_slash();

    std::cout << "----------------------------------------\n";
    std::cout << "Total: " << tests_run << " tests, " << tests_failed << " failed.\n";
    return tests_failed ? 1 : 0;
}
