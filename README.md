IPK Project 1 – L2/L3 Network Scanner
=====================================

Overview
--------

This project implements a simple L2/L3 host discovery scanner for IPv4 and IPv6 as required by the IPK Project 1 assignment. The application sends ARP/NDP requests on the local link and ICMP echo requests (IPv4/IPv6) to discover reachable hosts in configured subnets and prints a summary of scanned ranges together with per‑host results.

The implementation is **Linux-only**. It uses raw sockets (ARP, ICMPv4, ICMPv6) and `libpcap` for passive packet capture. Platform-dependent behaviour (e.g. Linux-only APIs) is explicitly marked in the source files (see `Scanner.h`, `Scanner.cpp`, `main.cpp`).

Build and Run
-------------

**Prerequisites (reference environment):**

- IPK reference devShell `c` (C/C++ environment with `g++`, `libpcap`, make, etc.).
- Linux with root privileges for raw sockets and packet capture.

**Select devShell (required by guidelines):**

```bash
make NixDevShellName
```

This prints `c`, which is used by the IPK infrastructure to activate the correct devShell.

**Build:**

```bash
make
```

This produces the executable `./ipk-L2L3-scan` in the project root as required by the assignment.

**Run:**

```bash
sudo ./ipk-L2L3-scan -i INTERFACE [-s SUBNET]... [-w TIMEOUT]
```

- `-i INTERFACE` – name of the network interface (e.g. `eth0`, `enp0s3`).
- `-s SUBNET` – IPv4/IPv6 subnet in CIDR notation (e.g. `192.168.1.0/24`, `fd00::1/126`), may be repeated.
- `-w TIMEOUT` – overall wait time in milliseconds after sending probes, before finalizing FAIL statuses.

The program also supports:

- `./ipk-L2L3-scan -i` – list non‑loopback interfaces (printed to stdout).
- `./ipk-L2L3-scan -h` or `./ipk-L2L3-scan --help` – show detailed usage (printed to stdout).

**Exit codes** (see `sysexits.h`): `0` = success; `EX_USAGE` (64) = invalid or missing arguments / invalid CIDR; `EX_OSERR` (71) = runtime failure (e.g. pcap, socket).

Implemented Features and Behavior
---------------------------------

- **Interface discovery**:
  - Lists non‑loopback interfaces using `libpcap` (`Scanner::listInterfaces`).
  - For the selected interface, retrieves MAC address, IPv4/IPv6 addresses and ifindex via `ioctl`/`getifaddrs`.

- **CIDR parsing and host generation**:
  - Supports IPv4 and IPv6 CIDR notation.
  - Correct handling of special IPv4 prefixes:
    - `/32`: exactly one host – the given address.
    - `/31`: RFC 3021 point‑to‑point, **both** addresses are usable.
    - Other prefixes: `2^(32-prefix) - 2` usable hosts (network and broadcast excluded).
  - IPv6:
    - `/128`: exactly one host – the given address.
    - Other prefixes: `2^(128-prefix) - 1` usable hosts (network address excluded) to match the assignment README example for `/126`.
  - Generated host lists are deterministic and used both by the sender and by unit tests.

- **Protection against huge ranges (design decision)**:
  - To avoid freezes and out‑of‑memory situations on very large subnets (e.g. `/8`), each `-s` subnet is limited to at most **65 536 usable hosts**.
  - If this limit would be exceeded, the scanner throws `std::invalid_argument` with a descriptive message and exits with a non‑zero status.

- **Packet sending**:
  - ARP requests (IPv4) are sent using an `AF_PACKET` raw socket with Ethernet frames constructed in `Packets.cpp`.
  - ICMPv4 echo requests:
    - Sent via `AF_INET` raw socket bound to the selected interface (using `SO_BINDTODEVICE`) and to the interface IPv4 address.
    - Uses a process‑wide ICMP identifier derived from `getpid()`, matching replies in `pcapCallback`.
  - NDP (IPv6):
    - Sends Neighbor Solicitation messages to the solicited‑node multicast address `ff02::1:ffXX:XXXX`.
  - ICMPv6 echo requests:
    - Sent via `AF_INET6` raw socket bound to the interface IPv6 address and scope id.
    - ICMPv6 checksum is calculated over the IPv6 pseudo‑header.

- **Packet capture and reply processing**:
  - Uses `libpcap` in a dedicated receive thread.
  - Supports multiple link‑layer types:
    - Ethernet (`DLT_EN10MB`), VLAN‑tagged Ethernet, Linux cooked capture v1 (`DLT_LINUX_SLL`), Linux cooked capture v2 (`DLT_LINUX_SLL2`).
  - Correct parsing of EtherType and dynamic offset based on link type and presence of 802.1Q tags.
  - ARP Reply:
    - Extracts sender IPv4 and MAC address, marks `arp OK` for that IPv4 host.
  - IPv4 ICMP:
    - Recognizes ICMP Echo Reply (type 0) with matching identifier.
    - Marks `icmpv4 OK` for the source IPv4 address.
  - IPv6:
    - NDP Neighbor Advertisement:
      - Parses Target Link‑Layer Address option (type 2) when present.
      - Falls back to link‑layer source MAC when the option is missing.
      - Marks `ndp OK` for the target IPv6 address.
    - ICMPv6 Echo Reply:
      - Marks `icmpv6 OK` for the source IPv6 address.

- **Timeout behavior**:
  - The `-w TIMEOUT` argument controls how long, after sending all probes, the scanner keeps waiting for replies before finalizing results.
  - Replies are processed and statuses (`OK`) are updated **immediately** when packets are captured.
  - Hosts that never receive a matching reply remain in the default `FAIL` state after the timeout expires.
  - `libpcap` uses its own small read timeout (100 ms) so packet delivery is prompt even for large `-w` values.

Source code structure
---------------------

The project is split into meaningful modules with clear responsibilities:

| Module | Role |
|--------|------|
| **main.cpp** | Entry point; CLI argument parsing (`Config`, `parseArguments`, `printUsage`); orchestration of help, list-interfaces, and scan modes. |
| **Scanner** (`Scanner.h`, `Scanner.cpp`) | Core scan logic: CIDR parsing and host list generation, libpcap setup, send loop (ARP/NDP/ICMP), pcap callback for reply handling, interface listing. |
| **Results** (`Results.h`, `Results.cpp`) | Storage and formatted output of per-host L2/L3 status (OK/FAIL, MAC). |
| **Packets** (`Packets.h`, `Packets.cpp`) | Packet construction and checksums: ARP request frame, ICMPv4/ICMPv6 echo request, NDP solicitation, RFC 1071 checksum. |
| **SignalHandler** (`SignalHandler.h`, `SignalHandler.cpp`) | Signal setup for graceful termination (SIGINT/SIGTERM). |

Source files use section comments and short, focused functions so the code stays readable and maintainable.

Important Design Decisions
--------------------------

The assignment allows several behaviors to be chosen by the student. The following decisions are **intentional** and are documented here as required by the guidelines:

1. **Limit on hosts per subnet**  
   - Decision: limit each `-s` subnet to at most **65 536 usable hosts**.  
   - Rationale: protects the application and the reference VM from freezes and excessive memory usage when scanning very large ranges (for example, `10.0.0.0/8`).  
   - Behavior: if the limit would be exceeded, the application prints an error (to stderr) and exits with a non‑zero code.

2. **IPv4 `/31` semantics**  
   - Decision: follow RFC 3021 – both addresses in `/31` are treated as usable hosts.  
   - Rationale: this is common for point‑to‑point links (no traditional broadcast address).

3. **IPv6 usable host count**  
   - Decision: for prefixes other than `/128`, the scanner uses `2^(hostBits) - 1` usable hosts (excluding only the network address).  
   - Rationale: matches the IPv6 `/126` example in the project README and keeps behavior simple and predictable.

4. **Interface selection and Linux‑only behavior**  
   - Decision: the implementation uses Linux‑specific APIs (`AF_PACKET`, `SO_BINDTODEVICE`, `pcap_datalink` with Linux SLL types).  
   - Rationale: the assignment is evaluated on the Linux reference VM; this simplifies the implementation and packet handling.

5. **ICMPv4 reply handling source**  
   - Decision: ICMPv4 replies are detected exclusively via `libpcap` (no `recvfrom` on the raw socket).  
   - Rationale: ensures a single, consistent code path for reply processing and avoids double handling and timeout inconsistencies.

Testing
-------

All results below are **textual** (no screenshots), so tests are reproducible from the same environment.

**How to execute automated tests**

```bash
make test
```

This builds `ipk-L2L3-scan-test` and runs the test suite. No root or live network is required.

**Reproducibility and environment**

- **Environment:** Linux (e.g. IPK reference VM or any x86_64-linux with devShell `c`). Build with `make` first. Activate devShell via `make NixDevShellName` (prints `c`).
- **Software (reference):** C++17 (g++), libpcap, make. No special topology for unit tests—they use only in-memory API calls.
- **Reproducibility:** From the same tree and environment, `make test` yields the same outcome; the full output is given below so evaluators can compare.

**What was tested**

- **Normal behaviour:** CIDR parsing and host list generation (e.g. `/30` → 2 hosts, `/126` → 3 hosts); correct summary lines; result formatting (arp/ndp OK or FAIL, icmpv4/icmpv6 OK or FAIL, MAC in `xx-xx-xx-xx-xx-xx`); checksums (RFC 1071) and packet layout (ARP frame, ICMP echo request).
- **Edge cases:** `/32` and `/128` (single host); `/31` (RFC 3021, two hosts); invalid CIDR (no slash, bad address, prefix &gt; 32 for IPv4); empty result store; overwriting same IP (no duplicate lines); combined output format (header, blank line, then per-host lines).

**Why it was tested**

To ensure the implementation matches the assignment specification, handles boundary cases correctly, and does not regress when code changes.

**How it was tested**

Unit tests in `tests/test_main.cpp` and `tests/test_additional.cpp` call `Scanner`, `ResultsStore`, and `Packets` APIs with fixed inputs, then assert on returned values and on strings produced by `printScanningSummary` / `ResultsStore::print`. No network I/O or real interfaces are used. Manual integration checks (optional) were done on Linux with QEMU/VirtualBox and `tcpdump`.

**Testing environment (summary)**

| Aspect | Detail |
|--------|--------|
| OS / platform | Linux (x86_64), reference devShell `c` |
| Build | `make` in project root |
| Test command | `make test` |
| Network topology (unit tests) | None; tests are offline |

**Inputs, expected outputs, and actual outputs**

Examples (unit tests):

| What | Input (or action) | Expected output | Actual output |
|------|-------------------|-----------------|---------------|
| CIDR /30 | `addSubnet("192.168.1.0/30")`, `generateHostIps()` | 2 hosts: 192.168.1.1, 192.168.1.2 | 2 hosts, correct addresses |
| CIDR /31 | `addSubnet("10.0.0.0/31")` | 2 hosts: 10.0.0.0, 10.0.0.1 | 2 hosts, 10.0.0.0 and 10.0.0.1 |
| CIDR /32 | `addSubnet("10.0.0.5/32")` | 1 host: 10.0.0.5 | 1 host, 10.0.0.5 |
| Invalid CIDR | `addSubnet("999.999.999.999/99")` | exception | `std::invalid_argument` thrown |
| CIDR no slash | `addSubnet("192.168.1.1")` | exception | `std::invalid_argument` thrown |
| Result format | `initHost("192.168.1.10", false)`, L2/L3 FAIL, `print(os)` | line with `arp FAIL`, `icmpv4 FAIL` | Output contains exactly that |
| Checksum | 8 zero bytes → `inetChecksum` | 0xFFFF (RFC 1071) | 0xFFFF |

Full automated run (actual output from `make test`):

```
Unit tests – IPK L2/L3 Scanner
----------------------------------------
  [TEST] CIDR 192.168.1.0/30 → 2 hosts (without network and broadcast) ... OK
  [TEST] CIDR 10.0.0.5/32 → 1 host ... OK
  [TEST] CIDR fd00::1/126 → 3 hosts (according to README) ... OK
  [TEST] Scanning ranges: number of hosts /30=2, /29=6 ... OK
  [TEST] ResultsStore: same IP twice → overwrites, one line in output ... OK
  [TEST] ResultsStore: IPv4 host with L2/L3 FAIL printed with arp/icmpv4 FAIL ... OK
  [TEST] ResultsStore: IPv6 host uses ndp/icmpv6 literals ... OK
  [TEST] inetChecksum: 8 zero bytes → 0xFFFF (RFC 1071) ... OK
  [TEST] inetChecksum: známý ICMP Echo Request (type=8, code=0, csum=0, id=1, seq=0) ... OK
  [TEST] Invalid CIDR 999.999.999.999/99 → exception ... OK
  [TEST] CIDR without slash → exception ... OK
  [TEST] CIDR with prefix > 32 for IPv4 → exception ... OK
  [TEST] Combined output format: ranges summary, empty line, then per-host results ... OK

--- Additional tests (CIDR, ResultsStore, Packets) ---
  [TEST] CIDR normalization: 192.168.0.5/25 → network address 192.168.0.0/25 ... OK
  [TEST] CIDR 10.0.0.0/31 → 2 hosts: 10.0.0.0 a 10.0.0.1 ... OK
  [TEST] CIDR 10.0.0.0/29 → hosts .1 to .6, without .0 and .7 ... OK
  [TEST] CIDR 192.168.0.0/25 → 126 hosts (README example) ... OK
  [TEST] CIDR fd00::cafe/128 → 1 host = fd00::cafe ... OK
  [TEST] printScanningSummary obsahuje IPv6 subnet s počtem hostů ... OK
  [TEST] ResultsStore: arp OK + icmpv4 FAIL → correct output ... OK
  [TEST] ResultsStore: arp FAIL + icmpv4 OK → correct output ... OK
  [TEST] ResultsStore: MAC format is lowercase hex with hyphens (00-1a-2b-3c-4d-5e) ... OK
  [TEST] ResultsStore: multiple hosts → each on its own line ... OK
  [TEST] buildArpRequestFrame: length 42B, dst=broadcast, ethertype=0x0806 ... OK
  [TEST] buildIcmpv4EchoRequest: type=8, code=0, checksum≠0 ... OK
  [TEST] inetChecksum: known-good ICMP Echo Request → checksum verified ... OK
  [TEST] ResultsStore: empty store → empty output ... OK
  [TEST] printScanningSummary: starts exactly with 'Scanning ranges:\n' ... OK
----------------------------------------
Total: 28 tests, 0 failed.
```

**Our test set**

The test suite in `tests/` is our own: written for this project to cover the assignment specification and edge cases. It is not taken from a third-party package.

**Comparison with comparable tools**

Tools such as **nmap** (e.g. `-sn` for host discovery), **arp-scan**, or **ping** also perform L2/L3 discovery. This project is a minimal implementation for the assignment: it does not aim to replace nmap. Differences: our output is a fixed text format (one line per host with arp/ndp and icmpv4/icmpv6 status); we support both IPv4 and IPv6 in one run; we use raw sockets and libpcap directly rather than a high-level library. For validation we compared packet structure with `tcpdump` and behaviour with manual `ping`/ARP where relevant.

Known Limitations
-----------------

- **Linux‑only implementation**  
  The scanner uses Linux‑specific APIs (`AF_PACKET`, `SO_BINDTODEVICE`, Linux SLL link types). Other operating systems are not supported.

- **Per‑subnet host limit**  
  Subnets with more than **65 536 usable hosts** are rejected with an error. This is a deliberate safety limit, not a bug.

- **Environment‑dependent ICMPv4 replies**  
  Some network environments (for example, certain virtualized gateways) selectively ignore ICMP echo requests sent from raw sockets even though they reply to the standard `ping(8)` utility. In such cases the scanner may legitimately report `icmpv4 FAIL` even though `ping` appears to work. The implementation has been validated at the packet level using `tcpdump`; this is considered an environmental limitation.

Apart from the limitations explicitly listed above, **no other known limitations** are present at the time of submission.

References / sources used
-------------------------

- IPK Project Guidelines and assignment text (NES@FIT, VUT Brno).
- Linux manual pages: `man 7 raw`, `man 7 packet`, `man 7 ip`, `man 7 icmp`, `man 7 icmp6`, `man 3 sysexits`.
- libpcap documentation and examples (packet capture API).
- RFC 1071 – Computing the Internet Checksum.
- RFC 3021 – Using 31‑Bit Prefixes on IPv4 Point‑to‑Point Links.
- RFC 4861 – Neighbor Discovery for IP version 6 (NDP, ICMPv6).
