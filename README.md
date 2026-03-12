IPK Project 1 – L2/L3 Network Scanner
=====================================

Overview
--------

This project implements a simple L2/L3 host discovery scanner for IPv4 and IPv6 as required by the IPK Project 1 assignment. The application sends ARP/NDP requests on the local link and ICMP echo requests (IPv4/IPv6) to discover reachable hosts in configured subnets and prints a summary of scanned ranges together with per‑host results.

The implementation is Linux‑only and targets the official IPK reference virtual machine. It uses raw sockets (ARP, ICMPv4, ICMPv6) and `libpcap` for passive packet capture.

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

Automated tests are implemented in the `tests` directory and are run via:

```bash
make test
```

This builds `ipk-L2L3-scan-test` and executes a set of C++ unit tests. No root privileges or real network traffic are required for these tests.

**Tested functionality (examples):**

- **CIDR parsing and host generation:**
  - IPv4 `/30`, `/32`, `/31`, `/29`, `/25` – number of usable hosts, correct host ranges.
  - IPv6 `/126`, `/128` – usable host counts consistent with the assignment examples.
  - Summary lines printed by `Scanner::printScanningSummary` contain the expected host counts.

- **Results formatting:**
  - Single IPv4/IPv6 host with various combinations of `OK`/`FAIL` at L2/L3 produces exactly the format required by the assignment (e.g. `arp OK (MAC), icmpv4 FAIL`, `ndp OK, icmpv6 OK`).
  - Repeated updates for the same IP overwrite previous results instead of duplicating lines.

- **Checksums and packet helpers:**
  - `inetChecksum` is tested on known ICMP echo request values and all‑zero buffers to verify RFC 1071 behavior.
  - ICMPv4/ICMPv6 echo request structures and ARP/NDP frame builders are validated at the byte level.

- **Input validation and error handling:**
  - Invalid CIDR strings (missing slash, invalid address, invalid prefix) throw exceptions and lead to non‑zero exit codes.
  - Output format is verified to contain the `Scanning ranges:` header, an empty line, and then host results.

**Test environment:**

- All automated tests run inside the reference `c` devShell without requiring root or access to live network interfaces.
- For manual integration tests, the scanner was validated on Linux with virtualized networks (QEMU/VirtualBox), using `tcpdump` to inspect ARP/ICMP traffic and confirm packet structure.

Known Limitations
-----------------

- **Linux‑only implementation**  
  The scanner uses Linux‑specific APIs (`AF_PACKET`, `SO_BINDTODEVICE`, Linux SLL link types). Other operating systems are not supported.

- **Per‑subnet host limit**  
  Subnets with more than **65 536 usable hosts** are rejected with an error. This is a deliberate safety limit, not a bug.

- **Environment‑dependent ICMPv4 replies**  
  Some network environments (for example, certain virtualized gateways) selectively ignore ICMP echo requests sent from raw sockets even though they reply to the standard `ping(8)` utility. In such cases the scanner may legitimately report `icmpv4 FAIL` even though `ping` appears to work. The implementation has been validated at the packet level using `tcpdump`; this is considered an environmental limitation.

Apart from the limitations explicitly listed above, **no other known limitations** are present at the time of submission.

References
----------

- IPK Project Guidelines and assignment text (NES@FIT, VUT Brno).
- `man 7 raw`, `man 7 packet`, `man 7 ip`, `man 7 icmp`, `man 7 icmp6`.
- `libpcap` documentation and examples.
- RFC 1071 – Computing the Internet Checksum.
- RFC 3021 – Using 31‑Bit Prefixes on IPv4 Point‑to‑Point Links.
