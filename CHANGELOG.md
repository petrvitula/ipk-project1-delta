# CHANGELOG

All notable changes to this project are documented in this file.

## v1.0.0 – Initial implementation

- Implemented IPv4/IPv6 L2/L3 scanner based on the IPK Project 1 assignment.
- Added command-line interface:
  - `-i INTERFACE` for selecting network interface.
  - `-s SUBNET` (repeatable) for specifying IPv4/IPv6 CIDR ranges.
  - `-w TIMEOUT` for controlling how long to wait for replies after sending probes.
  - `-h` / `--help` and `-i` (without arguments) for help and interface listing.

- Implemented CIDR parsing and host generation:
  - IPv4: `/32` → single host, `/31` → two usable hosts (RFC 3021), other prefixes exclude network and broadcast.
  - IPv6: `/128` → single host, other prefixes use `2^(hostBits) - 1` usable hosts (excluding network) to match assignment examples.
  - Per-subnet safety limit of 65 536 usable hosts to avoid excessive memory usage and hangs on very large ranges.

- Implemented ARP, NDP, ICMPv4, and ICMPv6 packet construction and sending using raw sockets:
  - ARP over `AF_PACKET` with custom Ethernet frames.
  - ICMPv4 echo requests over `AF_INET` raw socket bound to the selected interface and its IPv4 address.
  - NDP neighbor solicitation and ICMPv6 echo requests over `AF_INET6` raw socket with proper scope handling.

- Implemented passive packet capture using `libpcap` in a dedicated thread:
  - Support for Ethernet, 802.1Q VLAN, Linux cooked capture v1 and v2 link-layer types.
  - Robust EtherType parsing and handling of VLAN tags.
  - ARP Reply, NDP Neighbor Advertisement, ICMPv4 Echo Reply, and ICMPv6 Echo Reply recognition.

- Implemented results storage and printing:
  - Per-host L2 and L3 status (`OK`/`FAIL`) with MAC address formatting as required by the assignment.
  - No duplicate lines for hosts that are updated multiple times.

## v1.0.1 – Testing and robustness improvements

- Added a suite of C++ unit tests in `tests/` and a `make test` target:
  - Coverage for CIDR parsing, host generation, result formatting, checksums, and combined output format.
  - Additional tests in a separate translation unit (`test_additional.cpp`) using a shared test counter.
- Fixed and documented several edge cases and robustness issues:
  - Correct handling of IPv4 `/31` ranges and host lists.
  - Correct NDP Neighbor Advertisement MAC extraction (using Target Link-Layer Address option when available).
  - Correct ICMPv4 checksum calculation and storage in network byte order.
  - Avoided double processing of ICMPv4 replies by relying solely on `libpcap` for reply handling.
  - Avoided race conditions between sender and `libpcap` threads.
- Added `NixDevShellName` Makefile target returning `c` to comply with IPK devShell selection guidelines.

## Known limitations

- **Linux‑only implementation**  
  The scanner uses Linux‑specific APIs (`AF_PACKET`, `SO_BINDTODEVICE`, Linux SLL link types). Other operating systems are not supported.

- **Per‑subnet host limit**  
  Subnets with more than **65 536 usable hosts** are rejected with an error. This is a deliberate safety limit, not a bug.

- **Environment‑dependent ICMPv4 replies**  
  Some network environments (for example, certain virtualized gateways) selectively ignore ICMP echo requests sent from raw sockets even though they reply to the standard `ping(8)` utility. In such cases the scanner may legitimately report `icmpv4 FAIL` even though `ping` appears to work. The implementation has been validated at the packet level using `tcpdump`; this is considered an environmental limitation.

