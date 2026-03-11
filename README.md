# Project 1 - DELTA: L2/L3 Scanner

- Contact person: pluskal@vut.cz
- Automated testing: ivondracek@fit.vut.cz

## Assignment
1. Create a simple network ICMP(v6), ARP/NDP scanner. The program discovers what devices are available from a selected range of IP addresses. It prints to standard output the availability status of the given IP addresses at the L2 and L3 layers.
2. Create relevant tests for the project.

## Specification
The application scans for presence of L2 and L3 devices on given network segment(s). 

Packets/Frames should be sent using raw sockets. If needed, you can eavesdrop on the responses using the libpcap library.

The program can be terminated at any given moment with `SIGTERM` or `SIGINT` signals (<kbd>Ctrl</kbd> + <kbd>C</kbd> sequence).

Scanning should be done and return results as fast as possible. During development and testing, try scanning only the computers you own or manage.

### Synopsis
```
./ipk-L2L3-scan -i INTERFACE [-s SUBNET]... [-w TIMEOUT] [-h | --help]
```
```
./ipk-L2L3-scan -i
```
```
./ipk-L2L3-scan -h
```
```
./ipk-L2L3-scan --help
```

where:

* `-h`/`--help` writes usage instructions to `stdout` and terminates with `0` exit code.
* `-i eth0` (just one interface to scan through).
  * If `-i` is specified without a value (and any other parameters are unspecified), a list of active interfaces is printed to `stdout` and the program terminates with `0` exit code (additional information beyond the interface list is welcome but not required).
* `-w 3000` is the timeout in milliseconds to wait for a response during a single port scan. This parameter is optional, in its absence the value 1000 (i.e., one second) is used.
* `-s 192.168.1.0/24` or `-s fd00:cafe:0000:face::0/120` specifies which segments to scan using IPv4 or IPv6. There can be multiple segments to be scanned (i.e., **the `-s` argument can be repeated** when the program is called).
  * The application must be able to infer the correct network address and the resulting number of hosts to be scanned from the user input of the `-s` argument.
  * The application does not have to deal with the "bloat" of the `-s` argument input with respect to the number of hosts being scanned (e.g., too short netmask or prefix length, for instance `-s 10.0.0.0/8`) or the location of the segment being scanned (i.e., attempting to ARP scan a network to which the computer is not directly connected).
* All arguments can be in any order.

### Execution Examples
```
./ipk-L2L3-scan -i eth0 -w 1000 -s 192.168.0.0/25 -s 192.168.128.0/29
./ipk-L2L3-scan -i eth0 -w 1000 -s fd00:cafe:0000:face::0/120
```

### Functionality Illustration
```sh
./ipk-L2L3-scan -i eth0 -w 1000 -s 192.168.0.5/25 -s 192.168.0.128/29 -s fd00:cafe:0000:face::1/126
```
```
Scanning ranges:
192.168.0.0/25 126
192.168.0.128/29 6
fd00:cafe:0000:face::0/126 3

192.168.0.1 arp OK (00-50-56-f1-c7-1b), icmpv4 OK
192.168.0.2 arp OK (00-22-14-ec-46-bb), icmpv4 FAIL
192.168.0.3 arp FAIL, icmpv4 FAIL
...
fd00:cafe:0000:face::1 ndp OK (00-50-56-f1-c7-1b), icmpv6 OK
fd00:cafe:0000:face::2 ndp FAIL, icmpv6 FAIL
fd00:cafe:0000:face::3 ndp OK (a8-5e-45-af-7c-60), icmpv6 FAIL
```

### Output Format

> ⚠️ <span style="color:orange"> The application is going to be subject to automated testing. It is of utmost importance for the application to write the result to `stdout` exactly as specified.</span>

Program output (`stdout`) consists of 2 ordered sections: 1) scanning ranges summary, then 2) scan results. These sections are separated by an empty line.

The scan ranges summary section starts with a literal `Scanning ranges:` single line. The following lines in this section (individual lines in any order) each contain two values separated by space (` `): IP address of scanned network (IPv4 or IPv6 with prefix length), and number of usable hosts in the network.

The scan results section consists of one or more lines. Individual lines can be in any order. Each line starts with the scanned host IP address followed by ` ` and ARP/ND scan, then followed by `, ` and ICMP/ICMPv6 scan. Scan results must be marked by `arp`/`ndp`/`icmpv4`/`icmpv6` literals. ARP/ND scan result is either `OK` followed by space ` ` with MAC address in parentheses or `FAIL`. ICMP/ICMPv6 scan result is either `OK` or `FAIL`.

```sh
./ipk-L2L3-scan -i eth0 -s 192.168.0.1/30
```
```
Scanning ranges:
192.168.0.0/30 2

192.168.0.1 arp OK (00-50-56-f1-c7-1b), icmpv4 OK
192.168.0.2 arp OK (00-22-14-ec-46-bb), icmpv4 FAIL
```

```sh
./ipk-L2L3-scan -i eth0 -s 192.168.0.1/30 -s 192.168.0.130/29
```
```
Scanning ranges:
192.168.0.0/30 2
192.168.0.128/29 6

192.168.0.1 arp OK (00-50-56-f1-c7-1b), icmpv4 OK
192.168.0.2 arp OK (00-22-14-ec-46-bb), icmpv4 FAIL
192.168.0.129 arp FAIL, icmpv4 FAIL
192.168.0.130 arp FAIL, icmpv4 FAIL
192.168.0.131 arp FAIL, icmpv4 FAIL
192.168.0.132 arp FAIL, icmpv4 FAIL
192.168.0.133 arp FAIL, icmpv4 FAIL
192.168.0.134 arp FAIL, icmpv4 FAIL
```

## Bibliography

* RFC 792: Internet Control Message Protocol, 1981. Online. Request for Comments. Internet Engineering Task Force. [Accessed 17 February 2025]. 
* GUPTA, Mukesh and CONTA, Alex, 2006. RFC 4443: Internet Control Message Protocol (ICMPv6) for the Internet Protocol Version 6 (IPv6) Specification. Online. Request for Comments. Internet Engineering Task Force. [Accessed 17 February 2025]. 
* SIMPSON, William A., NARTEN, Thomas, NORDMARK, Erik and SOLIMAN, Hesham, 2007. RFC 4861: Neighbor Discovery for IP version 6 (IPv6). Online. Request for Comments. Internet Engineering Task Force. [Accessed 17 February 2025]. 
* RFC 826: An Ethernet Address Resolution Protocol: Or Converting Network Protocol Addresses to 48.bit Ethernet Address for Transmission on Ethernet Hardware, 1982. Online. Request for Comments. Internet Engineering Task Force. [Accessed 17 February 2025]. 
* Host Discovery Techniques | Nmap Network Scanning. Online. Available from: https://nmap.org/book/host-discovery-techniques.html [Accessed 17 February 2025]. 
