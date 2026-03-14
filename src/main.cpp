/**
 * @file main.cpp
 * @brief Main file for the ipk-L2L3-scan program
 * @author Petr Vitula (xvitulp00)
 *
 * Platform: Linux only. Requires root for raw sockets and packet capture.
 */

#include "Scanner.h"
#include "SignalHandler.h"

#include <iostream>
#include <string>
#include <vector>
#include <cstdlib>
#include <stdexcept>
#include <sysexits.h>

// simple structure for parsed cli arguments
struct Config {
    std::string interface;
    std::vector<std::string> subnets;
    int timeoutMs{1000};
    bool listInterfacesMode{false};
    bool helpRequested{false};
};

// prints usage in the exact format required by the assignment
static void printUsage(std::ostream &os) {
    os << "Usage:\n"
       << "  ./ipk-L2L3-scan -i INTERFACE [-s SUBNET]... [-w TIMEOUT] [-h | --help]\n"
       << "  ./ipk-L2L3-scan -i\n"
       << "  ./ipk-L2L3-scan -h\n"
       << "  ./ipk-L2L3-scan --help\n";
}

// parses command‑line arguments into config
// throws std::invalid_argument on invalid or missing values
static Config parseArguments(int argc, char **argv) {
    Config cfg;

    for (int i = 1; i < argc; ++i) {
        std::string arg = argv[i];

        if (arg == "-h" || arg == "--help") {
            cfg.helpRequested = true;
            return cfg;
        } else if (arg == "-i") {
            cfg.interface.clear();

            if (argc == 2) {
                // Exactly: ./ipk-L2L3-scan -i  -> list interfaces mode
                cfg.listInterfacesMode = true;
                return cfg;
            }

            if (i + 1 >= argc) {
                throw std::invalid_argument("Option -i requires an argument");
            }

            cfg.interface = argv[++i];
        } else if (arg == "-s") {
            if (i + 1 >= argc) {
                throw std::invalid_argument("Option -s requires an argument");
            }
            cfg.subnets.emplace_back(argv[++i]);
        } else if (arg == "-w") {
            if (i + 1 >= argc) {
                throw std::invalid_argument("Option -w requires an argument");
            }
            try {
                cfg.timeoutMs = std::stoi(argv[++i]);
            } catch (const std::exception &) {
                throw std::invalid_argument("Timeout must be a positive integer");
            }
            if (cfg.timeoutMs <= 0) {
                throw std::invalid_argument("Timeout must be a positive integer");
            }
        } else {
            throw std::invalid_argument("Unknown argument: " + arg);
        }
    }

    return cfg;
}

int main(int argc, char **argv) {
    try {
        Config cfg = parseArguments(argc, argv);

        // help mode: print usage to stdout and exit with code 0
        if (cfg.helpRequested) {
            printUsage(std::cout);
            return 0;
        }

        // interface listing mode: ./ipk-l2l3-scan -i
        if (cfg.listInterfacesMode) {
            Scanner::listInterfaces(std::cout);
            return 0;
        }

        // in normal scan mode we require interface and at least one subnet
        if (cfg.interface.empty()) {
            std::cerr << "Error: interface must be specified with -i.\n";
            printUsage(std::cerr);
            return EX_USAGE;
        }

        if (cfg.subnets.empty()) {
            std::cerr << "Error: at least one -s SUBNET must be specified.\n";
            printUsage(std::cerr);
            return EX_USAGE;
        }

        // set up signal handlers for sigint/sigterm
        setupSignalHandlers();

        Scanner scanner(cfg.interface, cfg.timeoutMs);

        for (const auto &cidr : cfg.subnets) {
            scanner.addSubnet(cidr);
        }

        // prepare libpcap handle for asynchronous receive thread
        scanner.initializePcap();

        // run the scan (sender + pcap + timeout)
        scanner.run();

        // print both sections according to the specification in readme:
        // 1) scanning ranges summary
        // 2) per‑host scan results
        scanner.printScanningSummary(std::cout);
        std::cout << "\n";
        scanner.results().print(std::cout);

        return 0;
    } catch (const std::invalid_argument &ex) {
        std::cerr << "Error: " << ex.what() << "\n";
        printUsage(std::cerr);
        return EX_USAGE;   // bad options or invalid CIDR/data
    } catch (const std::exception &ex) {
        std::cerr << "Error: " << ex.what() << "\n";
        printUsage(std::cerr);
        return EX_OSERR;   // runtime failure (pcap, socket, etc.)
    }
}

