/**
 * @file Results.h
 * @brief Header file for the Results class
 * @author Petr Vitula (xvitulp00)
 */
 
#pragma once

#include <string>
#include <unordered_map>
#include <mutex>
#include <vector>
#include <iosfwd>

// L2Type represents the type of Layer 2 protocol used to discover the host
enum class L2Type {
    Arp,
    Ndp
};

// L3Type represents the type of Layer 3 protocol used to discover the host
enum class L3Type {
    Icmpv4,
    Icmpv6
};

// L2Status represents the status of the Layer 2 discovery
enum class L2Status {
    Unknown,
    Ok,
    Fail
};

// L3Status represents the status of the Layer 3 discovery
enum class L3Status {
    Unknown,
    Ok,
    Fail
};

// HostResult represents the result of the discovery of a host
struct HostResult {
    std::string ip;
    L2Type l2Type{L2Type::Arp};
    L2Status l2Status{L2Status::Fail};
    std::string mac; // only meaningful when l2Status == Ok
    L3Type l3Type{L3Type::Icmpv4};
    L3Status l3Status{L3Status::Fail};
};

// ResultsStore is a class that stores the results of the discovery of hosts
class ResultsStore {
public:
    ResultsStore() = default;

    // Initialize entry for host with default FAIL statuses so that
    // no-response case is printed as FAIL.
    void initHost(const std::string &ip, bool isIPv6);

    void updateL2Ok(const std::string &ip, const std::string &mac);
    void updateL2Fail(const std::string &ip);

    void updateL3Ok(const std::string &ip);
    void updateL3Fail(const std::string &ip);

    // Print all known hosts in unspecified order using the exact format
    // required by the assignment.
    void print(std::ostream &os) const;

private:
    mutable std::mutex mutex_;
    std::unordered_map<std::string, HostResult> results_;

    HostResult &getOrCreateUnsafe(const std::string &ip, bool isIPv6);
    static const char *l2TypeLiteral(L2Type t);
    static const char *l3TypeLiteral(L3Type t);
};

