#pragma once

#include <string>
#include <unordered_map>
#include <mutex>
#include <vector>
#include <iosfwd>

enum class L2Type {
    Arp,
    Ndp
};

enum class L3Type {
    Icmpv4,
    Icmpv6
};

enum class L2Status {
    Unknown,
    Ok,
    Fail
};

enum class L3Status {
    Unknown,
    Ok,
    Fail
};

struct HostResult {
    std::string ip;
    L2Type l2Type{L2Type::Arp};
    L2Status l2Status{L2Status::Fail};
    std::string mac; // only meaningful when l2Status == Ok
    L3Type l3Type{L3Type::Icmpv4};
    L3Status l3Status{L3Status::Fail};
};

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

