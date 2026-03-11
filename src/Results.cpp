#include "Results.h"

#include <iostream>

// finds an existing record for the ip or creates a new one with default fail state
// note: does not lock the mutex, must be called only from methods that handle locking
HostResult &ResultsStore::getOrCreateUnsafe(const std::string &ip, bool isIPv6) {
    auto it = results_.find(ip);
    if (it == results_.end()) {
        HostResult hr;
        hr.ip = ip;
        if (isIPv6) {
            hr.l2Type = L2Type::Ndp;
            hr.l3Type = L3Type::Icmpv6;
        } else {
            hr.l2Type = L2Type::Arp;
            hr.l3Type = L3Type::Icmpv4;
        }
        // Defaults: FAIL for both L2 and L3 – no response case
        auto [insertedIt, _] = results_.emplace(ip, hr);
        return insertedIt->second;
    }
    return it->second;
}

// initializes a host in the map so that it appears in the output even without responses
void ResultsStore::initHost(const std::string &ip, bool isIPv6) {
    std::lock_guard<std::mutex> lock(mutex_);
    (void)getOrCreateUnsafe(ip, isIPv6);
}

static bool isIPv6Address(const std::string &ip) {
    return ip.find(':') != std::string::npos;
}

// records success on l2 (arp/ndp) and stores the mac address
void ResultsStore::updateL2Ok(const std::string &ip, const std::string &mac) {
    std::lock_guard<std::mutex> lock(mutex_);
    HostResult &hr = getOrCreateUnsafe(ip, isIPv6Address(ip));
    hr.l2Status = L2Status::Ok;
    hr.mac = mac;
}

void ResultsStore::updateL2Fail(const std::string &ip) {
    std::lock_guard<std::mutex> lock(mutex_);
    HostResult &hr = getOrCreateUnsafe(ip, isIPv6Address(ip));
    hr.l2Status = L2Status::Fail;
}

// records success on l3 (icmpv4/icmpv6)
void ResultsStore::updateL3Ok(const std::string &ip) {
    std::lock_guard<std::mutex> lock(mutex_);
    HostResult &hr = getOrCreateUnsafe(ip, isIPv6Address(ip));
    hr.l3Status = L3Status::Ok;
}

void ResultsStore::updateL3Fail(const std::string &ip) {
    std::lock_guard<std::mutex> lock(mutex_);
    HostResult &hr = getOrCreateUnsafe(ip, isIPv6Address(ip));
    hr.l3Status = L3Status::Fail;
}

const char *ResultsStore::l2TypeLiteral(L2Type t) {
    switch (t) {
    case L2Type::Arp:
        return "arp";
    case L2Type::Ndp:
        return "ndp";
    }
    return "arp";
}

const char *ResultsStore::l3TypeLiteral(L3Type t) {
    switch (t) {
    case L3Type::Icmpv4:
        return "icmpv4";
    case L3Type::Icmpv6:
        return "icmpv6";
    }
    return "icmpv4";
}

// prints results in the exact format required by the assignment (ip, l2, l3)
void ResultsStore::print(std::ostream &os) const {
    std::lock_guard<std::mutex> lock(mutex_);

    for (const auto &pair : results_) {
        const HostResult &hr = pair.second;

        os << hr.ip << " "
           << l2TypeLiteral(hr.l2Type) << " ";

        if (hr.l2Status == L2Status::Ok) {
            os << "OK (";
            os << hr.mac;
            os << ")";
        } else {
            os << "FAIL";
        }

        os << ", "
           << l3TypeLiteral(hr.l3Type) << " ";

        if (hr.l3Status == L3Status::Ok) {
            os << "OK";
        } else {
            os << "FAIL";
        }

        os << "\n";
    }
}

