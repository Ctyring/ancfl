#include "ancfl/address.h"
#include "ancfl/log.h"

ancfl::Logger::ptr g_logger = ANCFL_LOG_ROOT();

void test() {
    std::vector<ancfl::Address::ptr> addrs;

    ANCFL_LOG_INFO(g_logger) << "begin";
    bool v = ancfl::Address::Lookup(addrs, "localhost:3080");
    ANCFL_LOG_INFO(g_logger) << "end";
    if (!v) {
        ANCFL_LOG_ERROR(g_logger) << "lookup fail";
        return;
    }

    for (size_t i = 0; i < addrs.size(); ++i) {
        ANCFL_LOG_INFO(g_logger) << i << " - " << addrs[i]->toString();
    }

    auto addr = ancfl::Address::LookupAny("localhost:4080");
    if (addr) {
        ANCFL_LOG_INFO(g_logger) << *addr;
    } else {
        ANCFL_LOG_ERROR(g_logger) << "error";
    }
}

void test_iface() {
    std::multimap<std::string, std::pair<ancfl::Address::ptr, uint32_t>>
        results;

    bool v = ancfl::Address::GetInterfaceAddresses(results);
    if (!v) {
        ANCFL_LOG_ERROR(g_logger) << "GetInterfaceAddresses fail";
        return;
    }

    for (auto& i : results) {
        ANCFL_LOG_INFO(g_logger)
            << i.first << " - " << i.second.first->toString() << " - "
            << i.second.second;
    }
}

void test_ipv4() {
    // auto addr = ancfl::IPAddress::Create("www.ancfl.top");
    auto addr = ancfl::IPAddress::Create("127.0.0.8");
    if (addr) {
        ANCFL_LOG_INFO(g_logger) << addr->toString();
    }
}

int main(int argc, char** argv) {
    // test_ipv4();
    // test_iface();
    test();
    return 0;
}



