#include "ancfl/iomanager.h"
#include "ancfl/log.h"
#include "ancfl/socket.h"

static ancfl::Logger::ptr g_logger = ANCFL_LOG_ROOT();

void run() {
    ancfl::IPAddress::ptr addr =
        ancfl::Address::LookupAnyIPAddress("0.0.0.0:8050");
    ancfl::Socket::ptr sock = ancfl::Socket::CreateUDP(addr);
    if (sock->bind(addr)) {
        ANCFL_LOG_INFO(g_logger) << "udp bind : " << *addr;
    } else {
        ANCFL_LOG_ERROR(g_logger) << "udp bind : " << *addr << " fail";
        return;
    }
    while (true) {
        char buff[1024];
        ancfl::Address::ptr from(new ancfl::IPv4Address);
        int len = sock->recvFrom(buff, 1024, from);
        if (len > 0) {
            buff[len] = '\0';
            ANCFL_LOG_INFO(g_logger) << "recv: " << buff << " from: " << *from;
            len = sock->sendTo(buff, len, from);
            if (len < 0) {
                ANCFL_LOG_INFO(g_logger)
                    << "send: " << buff << " to: " << *from << " error=" << len;
            }
        }
    }
}

int main(int argc, char** argv) {
    ancfl::IOManager iom(1);
    iom.schedule(run);
    return 0;
}



