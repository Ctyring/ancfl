#include "ancfl/iomanager.h"
#include "ancfl/log.h"
#include "ancfl/tcp_server.h"

ancfl::Logger::ptr g_logger = ANCFL_LOG_ROOT();

void run() {
    auto addr = ancfl::Address::LookupAny("0.0.0.0:8033");
    // auto addr2 = ancfl::UnixAddress::ptr(new
    // ancfl::UnixAddress("/tmp/unix_addr"));
    std::vector<ancfl::Address::ptr> addrs;
    addrs.push_back(addr);
    // addrs.push_back(addr2);

    ancfl::TcpServer::ptr tcp_server(new ancfl::TcpServer);
    std::vector<ancfl::Address::ptr> fails;
    while (!tcp_server->bind(addrs, fails)) {
        sleep(2);
    }
    tcp_server->start();
    sleep(10);
    tcp_server->stop();
}
int main(int argc, char** argv) {
    ancfl::IOManager iom(2);
    iom.schedule(run);
    return 0;
}



