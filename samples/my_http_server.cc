#include "ancfl/http/http_server.h"
#include "ancfl/log.h"

ancfl::Logger::ptr g_logger = ANCFL_LOG_ROOT();
ancfl::IOManager::ptr worker;
void run() {
    g_logger->setLevel(ancfl::LogLevel::INFO);
    ancfl::Address::ptr addr =
        ancfl::Address::LookupAnyIPAddress("0.0.0.0:8020");
    if (!addr) {
        ANCFL_LOG_ERROR(g_logger) << "get address error";
        return;
    }

    ancfl::http::HttpServer::ptr http_server(
        new ancfl::http::HttpServer(true, worker.get()));
    while (!http_server->bind(addr)) {
        ANCFL_LOG_ERROR(g_logger) << "bind " << *addr << " fail";
        sleep(1);
    }

    http_server->start();
}

int main(int argc, char** argv) {
    ancfl::IOManager iom(1);
    worker.reset(new ancfl::IOManager(4, false));
    iom.schedule(run);
    return 0;
}



