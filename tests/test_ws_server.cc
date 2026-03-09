#include "ancfl/http/ws_server.h"
#include "ancfl/log.h"

static ancfl::Logger::ptr g_logger = ANCFL_LOG_ROOT();

void run() {
    ancfl::http::WSServer::ptr server(new ancfl::http::WSServer);
    ancfl::Address::ptr addr =
        ancfl::Address::LookupAnyIPAddress("0.0.0.0:8020");
    if (!addr) {
        ANCFL_LOG_ERROR(g_logger) << "get address error";
        return;
    }
    auto fun = [](ancfl::http::HttpRequest::ptr header,
                  ancfl::http::WSFrameMessage::ptr msg,
                  ancfl::http::WSSession::ptr session) {
        session->sendMessage(msg);
        return 0;
    };

    server->getWSServletDispatch()->addServlet("/ancfl", fun);
    while (!server->bind(addr)) {
        ANCFL_LOG_ERROR(g_logger) << "bind " << *addr << " fail";
        sleep(1);
    }
    server->start();
}

int main(int argc, char** argv) {
    ancfl::IOManager iom(2);
    iom.schedule(run);
    return 0;
}



