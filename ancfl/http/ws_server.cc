#include "ws_server.h"
#include "ancfl/log.h"

namespace ancfl {
namespace http {

static ancfl::Logger::ptr g_logger = ANCFL_LOG_NAME("system");

WSServer::WSServer(ancfl::IOManager* worker,
                   ancfl::IOManager* io_worker,
                   ancfl::IOManager* accept_worker)
    : TcpServer(worker, io_worker, accept_worker) {
    m_dispatch.reset(new WSServletDispatch);
    m_type = "websocket_server";
}

void WSServer::handleClient(Socket::ptr client) {
    ANCFL_LOG_DEBUG(g_logger) << "handleClient " << *client;
    WSSession::ptr session(new WSSession(client));
    do {
        HttpRequest::ptr header = session->handleShake();
        if (!header) {
            ANCFL_LOG_DEBUG(g_logger) << "handleShake error";
            break;
        }
        WSServlet::ptr servlet = m_dispatch->getWSServlet(header->getPath());
        if (!servlet) {
            ANCFL_LOG_DEBUG(g_logger) << "no match WSServlet";
            break;
        }
        int rt = servlet->onConnect(header, session);
        if (rt) {
            ANCFL_LOG_DEBUG(g_logger) << "onConnect return " << rt;
            break;
        }
        while (true) {
            auto msg = session->recvMessage();
            if (!msg) {
                break;
            }
            rt = servlet->handle(header, msg, session);
            if (rt) {
                ANCFL_LOG_DEBUG(g_logger) << "handle return " << rt;
                break;
            }
        }
        servlet->onClose(header, session);
    } while (0);
    session->close();
}

}  // namespace http
}  // namespace ancfl



