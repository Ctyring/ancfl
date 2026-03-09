#include "http_server.h"
#include "ancfl/http/servlets/config_servlet.h"
#include "ancfl/http/servlets/status_servlet.h"
#include "ancfl/log.h"

namespace ancfl {
namespace http {

static ancfl::Logger::ptr g_logger = ANCFL_LOG_NAME("system");

HttpServer::HttpServer(bool keepalive,
                       ancfl::IOManager* worker,
                       ancfl::IOManager* io_worker,
                       ancfl::IOManager* accept_worker)
    : TcpServer(worker, io_worker, accept_worker), m_isKeepalive(keepalive) {
    m_dispatch.reset(new ServletDispatch);
    m_type = "http";

    m_dispatch->addServlet("/_/status", Servlet::ptr(new StatusServlet));
    m_dispatch->addServlet("/_/config", Servlet::ptr(new ConfigServlet));
}

void HttpServer::setName(const std::string& v) {
    TcpServer::setName(v);
    m_dispatch->setDefault(std::make_shared<NotFoundServlet>(v));
}

void HttpServer::handleClient(Socket::ptr client) {
    ANCFL_LOG_INFO(g_logger) << "handleClient " << *client;
    HttpSession::ptr session(new HttpSession(client));
    do {
        auto req = session->recvRequest();
        if (!req) {
            ANCFL_LOG_DEBUG(g_logger)
                << "recv http request fail, errno=" << errno
                << " errstr=" << strerror(errno) << " cliet:" << *client
                << " keep_alive=" << m_isKeepalive;
            break;
        }

        HttpResponse::ptr rsp(new HttpResponse(
            req->getVersion(), req->isClose() || !m_isKeepalive));
        rsp->setHeader("Server", getName());
        m_dispatch->handle(req, rsp, session);
        session->sendResponse(rsp);

        if (!m_isKeepalive || req->isClose()) {
            break;
        }
    } while (true);
    session->close();
}

}  // namespace http
}  // namespace ancfl



