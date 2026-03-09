#include "rock_server.h"
#include "ancfl/log.h"
#include "ancfl/module.h"

namespace ancfl {

static ancfl::Logger::ptr g_logger = ANCFL_LOG_NAME("system");

RockServer::RockServer(const std::string& type,
                       ancfl::IOManager* worker,
                       ancfl::IOManager* io_worker,
                       ancfl::IOManager* accept_worker)
    : TcpServer(worker, io_worker, accept_worker) {
    m_type = type;
}

void RockServer::handleClient(Socket::ptr client) {
    ANCFL_LOG_DEBUG(g_logger) << "handleClient " << *client;
    ancfl::RockSession::ptr session(new ancfl::RockSession(client));
    session->setWorker(m_worker);
    ModuleMgr::GetInstance()->foreach (
        Module::ROCK, [session](Module::ptr m) { m->onConnect(session); });
    session->setDisconnectCb([](AsyncSocketStream::ptr stream) {
        ModuleMgr::GetInstance()->foreach (
            Module::ROCK, [stream](Module::ptr m) { m->onDisconnect(stream); });
    });
    session->setRequestHandler([](ancfl::RockRequest::ptr req,
                                  ancfl::RockResponse::ptr rsp,
                                  ancfl::RockStream::ptr conn) -> bool {
        // ANCFL_LOG_INFO(g_logger)
        //     << "handleReq " << req->toString() << " body=" << req->getBody();
        bool rt = false;
        ModuleMgr::GetInstance()->foreach (
            Module::ROCK, [&rt, req, rsp, conn](Module::ptr m) {
                if (rt) {
                    return;
                }
                rt = m->handleRequest(req, rsp, conn);
            });
        return rt;
    });
    session->setNotifyHandler(
        [](ancfl::RockNotify::ptr nty, ancfl::RockStream::ptr conn) -> bool {
            ANCFL_LOG_INFO(g_logger) << "handleNty " << nty->toString()
                                     << " body=" << nty->getBody();
            bool rt = false;
            ModuleMgr::GetInstance()->foreach (
                Module::ROCK, [&rt, nty, conn](Module::ptr m) {
                    if (rt) {
                        return;
                    }
                    rt = m->handleNotify(nty, conn);
                });
            return rt;
        });
    session->start();
}

}  // namespace ancfl



