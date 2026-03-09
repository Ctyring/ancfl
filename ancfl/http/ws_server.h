#pragma once
#include "ancfl/tcp_server.h"
#include "ws_servlet.h"
#include "ws_session.h"

namespace ancfl {
namespace http {

class WSServer : public TcpServer {
   public:
    typedef std::shared_ptr<WSServer> ptr;

    WSServer(ancfl::IOManager* worker = ancfl::IOManager::GetThis(),
             ancfl::IOManager* io_worker = ancfl::IOManager::GetThis(),
             ancfl::IOManager* accept_worker = ancfl::IOManager::GetThis());

    WSServletDispatch::ptr getWSServletDispatch() const { return m_dispatch; }
    void setWSServletDispatch(WSServletDispatch::ptr v) { m_dispatch = v; }

   protected:
    virtual void handleClient(Socket::ptr client) override;

   protected:
    WSServletDispatch::ptr m_dispatch;
};

}  // namespace http
}  // namespace ancfl



