#ifndef __ANCFL_ROCK_SERVER_H__
#define __ANCFL_ROCK_SERVER_H__

#include "ancfl/rock/rock_stream.h"
#include "ancfl/tcp_server.h"

namespace ancfl {

class RockServer : public TcpServer {
   public:
    typedef std::shared_ptr<RockServer> ptr;
    RockServer(const std::string& type = "rock",
               ancfl::IOManager* worker = ancfl::IOManager::GetThis(),
               ancfl::IOManager* io_worker = ancfl::IOManager::GetThis(),
               ancfl::IOManager* accept_worker = ancfl::IOManager::GetThis());

   protected:
    virtual void handleClient(Socket::ptr client) override;
};

}  // namespace ancfl

#endif



