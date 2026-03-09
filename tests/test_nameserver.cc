#include "ancfl/ns/ns_client.h"
#include "ancfl/ns/ns_protocol.h"
#include "ancfl/ancfl.h"

static ancfl::Logger::ptr g_logger = ANCFL_LOG_ROOT();

int type = 0;

void run() {
    g_logger->setLevel(ancfl::LogLevel::INFO);
    auto addr = ancfl::IPAddress::Create("127.0.0.1", 8072);
    // if(!conn->connect(addr)) {
    //     ANCFL_LOG_ERROR(g_logger) << "connect to: " << *addr << " fail";
    //     return;
    // }
    if (type == 0) {
        for (int i = 0; i < 5000; ++i) {
            ancfl::RockConnection::ptr conn(new ancfl::RockConnection);
            conn->connect(addr);
            ancfl::IOManager::GetThis()->addTimer(
                3000,
                [conn, i]() {
                    ancfl::RockRequest::ptr req(new ancfl::RockRequest);
                    req->setCmd((int)ancfl::ns::NSCommand::REGISTER);
                    auto rinfo = std::make_shared<ancfl::ns::RegisterRequest>();
                    auto info = rinfo->add_infos();
                    info->set_domain(std::to_string(rand() % 2) + "domain.com");
                    info->add_cmds(rand() % 2 + 100);
                    info->add_cmds(rand() % 2 + 200);
                    info->mutable_node()->set_ip("127.0.0.1");
                    info->mutable_node()->set_port(1000 + i);
                    info->mutable_node()->set_weight(100);
                    req->setAsPB(*rinfo);

                    auto rt = conn->request(req, 100);
                    ANCFL_LOG_INFO(g_logger)
                        << "[result=" << rt->result << " response="
                        << (rt->response ? rt->response->toString() : "null")
                        << "]";
                },
                true);
            conn->start();
        }
    } else {
        for (int i = 0; i < 1000; ++i) {
            ancfl::ns::NSClient::ptr nsclient(new ancfl::ns::NSClient);
            nsclient->init();
            nsclient->addQueryDomain(std::to_string(i % 2) + "domain.com");
            nsclient->connect(addr);
            nsclient->start();
            ANCFL_LOG_INFO(g_logger) << "NSClient start: i=" << i;

            if (i == 0) {
                // ancfl::IOManager::GetThis()->addTimer(1000, [nsclient](){
                //     auto domains = nsclient->getDomains();
                //     domains->dump(std::cout, "    ");
                // }, true);
            }
        }

        // conn->setConnectCb([](ancfl::AsyncSocketStream::ptr ss) {
        //     auto conn = std::dynamic_pointer_cast<ancfl::RockConnection>(ss);
        //     ancfl::RockRequest::ptr req(new ancfl::RockRequest);
        //     req->setCmd((int)ancfl::ns::NSCommand::QUERY);
        //     auto rinfo = std::make_shared<ancfl::ns::QueryRequest>();
        //     rinfo->add_domains("0domain.com");
        //     req->setAsPB(*rinfo);
        //     auto rt = conn->request(req, 1000);
        //     ANCFL_LOG_INFO(g_logger) << "[result="
        //         << rt->result << " response="
        //         << (rt->response ? rt->response->toString() : "null")
        //         << "]";
        //     return true;
        // });

        // conn->setNotifyHandler([](ancfl::RockNotify::ptr
        // nty,ancfl::RockStream::ptr stream){
        //         auto nm = nty->getAsPB<ancfl::ns::NotifyMessage>();
        //         if(!nm) {
        //             ANCFL_LOG_ERROR(g_logger) << "invalid notify message";
        //             return true;
        //         }
        //         ANCFL_LOG_INFO(g_logger) << ancfl::PBToJsonString(*nm);
        //         return true;
        // });
    }
}

int main(int argc, char** argv) {
    if (argc > 1) {
        type = 1;
    }
    ancfl::IOManager iom(5);
    iom.schedule(run);
    return 0;
}



