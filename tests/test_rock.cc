#include "ancfl/rock/rock_stream.h"
#include "ancfl/ancfl.h"

static ancfl::Logger::ptr g_logger = ANCFL_LOG_ROOT();

ancfl::RockConnection::ptr conn(new ancfl::RockConnection);
void run() {
    conn->setAutoConnect(true);
    ancfl::Address::ptr addr = ancfl::Address::LookupAny("127.0.0.1:8061");
    if (!conn->connect(addr)) {
        ANCFL_LOG_INFO(g_logger) << "connect " << *addr << " false";
    }
    conn->start();

    ancfl::IOManager::GetThis()->addTimer(
        1000,
        []() {
            ancfl::RockRequest::ptr req(new ancfl::RockRequest);
            static uint32_t s_sn = 0;
            req->setSn(++s_sn);
            req->setCmd(100);
            req->setBody("hello world sn=" + std::to_string(s_sn));

            auto rsp = conn->request(req, 300);
            if (rsp->response) {
                ANCFL_LOG_INFO(g_logger) << rsp->response->toString();
            } else {
                ANCFL_LOG_INFO(g_logger) << "error result=" << rsp->result;
            }
        },
        true);
}

int main(int argc, char** argv) {
    ancfl::IOManager iom(1);
    iom.schedule(run);
    return 0;
}



