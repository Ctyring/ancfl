#include "ancfl/iomanager.h"
#include "ancfl/log.h"
#include "ancfl/rock/rock_stream.h"
#include "ancfl/streams/service_discovery.h"
#include "ancfl/worker.h"

ancfl::ZKServiceDiscovery::ptr zksd(
    new ancfl::ZKServiceDiscovery("127.0.0.1:21812"));
ancfl::RockSDLoadBalance::ptr rsdlb(new ancfl::RockSDLoadBalance(zksd));

static ancfl::Logger::ptr g_logger = ANCFL_LOG_ROOT();

std::atomic<uint32_t> s_id;
void on_timer() {
    g_logger->setLevel(ancfl::LogLevel::INFO);
    // ANCFL_LOG_INFO(g_logger) << "on_timer";
    ancfl::RockRequest::ptr req(new ancfl::RockRequest);
    req->setSn(++s_id);
    req->setCmd(100);
    req->setBody("hello");

    auto rt = rsdlb->request("ancfl.top", "blog", req, 1000);
    if (!rt->response) {
        if (req->getSn() % 50 == 0) {
            ANCFL_LOG_ERROR(g_logger) << "invalid response: " << rt->toString();
        }
    } else {
        if (req->getSn() % 1000 == 0) {
            ANCFL_LOG_INFO(g_logger) << rt->toString();
        }
    }
}

void run() {
    zksd->setSelfInfo("127.0.0.1:2222");
    zksd->setSelfData("aaaa");

    std::unordered_map<std::string,
                       std::unordered_map<std::string, std::string> >
        confs;
    confs["ancfl.top"]["blog"] = "fair";
    rsdlb->start(confs);
    // ANCFL_LOG_INFO(g_logger) << "on_timer---";

    ancfl::IOManager::GetThis()->addTimer(1, on_timer, true);
}

int main(int argc, char** argv) {
    ancfl::WorkerMgr::GetInstance()->init(
        {{"service_io", {{"thread_num", "1"}}}});
    ancfl::IOManager iom(1);
    iom.addTimer(
        1000, []() { std::cout << rsdlb->statusString() << std::endl; }, true);
    iom.schedule(run);
    return 0;
}



