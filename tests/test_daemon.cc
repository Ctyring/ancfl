#include "ancfl/daemon.h"
#include "ancfl/iomanager.h"
#include "ancfl/log.h"

static ancfl::Logger::ptr g_logger = ANCFL_LOG_ROOT();

ancfl::Timer::ptr timer;
int server_main(int argc, char** argv) {
    ANCFL_LOG_INFO(g_logger)
        << ancfl::ProcessInfoMgr::GetInstance()->toString();
    ancfl::IOManager iom(1);
    timer = iom.addTimer(
        1000,
        []() {
            ANCFL_LOG_INFO(g_logger) << "onTimer";
            static int count = 0;
            if (++count > 10) {
                exit(1);
            }
        },
        true);
    return 0;
}

int main(int argc, char** argv) {
    return ancfl::start_daemon(argc, argv, server_main, argc != 1);
}



