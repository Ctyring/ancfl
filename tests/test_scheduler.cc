#include "ancfl/ancfl.h"
static ancfl::Logger::ptr g_logger = ANCFL_LOG_ROOT();

void test_fiber() {
    static int s_count = 5;
    ANCFL_LOG_INFO(g_logger) << "test in fiber s_count=" << s_count;
    if (--s_count >= 0) {
        // ancfl::Fiber::ptr tmp_fiber(new ancfl::Fiber(std::bind(test_fiber)));
        ancfl::Scheduler::GetThis()->schedule(&test_fiber,
                                              ancfl::GetThreadId());
    }
}

int main(int argc, char** argv) {
    ANCFL_LOG_INFO(g_logger) << "main";
    ancfl::Scheduler sc(3, false, "test");
    sc.start();
    sleep(2);
    ANCFL_LOG_INFO(g_logger) << "schedule";
    sc.schedule(&test_fiber);
    sc.stop();
    ANCFL_LOG_INFO(g_logger) << "over";
    return 0;
}



