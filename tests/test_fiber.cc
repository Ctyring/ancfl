#include "ancfl/ancfl.h"

ancfl::Logger::ptr g_logger = ANCFL_LOG_ROOT();

void run_in_fiber() {
    ANCFL_LOG_INFO(g_logger) << "run_in_fiber begin";
    ancfl::Fiber::YieldToHold();
    ANCFL_LOG_INFO(g_logger) << "run_in_fiber end";
    ancfl::Fiber::YieldToHold();
}

void test_fiber() {
    ANCFL_LOG_INFO(g_logger) << "main begin -1";
    {
        ancfl::Fiber::GetThis();
        ANCFL_LOG_INFO(g_logger) << "main begin";
        ancfl::Fiber::ptr fiber(new ancfl::Fiber(run_in_fiber));
        fiber->call();
        // ANCFL_LOG_INFO(g_logger) << "main after swapIn";
        // fiber->swapIn();
        // ANCFL_LOG_INFO(g_logger) << "main after end";
        // fiber->swapIn();
    }
    ANCFL_LOG_INFO(g_logger) << "main after end2";
}

int main(int argc, char** argv) {
    ancfl::Thread::SetName("main");

    std::vector<ancfl::Thread::ptr> thrs;
    for (int i = 0; i < 3; ++i) {
        thrs.push_back(ancfl::Thread::ptr(
            new ancfl::Thread(&test_fiber, "name_" + std::to_string(i))));
    }
    for (auto i : thrs) {
        i->join();
    }
    return 0;
}



