#include <unistd.h>
#include <iostream>
#include "ancfl/ancfl.h"

ancfl::Logger::ptr g_logger = ANCFL_LOG_ROOT();

int count = 0;
ancfl::Mutex s_mutex;

void fun1() {
    ANCFL_LOG_INFO(g_logger)
        << "name: " << ancfl::Thread::GetName()
        << " this.name: " << ancfl::Thread::GetThis()->getName()
        << " id: " << ancfl::GetThreadId()
        << " this.id: " << ancfl::Thread::GetThis()->getId();

    for (int i = 0; i < 100000; ++i) {
        ancfl::Mutex::Lock lock(
            s_mutex);  // 定义lock对象，类型为ancfl::Mutex::Lock，传入互斥量，在构造函数中完成加锁操作，如果该锁已经被持有，那构造lock时就会阻塞，直到锁被释放
        ++count;
    }
}

void fun2() {
    // while (true) {
    ANCFL_LOG_INFO(g_logger) << "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx";
    // }
}

void fun3() {
    // while (true) {
    ANCFL_LOG_INFO(g_logger) << "========================================";
    // }
}

int main(int argc, char** argv) {
    // ancfl::Thread::ptr thr(
    //     new ancfl::Thread(&fun2, "name_" + std::to_string(1)));
    // thr->join();
    std::cout << "test_thread" << std::endl;
    ANCFL_LOG_INFO(g_logger) << "thread test begin";
    std::cout << "ok" << std::endl;
    YAML::Node root = YAML::LoadFile("/root/cty/ancfl/bin/conf/log.yml");
    ancfl::Config::LoadFromYaml(root);

    std::vector<ancfl::Thread::ptr> thrs;
    for (int i = 0; i < 2; ++i) {
        ancfl::Thread::ptr thr(
            new ancfl::Thread(&fun2, "name_" + std::to_string(i * 2)));
        ancfl::Thread::ptr thr2(
            new ancfl::Thread(&fun3, "name_" + std::to_string(i * 2 + 1)));
        thrs.push_back(thr);
        thrs.push_back(thr2);
    }
    for (size_t i = 0; i < thrs.size(); ++i) {
        thrs[i]->join();
    }
    ANCFL_LOG_INFO(g_logger) << "thread test end";
    ANCFL_LOG_INFO(g_logger) << "count=" << count;
    return 0;
}



