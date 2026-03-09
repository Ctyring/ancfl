#include <unistd.h>
#include <fstream>
#include <iostream>
#include "ancfl/env.h"

struct A {
    A() {
        std::ifstream ifs("/proc/" + std::to_string(getpid()) + "/cmdline",
                          std::ios::binary);
        std::string content;
        content.resize(4096);

        ifs.read(&content[0], content.size());
        content.resize(ifs.gcount());

        for (size_t i = 0; i < content.size(); ++i) {
            std::cout << i << " - " << content[i] << " - " << (int)content[i]
                      << std::endl;
        }
    }
};

A a;

int main(int argc, char** argv) {
    std::cout << "argc=" << argc << std::endl;
    ancfl::EnvMgr::GetInstance()->addHelp("s", "start with the terminal");
    ancfl::EnvMgr::GetInstance()->addHelp("d", "run as daemon");
    ancfl::EnvMgr::GetInstance()->addHelp("p", "print help");
    if (!ancfl::EnvMgr::GetInstance()->init(argc, argv)) {
        ancfl::EnvMgr::GetInstance()->printHelp();
        return 0;
    }

    std::cout << "exe=" << ancfl::EnvMgr::GetInstance()->getExe() << std::endl;
    std::cout << "cwd=" << ancfl::EnvMgr::GetInstance()->getCwd() << std::endl;

    std::cout << "path=" << ancfl::EnvMgr::GetInstance()->getEnv("PATH", "xxx")
              << std::endl;
    std::cout << "test=" << ancfl::EnvMgr::GetInstance()->getEnv("TEST", "")
              << std::endl;
    std::cout << "set env "
              << ancfl::EnvMgr::GetInstance()->setEnv("TEST", "yy") 
              << std::endl;
    std::cout << "test=" << ancfl::EnvMgr::GetInstance()->getEnv("TEST", "")
              << std::endl;
    if (ancfl::EnvMgr::GetInstance()->has("p")) {
        ancfl::EnvMgr::GetInstance()->printHelp();
    }
    return 0;
}



