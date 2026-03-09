#include <iostream>
#include "ancfl/db/redis.h"
#include "ancfl/log.h"
#include "ancfl/module.h"
#include "ancfl/singleton.h"

static ancfl::Logger::ptr g_logger = ANCFL_LOG_ROOT();

class A {
   public:
    A() { std::cout << "A::A " << this << std::endl; }

    ~A() { std::cout << "A::~A " << this << std::endl; }
};

class MyModule : public ancfl::RockModule {
   public:
    MyModule() : RockModule("hello", "1.0", "") {
        // ancfl::Singleton<A>::GetInstance();
    }

    bool onLoad() override {
        ancfl::Singleton<A>::GetInstance();
        std::cout << "-----------onLoad------------" << std::endl;
        return true;
    }

    bool onUnload() override {
        ancfl::Singleton<A>::GetInstance();
        std::cout << "-----------onUnload------------" << std::endl;
        return true;
    }

    bool onServerReady() {
        registerService("rock", "ancfl.top", "blog");
        auto rpy = ancfl::RedisUtil::Cmd("local", "get abc");
        if (!rpy) {
            ANCFL_LOG_ERROR(g_logger) << "redis cmd get abc error";
        } else {
            ANCFL_LOG_ERROR(g_logger)
                << "redis get abc: " << (rpy->str ? rpy->str : "(null)");
        }
        return true;
    }

    bool handleRockRequest(ancfl::RockRequest::ptr request,
                           ancfl::RockResponse::ptr response,
                           ancfl::RockStream::ptr stream) {
        ANCFL_LOG_INFO(g_logger) << "handleRockRequest " << request->toString();
        response->setResult(0);
        response->setResultStr("ok");
        response->setBody("echo: " + request->getBody());

        usleep(100 * 1000);
        auto addr = stream->getLocalAddressString();
        if (addr.find("8061") != std::string::npos) {
            if (rand() % 100 < 50) {
                usleep(10 * 1000);
            } else if (rand() % 100 < 10) {
                response->setResult(-1000);
            }
        } else {
            // if(rand() % 100 < 25) {
            //     usleep(10 * 1000);
            // } else if(rand() % 100 < 10) {
            //     response->setResult(-1000);
            // }
        }
        return true;
    }

    bool handleRockNotify(ancfl::RockNotify::ptr notify,
                          ancfl::RockStream::ptr stream) {
        ANCFL_LOG_INFO(g_logger) << "handleRockNotify " << notify->toString();
        return true;
    }
};

extern "C" {

ancfl::Module* CreateModule() {
    ancfl::Singleton<A>::GetInstance();
    std::cout << "=============CreateModule=================" << std::endl;
    return new MyModule;
}

void DestoryModule(ancfl::Module* ptr) {
    std::cout << "=============DestoryModule=================" << std::endl;
    delete ptr;
}
}



