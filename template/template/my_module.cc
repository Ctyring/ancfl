#include "my_module.h"
#include "ancfl/config.h"
#include "ancfl/log.h"

namespace name_space {

static ancfl::Logger::ptr g_logger = ANCFL_LOG_ROOT();

MyModule::MyModule() : ancfl::Module("project_name", "1.0", "") {}

bool MyModule::onLoad() {
    ANCFL_LOG_INFO(g_logger) << "onLoad";
    return true;
}

bool MyModule::onUnload() {
    ANCFL_LOG_INFO(g_logger) << "onUnload";
    return true;
}

bool MyModule::onServerReady() {
    ANCFL_LOG_INFO(g_logger) << "onServerReady";
    return true;
}

bool MyModule::onServerUp() {
    ANCFL_LOG_INFO(g_logger) << "onServerUp";
    return true;
}

}  // namespace name_space

extern "C" {

ancfl::Module* CreateModule() {
    ancfl::Module* module = new name_space::MyModule;
    ANCFL_LOG_INFO(name_space::g_logger) << "CreateModule " << module;
    return module;
}

void DestoryModule(ancfl::Module* module) {
    ANCFL_LOG_INFO(name_space::g_logger) << "CreateModule " << module;
    delete module;
}
}



