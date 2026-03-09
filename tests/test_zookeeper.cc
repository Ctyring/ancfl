#include "ancfl/iomanager.h"
#include "ancfl/log.h"
#include "ancfl/zk_client.h"

static ancfl::Logger::ptr g_logger = ANCFL_LOG_ROOT();

int g_argc;

void on_watcher(int type,
                int stat,
                const std::string& path,
                ancfl::ZKClient::ptr client) {
    ANCFL_LOG_INFO(g_logger)
        << " type=" << type << " stat=" << stat << " path=" << path
        << " client=" << client << " fiber=" << ancfl::Fiber::GetThis()
        << " iomanager=" << ancfl::IOManager::GetThis();

    if (stat == ZOO_CONNECTED_STATE) {
        if (g_argc == 1) {
            std::vector<std::string> vals;
            Stat stat;
            int rt = client->getChildren("/", vals, true, &stat);
            if (rt == ZOK) {
                ANCFL_LOG_INFO(g_logger)
                    << "[" << ancfl::Join(vals.begin(), vals.end(), ",") << "]";
            } else {
                ANCFL_LOG_INFO(g_logger) << "getChildren error " << rt;
            }
        } else {
            std::string new_val;
            new_val.resize(255);
            int rt = client->create("/zkxxx", "", new_val, &ZOO_OPEN_ACL_UNSAFE,
                                    ZOO_EPHEMERAL);
            if (rt == ZOK) {
                ANCFL_LOG_INFO(g_logger) << "[" << new_val.c_str() << "]";
            } else {
                ANCFL_LOG_INFO(g_logger) << "getChildren error " << rt;
            }

            // extern ZOOAPI const int ZOO_SEQUENCE;
            // extern ZOOAPI const int ZOO_CONTAINER;
            rt = client->create("/zkxxx", "", new_val, &ZOO_OPEN_ACL_UNSAFE,
                                ZOO_SEQUENCE | ZOO_EPHEMERAL);
            if (rt == ZOK) {
                ANCFL_LOG_INFO(g_logger)
                    << "create [" << new_val.c_str() << "]";
            } else {
                ANCFL_LOG_INFO(g_logger) << "create error " << rt;
            }

            rt = client->get("/hello", new_val, true);
            if (rt == ZOK) {
                ANCFL_LOG_INFO(g_logger) << "get [" << new_val.c_str() << "]";
            } else {
                ANCFL_LOG_INFO(g_logger) << "get error " << rt;
            }

            rt = client->create("/hello", "", new_val, &ZOO_OPEN_ACL_UNSAFE,
                                ZOO_EPHEMERAL);
            if (rt == ZOK) {
                ANCFL_LOG_INFO(g_logger) << "get [" << new_val.c_str() << "]";
            } else {
                ANCFL_LOG_INFO(g_logger) << "get error " << rt;
            }

            rt = client->set("/hello", "xxx");
            if (rt == ZOK) {
                ANCFL_LOG_INFO(g_logger) << "set [" << new_val.c_str() << "]";
            } else {
                ANCFL_LOG_INFO(g_logger) << "set error " << rt;
            }

            rt = client->del("/hello");
            if (rt == ZOK) {
                ANCFL_LOG_INFO(g_logger) << "del [" << new_val.c_str() << "]";
            } else {
                ANCFL_LOG_INFO(g_logger) << "del error " << rt;
            }
        }
    } else if (stat == ZOO_EXPIRED_SESSION_STATE) {
        client->reconnect();
    }
}

int main(int argc, char** argv) {
    g_argc = argc;
    ancfl::IOManager iom(1);
    ancfl::ZKClient::ptr client(new ancfl::ZKClient);
    if (g_argc > 1) {
        ANCFL_LOG_INFO(g_logger)
            << client->init("127.0.0.1:2181", 3000, on_watcher);
        // ANCFL_LOG_INFO(g_logger) <<
        // client->init("127.0.0.1:21811,127.0.0.1:21812,127.0.0.1:21811", 3000,
        // on_watcher);
        iom.addTimer(1115000, [client]() { client->close(); });
    } else {
        ANCFL_LOG_INFO(g_logger)
            << client->init("127.0.0.1:21811,127.0.0.1:21812,127.0.0.1:21811",
                            3000, on_watcher);
        iom.addTimer(
            5000, []() {}, true);
    }
    iom.stop();
    return 0;
}



