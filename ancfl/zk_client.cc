#include "zk_client.h"

namespace ancfl {

ACL_vector ZOO_OPEN_ACL_UNSAFE = {1, nullptr};

const int ZKClient::EventType::CREATED = 1;
const int ZKClient::EventType::DELETED = 2;
const int ZKClient::EventType::CHANGED = 3;
const int ZKClient::EventType::CHILD = 4;
const int ZKClient::EventType::SESSION = 5;
const int ZKClient::EventType::NOWATCHING = 6;

const int ZKClient::FlagsType::EPHEMERAL = 1;
const int ZKClient::FlagsType::SEQUENCE = 2;
const int ZKClient::FlagsType::CONTAINER = 4;

const int ZKClient::StateType::EXPIRED_SESSION = -112;
const int ZKClient::StateType::AUTH_FAILED = -113;
const int ZKClient::StateType::CONNECTING = 1;
const int ZKClient::StateType::ASSOCIATING = 2;
const int ZKClient::StateType::CONNECTED = 3;
const int ZKClient::StateType::READONLY = 5;
const int ZKClient::StateType::NOTCONNECTED = 999;

ZKClient::ZKClient() 
    : m_handle(nullptr)
    , m_recvTimeout(0)
    , m_initialized(false) {}

ZKClient::~ZKClient() {
    close();
}

bool ZKClient::reconnect() {
    return m_initialized;
}

bool ZKClient::init(const std::string& hosts,
                    int recv_timeout,
                    watcher_callback cb,
                    log_callback lcb) {
    if (m_initialized) {
        return true;
    }
    m_hosts = hosts;
    m_recvTimeout = recv_timeout;
    if (cb) {
        m_watcherCb = std::bind(cb, std::placeholders::_1, std::placeholders::_2,
                                std::placeholders::_3, shared_from_this());
    }
    m_logCb = lcb;
    m_initialized = true;
    return true;
}

int32_t ZKClient::setServers(const std::string& hosts) {
    m_hosts = hosts;
    return 0;
}

int32_t ZKClient::create(const std::string& path,
                         const std::string& val,
                         std::string& new_path,
                         const struct ACL_vector* acl,
                         int flags) {
    new_path = path;
    return 0;
}

int32_t ZKClient::exists(const std::string& path, bool watch, Stat* stat) {
    return -1;
}

int32_t ZKClient::del(const std::string& path, int version) {
    return -1;
}

int32_t ZKClient::get(const std::string& path,
                      std::string& val,
                      bool watch,
                      Stat* stat) {
    return -1;
}

int32_t ZKClient::getConfig(std::string& val, bool watch, Stat* stat) {
    return -1;
}

int32_t ZKClient::set(const std::string& path,
                      const std::string& val,
                      int version,
                      Stat* stat) {
    return -1;
}

int32_t ZKClient::getChildren(const std::string& path,
                              std::vector<std::string>& val,
                              bool watch,
                              Stat* stat) {
    return -1;
}

int32_t ZKClient::close() {
    m_watcherCb = nullptr;
    m_initialized = false;
    return 0;
}

std::string ZKClient::getCurrentServer() {
    return "";
}

int32_t ZKClient::getState() {
    return m_initialized ? StateType::CONNECTED : StateType::NOTCONNECTED;
}

}  // namespace ancfl
