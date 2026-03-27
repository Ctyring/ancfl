#ifndef __ANCFL_ZK_CLIENT_H__
#define __ANCFL_ZK_CLIENT_H__

#include <stdint.h>
#include <functional>
#include <memory>
#include <string>
#include <vector>

namespace ancfl {

static const int ZOK = 0;
static const int ZNODEEXISTS = -110;
static const int ZOO_CONNECTED_STATE = 3;
static const int ZOO_EXPIRED_SESSION_STATE = -112;
static const int ZOO_AUTH_FAILED_STATE = -113;
static const int ZOO_CONNECTING_STATE = 1;
static const int ZOO_ASSOCIATING_STATE = 2;
static const int ZOO_READONLY_STATE = 5;
static const int ZOO_NOTCONNECTED_STATE = 999;
static const int ZOO_CREATED_EVENT = 1;
static const int ZOO_DELETED_EVENT = 2;
static const int ZOO_CHANGED_EVENT = 3;
static const int ZOO_CHILD_EVENT = 4;
static const int ZOO_SESSION_EVENT = 5;
static const int ZOO_NOTWATCHING_EVENT = 6;
static const int ZOO_EPHEMERAL = 1;
static const int ZOO_SEQUENCE = 2;
static const int ZOO_CONTAINER = 4;

struct Stat {
    int64_t czxid;
    int64_t mzxid;
    int64_t ctime;
    int64_t mtime;
    int32_t version;
    int32_t cversion;
    int32_t aversion;
    int64_t ephemeralOwner;
    int32_t dataLength;
    int32_t numChildren;
    int64_t pzxid;
};

struct ACL {
    int32_t perms;
    char scheme[64];
    char id[64];
};

struct ACL_vector {
    int32_t count;
    ACL* data;
};

extern ACL_vector ZOO_OPEN_ACL_UNSAFE;

class ZKClient : public std::enable_shared_from_this<ZKClient> {
   public:
    class EventType {
       public:
        static const int CREATED;
        static const int DELETED;
        static const int CHANGED;
        static const int CHILD;
        static const int SESSION;
        static const int NOWATCHING;
    };
    class FlagsType {
       public:
        static const int EPHEMERAL;
        static const int SEQUENCE;
        static const int CONTAINER;
    };
    class StateType {
       public:
        static const int EXPIRED_SESSION;
        static const int AUTH_FAILED;
        static const int CONNECTING;
        static const int ASSOCIATING;
        static const int CONNECTED;
        static const int READONLY;
        static const int NOTCONNECTED;
    };

    typedef std::shared_ptr<ZKClient> ptr;
    typedef std::function<
        void(int type, int stat, const std::string& path, ZKClient::ptr)>
        watcher_callback;
    typedef void (*log_callback)(const char* message);

    ZKClient();
    ~ZKClient();

    bool init(const std::string& hosts,
              int recv_timeout,
              watcher_callback cb,
              log_callback lcb = nullptr);
    int32_t setServers(const std::string& hosts);

    int32_t create(const std::string& path,
                   const std::string& val,
                   std::string& new_path,
                   const struct ACL_vector* acl = nullptr,
                   int flags = 0);
    int32_t exists(const std::string& path, bool watch, Stat* stat = nullptr);
    int32_t del(const std::string& path, int version = -1);
    int32_t get(const std::string& path,
                std::string& val,
                bool watch,
                Stat* stat = nullptr);
    int32_t getConfig(std::string& val, bool watch, Stat* stat = nullptr);
    int32_t set(const std::string& path,
                const std::string& val,
                int version = -1,
                Stat* stat = nullptr);
    int32_t getChildren(const std::string& path,
                        std::vector<std::string>& val,
                        bool watch,
                        Stat* stat = nullptr);
    int32_t close();
    int32_t getState();
    std::string getCurrentServer();

    bool reconnect();

   private:
    typedef std::function<void(int type, int stat, const std::string& path)>
        watcher_callback2;

   private:
    void* m_handle;
    std::string m_hosts;
    watcher_callback2 m_watcherCb;
    log_callback m_logCb;
    int32_t m_recvTimeout;
    bool m_initialized;
};

}  // namespace ancfl

#endif
