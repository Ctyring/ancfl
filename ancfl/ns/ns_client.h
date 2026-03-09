#ifndef __ANCFL_NS_NS_CLIENT_H__
#define __ANCFL_NS_NS_CLIENT_H__

#include "ns_protocol.h"
#include "ancfl/rock/rock_stream.h"

namespace ancfl {
namespace ns {

class NSClient : public RockConnection {
   public:
    typedef std::shared_ptr<NSClient> ptr;
    NSClient();
    ~NSClient();

    const std::set<std::string>& getQueryDomains();
    void setQueryDomains(const std::set<std::string>& v);

    void addQueryDomain(const std::string& domain);
    void delQueryDomain(const std::string& domain);

    bool hasQueryDomain(const std::string& domain);

    RockResult::ptr query();

    void init();
    void uninit();
    NSDomainSet::ptr getDomains() const { return m_domains; }

   private:
    void onQueryDomainChange();
    bool onConnect(ancfl::AsyncSocketStream::ptr stream);
    void onDisconnect(ancfl::AsyncSocketStream::ptr stream);
    bool onNotify(ancfl::RockNotify::ptr, ancfl::RockStream::ptr);

    void onTimer();

   private:
    ancfl::RWMutex m_mutex;
    std::set<std::string> m_queryDomains;
    NSDomainSet::ptr m_domains;
    uint32_t m_sn = 0;
    ancfl::Timer::ptr m_timer;
};

}  // namespace ns
}  // namespace ancfl

#endif



