#ifndef __ANCFL_NS_NAME_SERVER_MODULE_H__
#define __ANCFL_NS_NAME_SERVER_MODULE_H__

#include "ns_protocol.h"
#include "ancfl/module.h"

namespace ancfl {
namespace ns {

class NameServerModule;
class NSClientInfo {
    friend class NameServerModule;

   public:
    typedef std::shared_ptr<NSClientInfo> ptr;

   private:
    NSNode::ptr m_node;
    std::map<std::string, std::set<uint32_t> > m_domain2cmds;
};

class NameServerModule : public RockModule {
   public:
    typedef std::shared_ptr<NameServerModule> ptr;
    NameServerModule();

    virtual bool handleRockRequest(ancfl::RockRequest::ptr request,
                                   ancfl::RockResponse::ptr response,
                                   ancfl::RockStream::ptr stream) override;
    virtual bool handleRockNotify(ancfl::RockNotify::ptr notify,
                                  ancfl::RockStream::ptr stream) override;
    virtual bool onConnect(ancfl::Stream::ptr stream) override;
    virtual bool onDisconnect(ancfl::Stream::ptr stream) override;
    virtual std::string statusString() override;

   private:
    bool handleRegister(ancfl::RockRequest::ptr request,
                        ancfl::RockResponse::ptr response,
                        ancfl::RockStream::ptr stream);
    bool handleQuery(ancfl::RockRequest::ptr request,
                     ancfl::RockResponse::ptr response,
                     ancfl::RockStream::ptr stream);
    bool handleTick(ancfl::RockRequest::ptr request,
                    ancfl::RockResponse::ptr response,
                    ancfl::RockStream::ptr stream);

   private:
    NSClientInfo::ptr get(ancfl::RockStream::ptr rs);
    void set(ancfl::RockStream::ptr rs, NSClientInfo::ptr info);

    void setQueryDomain(ancfl::RockStream::ptr rs,
                        const std::set<std::string>& ds);

    void doNotify(std::set<std::string>& domains,
                  std::shared_ptr<NotifyMessage> nty);

    std::set<ancfl::RockStream::ptr> getStreams(const std::string& domain);

   private:
    NSDomainSet::ptr m_domains;

    ancfl::RWMutex m_mutex;
    std::map<ancfl::RockStream::ptr, NSClientInfo::ptr> m_sessions;

    /// sessoin 关注的域�?    std::map<ancfl::RockStream::ptr, std::set<std::string> > m_queryDomains;
    /// 域名对应关注的session
    std::map<std::string, std::set<ancfl::RockStream::ptr> > m_domainToSessions;
};

}  // namespace ns
}  // namespace ancfl

#endif



