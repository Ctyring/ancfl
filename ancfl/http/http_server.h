/**
 * @file http_server.h
 * @brief HTTP服务器封�? */

#ifndef __ANCFL_HTTP_HTTP_SERVER_H__
#define __ANCFL_HTTP_HTTP_SERVER_H__

#include "http_session.h"
#include "servlet.h"
#include "ancfl/tcp_server.h"

namespace ancfl {
namespace http {

/**
 * @brief HTTP服务器类
 */
class HttpServer : public TcpServer {
   public:
    /// 智能指针类型
    typedef std::shared_ptr<HttpServer> ptr;

    /**
     * @brief 构造函�?     * @param[in] keepalive 是否长连�?     * @param[in] worker 工作调度�?     * @param[in] accept_worker 接收连接调度�?     */
    HttpServer(bool keepalive = false,
               ancfl::IOManager* worker = ancfl::IOManager::GetThis(),
               ancfl::IOManager* io_worker = ancfl::IOManager::GetThis(),
               ancfl::IOManager* accept_worker = ancfl::IOManager::GetThis());

    /**
     * @brief 获取ServletDispatch
     */
    ServletDispatch::ptr getServletDispatch() const { return m_dispatch; }

    /**
     * @brief 设置ServletDispatch
     */
    void setServletDispatch(ServletDispatch::ptr v) { m_dispatch = v; }

    virtual void setName(const std::string& v) override;

   protected:
    virtual void handleClient(Socket::ptr client) override;

   private:
    /// 是否支持长连�?    bool m_isKeepalive;
    /// Servlet分发�?    ServletDispatch::ptr m_dispatch;
};

}  // namespace http
}  // namespace ancfl

#endif



