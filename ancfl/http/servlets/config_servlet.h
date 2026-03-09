#ifndef __ANCFL_HTTP_SERVLET_CONFIG_H__
#define __ANCFL_HTTP_SERVLET_CONFIG_H__

#include "ancfl/http/servlet.h"
namespace ancfl {
namespace http {
class ConfigServlet : public Servlet {
   public:
    ConfigServlet();
    virtual int32_t handle(ancfl::http::HttpRequest::ptr request,
                           ancfl::http::HttpResponse::ptr response,
                           ancfl::http::HttpSession::ptr session) override;
};
}  // namespace http
}  // namespace ancfl

#endif



