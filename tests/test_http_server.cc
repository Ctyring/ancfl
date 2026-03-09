#include "ancfl/http/http_server.h"
#include "ancfl/log.h"
static ancfl::Logger::ptr g_logger = ANCFL_LOG_ROOT();
#define XX(...) #__VA_ARGS__

ancfl::IOManager::ptr worker;
void run() {
    g_logger->setLevel(ancfl::LogLevel::INFO);
    // ancfl::http::HttpServer::ptr server(new ancfl::http::HttpServer(true,
    // worker.get(), ancfl::IOManager::GetThis()));
    ancfl::http::HttpServer::ptr server(new ancfl::http::HttpServer(true));
    ancfl::Address::ptr addr =
        ancfl::Address::LookupAnyIPAddress("0.0.0.0:8020");
    while (!server->bind(addr)) {
        sleep(2);
    }
    auto sd = server->getServletDispatch();
    sd->addServlet("/ancfl/xx", [](ancfl::http::HttpRequest::ptr req,
                                   ancfl::http::HttpResponse::ptr rsp,
                                   ancfl::http::HttpSession::ptr session) {
        rsp->setBody(req->toString());
        return 0;
    });
    sd->addGlobServlet("/ancfl/*", [](ancfl::http::HttpRequest::ptr req,
                                      ancfl::http::HttpResponse::ptr rsp,
                                      ancfl::http::HttpSession::ptr session) {
        rsp->setBody("Glob:\r\n" + req->toString());
        return 0;
    });
    sd->addGlobServlet("/ancflx/*", [](ancfl::http::HttpRequest::ptr req,
                                       ancfl::http::HttpResponse::ptr rsp,
                                       ancfl::http::HttpSession::ptr session) {
        rsp->setBody(XX(
            <html><head><title> 404 Not Found</ title></ head><body><center>
                    <h1> 404 Not Found</ h1></ center><hr><center> nginx /
                    1.16.0 <
                / center > </ body></ html> < !--a padding to disable MSIE and
            Chrome friendly error page-- > < !--a padding to disable MSIE and
            Chrome friendly error page-- > < !--a padding to disable MSIE and
            Chrome friendly error page-- > < !--a padding to disable MSIE and
            Chrome friendly error page-- > < !--a padding to disable MSIE and
            Chrome friendly error page-- > < !--a padding to disable MSIE and
            Chrome friendly error page-- >));
        return 0;
    });
    ANCFL_LOG_INFO(g_logger) << "server start";
    server->start();
}

int main(int argc, char** argv) {
    ancfl::IOManager iom(1, true, "main");
    worker.reset(new ancfl::IOManager(3, false, "worker"));
    iom.schedule(run);
    return 0;
}



