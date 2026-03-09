#include "ancfl/http/http.h"
#include "ancfl/log.h"
void test() {
    ancfl::http::HttpRequest::ptr req(new ancfl::http::HttpRequest);
    req->setHeader("host", "www.ancfl.top");
    req->setBody("hello world!");
    req->dump(std::cout) << std::endl;
}

void test_response() {
    ancfl::http::HttpResponse::ptr resp(new ancfl::http::HttpResponse);
    resp->setHeader("X-X", "ancfl");
    resp->setBody("hello world!");
    resp->setStatus(ancfl::http::HttpStatus::BAD_REQUEST);
    resp->setClose(false);
    // 设置长连�?    resp->setHeader("Connection", "keep-alive");
    resp->dump(std::cout) << std::endl;
}
int main(int argc, char** argv) {
    test_response();
    return 0;
}



