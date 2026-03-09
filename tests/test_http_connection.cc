#include <fstream>
#include <iostream>
#include "ancfl/http/http_connection.h"
#include "ancfl/http/http_parser.h"
#include "ancfl/iomanager.h"
#include "ancfl/log.h"
#include "ancfl/streams/zlib_stream.h"

static ancfl::Logger::ptr g_logger = ANCFL_LOG_ROOT();

void test_pool() {
    ancfl::http::HttpConnectionPool::ptr pool(
        new ancfl::http::HttpConnectionPool("www.ancfl.top", "", 80, false, 10,
                                            1000 * 30, 5));

    ancfl::IOManager::GetThis()->addTimer(
        1000,
        [pool]() {
            auto r = pool->doGet("/", 300);
            ANCFL_LOG_INFO(g_logger) << r->toString();
        },
        true);
}

void run() {
    ancfl::Address::ptr addr =
        ancfl::Address::LookupAnyIPAddress("www.ancfl.top:80");
    if (!addr) {
        ANCFL_LOG_INFO(g_logger) << "get addr error";
        return;
    }

    ancfl::Socket::ptr sock = ancfl::Socket::CreateTCP(addr);
    bool rt = sock->connect(addr);
    if (!rt) {
        ANCFL_LOG_INFO(g_logger) << "connect " << *addr << " failed";
        return;
    }

    ancfl::http::HttpConnection::ptr conn(
        new ancfl::http::HttpConnection(sock));
    ancfl::http::HttpRequest::ptr req(new ancfl::http::HttpRequest);
    req->setPath("/blog/");
    req->setHeader("host", "www.ancfl.top");
    ANCFL_LOG_INFO(g_logger) << "req:" << std::endl << *req;

    conn->sendRequest(req);
    auto rsp = conn->recvResponse();

    if (!rsp) {
        ANCFL_LOG_INFO(g_logger) << "recv response error";
        return;
    }
    ANCFL_LOG_INFO(g_logger) << "rsp:" << std::endl << *rsp;

    std::ofstream ofs("rsp.dat");
    ofs << *rsp;

    ANCFL_LOG_INFO(g_logger) << "=========================";

    auto r =
        ancfl::http::HttpConnection::DoGet("http://www.ancfl.top/blog/", 300);
    ANCFL_LOG_INFO(g_logger)
        << "result=" << r->result << " error=" << r->error
        << " rsp=" << (r->response ? r->response->toString() : "");

    ANCFL_LOG_INFO(g_logger) << "=========================";
    test_pool();
}

void test_https() {
    auto r = ancfl::http::HttpConnection::DoGet(
        "http://www.baidu.com/", 300,
        {{"Accept-Encoding", "gzip, deflate, br"},
         {"Connection", "keep-alive"},
         {"User-Agent", "curl/7.29.0"}});
    ANCFL_LOG_INFO(g_logger)
        << "result=" << r->result << " error=" << r->error
        << " rsp=" << (r->response ? r->response->toString() : "");

    // ancfl::http::HttpConnectionPool::ptr pool(new
    // ancfl::http::HttpConnectionPool(
    //             "www.baidu.com", "", 80, false, 10, 1000 * 30, 5));
    auto pool = ancfl::http::HttpConnectionPool::Create("https://www.baidu.com",
                                                        "", 10, 1000 * 30, 5);
    ancfl::IOManager::GetThis()->addTimer(
        1000,
        [pool]() {
            auto r = pool->doGet("/", 3000,
                                 {{"Accept-Encoding", "gzip, deflate, br"},
                                  {"User-Agent", "curl/7.29.0"}});
            ANCFL_LOG_INFO(g_logger) << r->toString();
        },
        true);
}

void test_data() {
    ancfl::Address::ptr addr = ancfl::Address::LookupAny("www.baidu.com:80");
    auto sock = ancfl::Socket::CreateTCP(addr);

    sock->connect(addr);
    const char buff[] =
        "GET / HTTP/1.1\r\n"
        "connection: close\r\n"
        "Accept-Encoding: gzip, deflate, br\r\n"
        "Host: www.baidu.com\r\n\r\n";
    sock->send(buff, sizeof(buff));

    std::string line;
    line.resize(1024);

    std::ofstream ofs("http.dat", std::ios::binary);
    int total = 0;
    int len = 0;
    while ((len = sock->recv(&line[0], line.size())) > 0) {
        total += len;
        ofs.write(line.c_str(), len);
    }
    std::cout << "total: " << total << " tellp=" << ofs.tellp() << std::endl;
    ofs.flush();
}

void test_parser() {
    std::ifstream ifs("http.dat", std::ios::binary);
    std::string content;
    std::string line;
    line.resize(1024);

    int total = 0;
    while (!ifs.eof()) {
        ifs.read(&line[0], line.size());
        content.append(&line[0], ifs.gcount());
        total += ifs.gcount();
    }

    std::cout << "length: " << content.size() << " total: " << total
              << std::endl;
    ancfl::http::HttpResponseParser parser;
    size_t nparse = parser.execute(&content[0], content.size(), false);
    std::cout << "finish: " << parser.isFinished() << std::endl;
    content.resize(content.size() - nparse);
    std::cout << "rsp: " << *parser.getData() << std::endl;

    auto& client_parser = parser.getParser();
    std::string body;
    int cl = 0;
    do {
        size_t nparse = parser.execute(&content[0], content.size(), true);
        std::cout << "content_len: " << client_parser.content_len
                  << " left: " << content.size() << std::endl;
        cl += client_parser.content_len;
        content.resize(content.size() - nparse);
        body.append(content.c_str(), client_parser.content_len);
        content = content.substr(client_parser.content_len + 2);
    } while (!client_parser.chunks_done);

    std::cout << "total: " << body.size() << " content:" << cl << std::endl;

    ancfl::ZlibStream::ptr stream = ancfl::ZlibStream::CreateGzip(false);
    stream->write(body.c_str(), body.size());
    stream->flush();

    body = stream->getResult();

    std::ofstream ofs("http.txt");
    ofs << body;
}

int main(int argc, char** argv) {
    ancfl::IOManager iom(2);
    // iom.schedule(run);
    iom.schedule(test_https);
    return 0;
}



