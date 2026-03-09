#include <arpa/inet.h>
#include <fcntl.h>
#include <sys/epoll.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>
#include <iostream>
#include "ancfl/iomanager.h"
#include "ancfl/ancfl.h"

ancfl::Logger::ptr g_logger = ANCFL_LOG_ROOT();

int sock = 0;

void test_fiber() {
    ANCFL_LOG_INFO(g_logger) << "test_fiber sock=" << sock;

    // sleep(3);

    // close(sock);
    // ancfl::IOManager::GetThis()->cancelAll(sock);

    sock = socket(AF_INET, SOCK_STREAM, 0);
    fcntl(sock, F_SETFL, O_NONBLOCK);

    sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(80);
    inet_pton(AF_INET, "115.239.210.27", &addr.sin_addr.s_addr);

    if (!connect(sock, (const sockaddr*)&addr, sizeof(addr))) {
    } else if (errno == EINPROGRESS) {
        ANCFL_LOG_INFO(g_logger)
            << "add event errno=" << errno << " " << strerror(errno);
        ancfl::IOManager::GetThis()->addEvent(
            sock, ancfl::IOManager::READ,
            []() { ANCFL_LOG_INFO(g_logger) << "read callback"; });
        ancfl::IOManager::GetThis()->addEvent(
            sock, ancfl::IOManager::WRITE, []() {
                ANCFL_LOG_INFO(g_logger) << "write callback";
                // close(sock);
                ancfl::IOManager::GetThis()->cancelEvent(
                    sock, ancfl::IOManager::READ);
                close(sock);
            });
    } else {
        ANCFL_LOG_INFO(g_logger) << "else " << errno << " " << strerror(errno);
    }
}

void test1() {
    std::cout << "EPOLLIN=" << EPOLLIN << " EPOLLOUT=" << EPOLLOUT << std::endl;
    ancfl::IOManager iom(2, false);
    iom.schedule(&test_fiber);
}
ancfl::Timer::ptr s_timer;
void test_timer() {
    ancfl::IOManager iom(5);
    s_timer = iom.addTimer(
        1000,
        []() {
            static int i = 0;
            ANCFL_LOG_INFO(g_logger) << "hello timer i=" << i;
            if (++i == 3) {
                s_timer->reset(2000, true);
                // s_timer->cancel();
            }
        },
        true);
}

int main(int argc, char** argv) {
    // test1();
    test_timer();
    return 0;
}



