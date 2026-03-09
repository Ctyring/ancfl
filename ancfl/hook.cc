#include "hook.h"
#include <dlfcn.h>

#include "config.h"
#include "fd_manager.h"
#include "fiber.h"
#include "iomanager.h"
#include "log.h"
#include "macro.h"

ancfl::Logger::ptr g_logger = ANCFL_LOG_NAME("system");
namespace ancfl {

static ancfl::ConfigVar<int>::ptr g_tcp_connect_timeout =
    ancfl::Config::Lookup("tcp.connect.timeout", 5000, "tcp connect timeout");

static thread_local bool t_hook_enable = false;

#define HOOK_FUN(XX) \
    XX(sleep)        \
    XX(usleep)       \
    XX(nanosleep)    \
    XX(socket)       \
    XX(connect)      \
    XX(accept)       \
    XX(read)         \
    XX(readv)        \
    XX(recv)         \
    XX(recvfrom)     \
    XX(recvmsg)      \
    XX(write)        \
    XX(writev)       \
    XX(send)         \
    XX(sendto)       \
    XX(sendmsg)      \
    XX(close)        \
    XX(fcntl)        \
    XX(ioctl)        \
    XX(getsockopt)   \
    XX(setsockopt)

void hook_init() {
    static bool is_inited = false;
    if (is_inited) {
        return;
    }
#define XX(name) name##_f = (name##_fun)dlsym(RTLD_NEXT, #name);
    HOOK_FUN(XX);
#undef XX
}

static uint64_t s_connect_timeout = -1;
struct _HookIniter {
    _HookIniter() {
        hook_init();
        s_connect_timeout = g_tcp_connect_timeout->getValue();

        g_tcp_connect_timeout->addListener(
            [](const int& old_value, const int& new_value) {
                ANCFL_LOG_INFO(g_logger) << "tcp connect timeout changed from "
                                         << old_value << " to " << new_value;
                s_connect_timeout = new_value;
            });
    }
};

static _HookIniter s_hook_initer;

bool is_hook_enable() {
    return t_hook_enable;
}

void set_hook_enable(bool flag) {
    t_hook_enable = flag;
}

}  // namespace ancfl

struct timer_info {
    int cancelled = 0;
};

template <typename OriginFun, typename... Args>
static ssize_t do_io(int fd,
                     OriginFun fun,
                     const char* hook_fun_name,
                     uint32_t event,
                     int timeout_so,
                     Args&&... args) {
    if (!ancfl::t_hook_enable) {
        return fun(fd, std::forward<Args>(args)...);
    }

    ancfl::FdCtx::ptr ctx = ancfl::FdMgr::GetInstance()->get(fd);
    if (!ctx) {
        return fun(fd, std::forward<Args>(args)...);
    }

    if (ctx->isClose()) {
        errno = EBADF;
        return -1;
    }

    if (!ctx->isSocket() || ctx->getUserNonblock()) {
        return fun(fd, std::forward<Args>(args)...);
    }

    uint64_t to = ctx->getTimeout(timeout_so);
    std::shared_ptr<timer_info> tinfo(new timer_info);

retry:
    ssize_t n = fun(fd, std::forward<Args>(args)...);
    // 如果失败并且失败原因为中断，那么重试
    while (n == -1 && errno == EINTR) {
        n = fun(fd, std::forward<Args>(args)...);
    }
    // 失败原因是当前无法立即完成，但在稍后的某个时间可能会成功完成
    if (n == -1 && errno == EAGAIN) {
        ancfl::IOManager* iom = ancfl::IOManager::GetThis();
        ancfl::Timer::ptr timer;
        std::weak_ptr<timer_info> winfo(tinfo);
        // 如果有超时时�?        if (to != (uint64_t)-1) {
            timer = iom->addConditionTimer(
                to,
                [winfo, fd, iom, event]() {
                    auto t = winfo.lock();
                    if (!t || t->cancelled) {
                        return;
                    }
                    t->cancelled = ETIMEDOUT;
                    iom->cancelEvent(fd, (ancfl::IOManager::Event)(event));
                },
                winfo);
        }

        int rt = iom->addEvent(fd, (ancfl::IOManager::Event)(event));
        if (ANCFL_UNLIKELY(rt)) {
            ANCFL_LOG_ERROR(g_logger)
                << hook_fun_name << " addEvent(" << fd << ", " << event << ")";
            if (timer) {
                timer->cancel();
            }
            return -1;
        } else {
            ancfl::Fiber::YieldToHold();
            if (timer) {
                timer->cancel();
            }
            if (tinfo->cancelled) {
                errno = tinfo->cancelled;
                return -1;
            }
            goto retry;
        }
    }

    return n;
}

extern "C" {
#define XX(name) name##_fun name##_f = nullptr;
HOOK_FUN(XX);
#undef XX

unsigned int sleep(unsigned int seconds) {
    if (!ancfl::t_hook_enable) {
        return sleep_f(seconds);
    }

    ancfl::Fiber::ptr fiber = ancfl::Fiber::GetThis();
    ancfl::IOManager* iom = ancfl::IOManager::GetThis();
    iom->addTimer(
        seconds * 1000,
        // ::* 指向成员的指�?        // void(*)(int) &a; 把a转换成返回值为void，参数为int的函数指�?        // bind绑定类成员函数时，第一个参数表示对象成员函数地址，第二个参数表示对象地址
        std::bind((void(ancfl::Scheduler::*)(ancfl::Fiber::ptr, int thread)) &
                      ancfl::IOManager::schedule,
                  iom, fiber, -1));
    ancfl::Fiber::YieldToHold();
    return 0;
}

int usleep(useconds_t usec) {
    if (!ancfl::t_hook_enable) {
        return usleep_f(usec);
    }
    ancfl::Fiber::ptr fiber = ancfl::Fiber::GetThis();
    ancfl::IOManager* iom = ancfl::IOManager::GetThis();
    iom->addTimer(
        usec / 1000,
        std::bind((void(ancfl::Scheduler::*)(ancfl::Fiber::ptr, int thread)) &
                      ancfl::IOManager::schedule,
                  iom, fiber, -1));
    ancfl::Fiber::YieldToHold();
    return 0;
}

int nanosleep(const struct timespec* req, struct timespec* rem) {
    if (!ancfl::t_hook_enable) {
        return nanosleep_f(req, rem);
    }

    int timeout_ms = req->tv_sec * 1000 + req->tv_nsec / 1000 / 1000;
    ancfl::Fiber::ptr fiber = ancfl::Fiber::GetThis();
    ancfl::IOManager* iom = ancfl::IOManager::GetThis();
    iom->addTimer(
        timeout_ms,
        std::bind((void(ancfl::Scheduler::*)(ancfl::Fiber::ptr, int thread)) &
                      ancfl::IOManager::schedule,
                  iom, fiber, -1));
    ancfl::Fiber::YieldToHold();
    return 0;
}

int socket(int domain, int type, int protocol) {
    if (!ancfl::t_hook_enable) {
        return socket_f(domain, type, protocol);
    }
    int fd = socket_f(domain, type, protocol);
    if (fd == -1) {
        return fd;
    }
    ancfl::FdMgr::GetInstance()->get(fd, true);
    return fd;
}

int connect_with_timeout(int fd,
                         const struct sockaddr* addr,
                         socklen_t addrlen,
                         uint64_t timeout_ms) {
    if (!ancfl::t_hook_enable) {
        return connect_f(fd, addr, addrlen);
    }
    // 文件句柄的情况判�?    ancfl::FdCtx::ptr ctx = ancfl::FdMgr::GetInstance()->get(fd);
    if (!ctx || ctx->isClose()) {
        errno = EBADF;
        return -1;
    }

    if (!ctx->isSocket()) {
        return connect_f(fd, addr, addrlen);
    }

    if (ctx->getUserNonblock()) {
        return connect_f(fd, addr, addrlen);
    }

    // 如果而文件是正常的，进行连接
    int n = connect_f(fd, addr, addrlen);
    // 如果连接成功，或者连接失败，但是错误不是EINPROGRESS，直接返�?    if (n == 0) {
        return 0;
    } else if (n != -1 || errno != EINPROGRESS) {
        return n;
    }
    // EINPROGRESS 表示连接正在进行�?    ancfl::IOManager* iom = ancfl::IOManager::GetThis();
    ancfl::Timer::ptr timer;
    std::shared_ptr<timer_info> tinfo(new timer_info);
    std::weak_ptr<timer_info> winfo(tinfo);
    // 如果存在超时时间，添加一个定时器，定时器会在超时的时候调�?    if (timeout_ms != (uint64_t)-1) {
        timer = iom->addConditionTimer(
            timeout_ms,
            [winfo, fd, iom]() {
                auto t = winfo.lock();
                // 如果到期的时候，连接已经成功了，那么就不需要取消了
                if (!t || t->cancelled) {
                    return;
                }
                // 修改状态并取消事件
                t->cancelled = ETIMEDOUT;
                iom->cancelEvent(fd, ancfl::IOManager::WRITE);
            },
            winfo);
    }
    // 添加事件
    int rt = iom->addEvent(fd, ancfl::IOManager::WRITE);
    if (rt == 0) {
        // 把自己切出去
        ancfl::Fiber::YieldToHold();
        // 如果是超时，这里就会返回
        if (timer) {
            timer->cancel();
        }
        if (tinfo->cancelled) {
            errno = tinfo->cancelled;
            return -1;
        }
    } else {
        if (timer) {
            timer->cancel();
        }
        ANCFL_LOG_ERROR(g_logger)
            << "connect addEvent(" << fd << ", WRITE) error";
    }
    // 判断是否连接成功
    int error = 0;
    socklen_t len = sizeof(int);
    // 获取状态码
    if (-1 == getsockopt(fd, SOL_SOCKET, SO_ERROR, &error, &len)) {
        return -1;
    }
    // 如果状态码�?，表示连接成�?    if (!error) {
        return 0;
    } else {
        errno = error;
        return -1;
    }
}

int connect(int sockfd, const struct sockaddr* addr, socklen_t addrlen) {
    return connect_with_timeout(sockfd, addr, addrlen,
                                ancfl::s_connect_timeout);
}

int accept(int s, struct sockaddr* addr, socklen_t* addrlen) {
    int fd = do_io(s, accept_f, "accept", ancfl::IOManager::READ, SO_RCVTIMEO,
                   addr, addrlen);
    if (fd >= 0) {
        ancfl::FdMgr::GetInstance()->get(fd, true);
    }
    return fd;
}

ssize_t read(int fd, void* buf, size_t count) {
    return do_io(fd, read_f, "read", ancfl::IOManager::READ, SO_RCVTIMEO, buf,
                 count);
}

ssize_t readv(int fd, const struct iovec* iov, int iovcnt) {
    return do_io(fd, readv_f, "readv", ancfl::IOManager::READ, SO_RCVTIMEO, iov,
                 iovcnt);
}

ssize_t recv(int sockfd, void* buf, size_t len, int flags) {
    return do_io(sockfd, recv_f, "recv", ancfl::IOManager::READ, SO_RCVTIMEO,
                 buf, len, flags);
}

ssize_t recvfrom(int sockfd,
                 void* buf,
                 size_t len,
                 int flags,
                 struct sockaddr* src_addr,
                 socklen_t* addrlen) {
    return do_io(sockfd, recvfrom_f, "recvfrom", ancfl::IOManager::READ,
                 SO_RCVTIMEO, buf, len, flags, src_addr, addrlen);
}

ssize_t recvmsg(int sockfd, struct msghdr* msg, int flags) {
    return do_io(sockfd, recvmsg_f, "recvmsg", ancfl::IOManager::READ,
                 SO_RCVTIMEO, msg, flags);
}

ssize_t write(int fd, const void* buf, size_t count) {
    return do_io(fd, write_f, "write", ancfl::IOManager::WRITE, SO_SNDTIMEO,
                 buf, count);
}

ssize_t writev(int fd, const struct iovec* iov, int iovcnt) {
    return do_io(fd, writev_f, "writev", ancfl::IOManager::WRITE, SO_SNDTIMEO,
                 iov, iovcnt);
}

ssize_t send(int s, const void* msg, size_t len, int flags) {
    return do_io(s, send_f, "send", ancfl::IOManager::WRITE, SO_SNDTIMEO, msg,
                 len, flags);
}

ssize_t sendto(int s,
               const void* msg,
               size_t len,
               int flags,
               const struct sockaddr* to,
               socklen_t tolen) {
    return do_io(s, sendto_f, "sendto", ancfl::IOManager::WRITE, SO_SNDTIMEO,
                 msg, len, flags, to, tolen);
}

ssize_t sendmsg(int s, const struct msghdr* msg, int flags) {
    return do_io(s, sendmsg_f, "sendmsg", ancfl::IOManager::WRITE, SO_SNDTIMEO,
                 msg, flags);
}

int close(int fd) {
    if (!ancfl::t_hook_enable) {
        return close_f(fd);
    }

    ancfl::FdCtx::ptr ctx = ancfl::FdMgr::GetInstance()->get(fd);
    if (ctx) {
        auto iom = ancfl::IOManager::GetThis();
        if (iom) {
            iom->cancelAll(fd);
        }
        ancfl::FdMgr::GetInstance()->del(fd);
    }
    return close_f(fd);
}

int fcntl(int fd, int cmd, ... /* arg */) {
    va_list va;
    va_start(va, cmd);
    switch (cmd) {
        case F_SETFL: {
            int arg = va_arg(va, int);
            va_end(va);
            ancfl::FdCtx::ptr ctx = ancfl::FdMgr::GetInstance()->get(fd);
            if (!ctx || ctx->isClose() || !ctx->isSocket()) {
                return fcntl_f(fd, cmd, arg);
            }
            ctx->setUserNonblock(arg & O_NONBLOCK);
            if (ctx->getSysNonblock()) {
                arg |= O_NONBLOCK;
            } else {
                arg &= ~O_NONBLOCK;
            }
            return fcntl_f(fd, cmd, arg);
        } break;
        case F_GETFL: {
            va_end(va);
            int arg = fcntl_f(fd, cmd);
            ancfl::FdCtx::ptr ctx = ancfl::FdMgr::GetInstance()->get(fd);
            if (!ctx || ctx->isClose() || !ctx->isSocket()) {
                return arg;
            }
            if (ctx->getUserNonblock()) {
                return arg | O_NONBLOCK;
            } else {
                return arg & ~O_NONBLOCK;
            }
        } break;
        case F_DUPFD:
        case F_DUPFD_CLOEXEC:
        case F_SETFD:
        case F_SETOWN:
        case F_SETSIG:
        case F_SETLEASE:
        case F_NOTIFY:
#ifdef F_SETPIPE_SZ
        case F_SETPIPE_SZ:
#endif
        {
            int arg = va_arg(va, int);
            va_end(va);
            return fcntl_f(fd, cmd, arg);
        } break;
        case F_GETFD:
        case F_GETOWN:
        case F_GETSIG:
        case F_GETLEASE:
#ifdef F_GETPIPE_SZ
        case F_GETPIPE_SZ:
#endif
        {
            va_end(va);
            return fcntl_f(fd, cmd);
        } break;
        case F_SETLK:
        case F_SETLKW:
        case F_GETLK: {
            struct flock* arg = va_arg(va, struct flock*);
            va_end(va);
            return fcntl_f(fd, cmd, arg);
        } break;
        case F_GETOWN_EX:
        case F_SETOWN_EX: {
            struct f_owner_exlock* arg = va_arg(va, struct f_owner_exlock*);
            va_end(va);
            return fcntl_f(fd, cmd, arg);
        } break;
        default:
            va_end(va);
            return fcntl_f(fd, cmd);
    }
}

int ioctl(int d, unsigned long int request, ...) {
    va_list va;
    va_start(va, request);
    void* arg = va_arg(va, void*);
    va_end(va);

    if (FIONBIO == request) {
        bool user_nonblock = !!*(int*)arg;
        ancfl::FdCtx::ptr ctx = ancfl::FdMgr::GetInstance()->get(d);
        if (!ctx || ctx->isClose() || !ctx->isSocket()) {
            return ioctl_f(d, request, arg);
        }
        ctx->setUserNonblock(user_nonblock);
    }
    return ioctl_f(d, request, arg);
}

int getsockopt(int sockfd,
               int level,
               int optname,
               void* optval,
               socklen_t* optlen) {
    return getsockopt_f(sockfd, level, optname, optval, optlen);
}

int setsockopt(int sockfd,
               int level,
               int optname,
               const void* optval,
               socklen_t optlen) {
    if (!ancfl::t_hook_enable) {
        return setsockopt_f(sockfd, level, optname, optval, optlen);
    }
    if (level == SOL_SOCKET) {
        if (optname == SO_RCVTIMEO || optname == SO_SNDTIMEO) {
            ancfl::FdCtx::ptr ctx = ancfl::FdMgr::GetInstance()->get(sockfd);
            if (ctx) {
                const timeval* v = (const timeval*)optval;
                ctx->setTimeout(optname, v->tv_sec * 1000 + v->tv_usec / 1000);
            }
        }
    }
    return setsockopt_f(sockfd, level, optname, optval, optlen);
}
}



