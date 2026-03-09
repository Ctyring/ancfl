/**
 * @file fd_manager.h
 * @brief 文件句柄管理�? */
#ifndef __FD_MANAGER_H__
#define __FD_MANAGER_H__

#include <memory>
#include <vector>
#include "singleton.h"
#include "thread.h"

namespace ancfl {

/**
 * @brief 文件句柄上下文类
 * @details 管理文件句柄类型(是否socket)
 *          是否阻塞,是否关闭,�?写超时时�? */
class FdCtx : public std::enable_shared_from_this<FdCtx> {
   public:
    typedef std::shared_ptr<FdCtx> ptr;
    /**
     * @brief 通过文件句柄构造FdCtx
     */
    FdCtx(int fd);
    /**
     * @brief 析构函数
     */
    ~FdCtx();

    /**
     * @brief 是否初始化完�?     */
    bool isInit() const { return m_isInit; }

    /**
     * @brief 是否socket
     */
    bool isSocket() const { return m_isSocket; }

    /**
     * @brief 是否已关�?     */
    bool isClose() const { return m_isClosed; }

    /**
     * @brief 设置用户主动设置非阻�?     * @param[in] v 是否阻塞
     */
    void setUserNonblock(bool v) { m_userNonblock = v; }

    /**
     * @brief 获取是否用户主动设置的非阻塞
     */
    bool getUserNonblock() const { return m_userNonblock; }

    /**
     * @brief 设置系统非阻�?     * @param[in] v 是否阻塞
     */
    void setSysNonblock(bool v) { m_sysNonblock = v; }

    /**
     * @brief 获取系统非阻�?     */
    bool getSysNonblock() const { return m_sysNonblock; }

    /**
     * @brief 设置超时时间
     * @param[in] type 类型SO_RCVTIMEO(读超�?, SO_SNDTIMEO(写超�?
     * @param[in] v 时间毫秒
     */
    void setTimeout(int type, uint64_t v);

    /**
     * @brief 获取超时时间
     * @param[in] type 类型SO_RCVTIMEO(读超�?, SO_SNDTIMEO(写超�?
     * @return 超时时间毫秒
     */
    uint64_t getTimeout(int type);

   private:
    /**
     * @brief 初始�?     */
    bool init();

   private:
    /// 是否初始�?    bool m_isInit : 1;
    /// 是否socket
    bool m_isSocket : 1;
    /// 是否hook非阻�?    bool m_sysNonblock : 1;
    /// 是否用户主动设置非阻�?    bool m_userNonblock : 1;
    /// 是否关闭
    bool m_isClosed : 1;
    /// 文件句柄
    int m_fd;
    /// 读超时时间毫�?    uint64_t m_recvTimeout;
    /// 写超时时间毫�?    uint64_t m_sendTimeout;
};

/**
 * @brief 文件句柄管理�? */
class FdManager {
   public:
    typedef RWMutex RWMutexType;
    /**
     * @brief 无参构造函�?     */
    FdManager();

    /**
     * @brief 获取/创建文件句柄类FdCtx
     * @param[in] fd 文件句柄
     * @param[in] auto_create 是否自动创建
     * @return 返回对应文件句柄类FdCtx::ptr
     */
    FdCtx::ptr get(int fd, bool auto_create = false);

    /**
     * @brief 删除文件句柄�?     * @param[in] fd 文件句柄
     */
    void del(int fd);

   private:
    /// 读写�?    RWMutexType m_mutex;
    /// 文件句柄集合
    std::vector<FdCtx::ptr> m_datas;
};

/// 文件句柄单例
typedef Singleton<FdManager> FdMgr;

}  // namespace ancfl

#endif



