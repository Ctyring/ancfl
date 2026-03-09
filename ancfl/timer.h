/**
 * @file timer.h
 * @brief 定时器封�? */
#ifndef __ANCFL_TIMER_H__
#define __ANCFL_TIMER_H__

#include <memory>
#include <set>
#include <vector>
#include "thread.h"

namespace ancfl {

class TimerManager;
/**
 * @brief 定时�? */
class Timer : public std::enable_shared_from_this<Timer> {
    friend class TimerManager;

   public:
    /// 定时器的智能指针类型
    typedef std::shared_ptr<Timer> ptr;

    /**
     * @brief 取消定时�?     */
    bool cancel();

    /**
     * @brief 刷新设置定时器的执行时间
     */
    bool refresh();

    /**
     * @brief 重置定时器时�?     * @param[in] ms 定时器执行间隔时�?毫秒)
     * @param[in] from_now 是否从当前时间开始计�?     */
    bool reset(uint64_t ms, bool from_now);

   private:
    /**
     * @brief 构造函�?     * @param[in] ms 定时器执行间隔时�?     * @param[in] cb 回调函数
     * @param[in] recurring 是否循环
     * @param[in] manager 定时器管理器
     */
    Timer(uint64_t ms,
          std::function<void()> cb,
          bool recurring,
          TimerManager* manager);
    /**
     * @brief 构造函�?     * @param[in] next 执行的时间戳(毫秒)
     */
    Timer(uint64_t next);

   private:
    /// 是否循环定时�?    bool m_recurring = false;
    /// 执行周期
    uint64_t m_ms = 0;
    /// 精确的执行时�?    uint64_t m_next = 0;
    /// 回调函数
    std::function<void()> m_cb;
    /// 定时器管理器
    TimerManager* m_manager = nullptr;

   private:
    /**
     * @brief 定时器比较仿函数
     */
    struct Comparator {
        /**
         * @brief 比较定时器的智能指针的大�?按执行时间排�?
         * @param[in] lhs 定时器智能指�?         * @param[in] rhs 定时器智能指�?         */
        bool operator()(const Timer::ptr& lhs, const Timer::ptr& rhs) const;
    };
};

/**
 * @brief 定时器管理器
 */
class TimerManager {
    friend class Timer;

   public:
    /// 读写锁类�?    typedef RWMutex RWMutexType;

    /**
     * @brief 构造函�?     */
    TimerManager();

    /**
     * @brief 析构函数
     */
    virtual ~TimerManager();

    /**
     * @brief 添加定时�?     * @param[in] ms 定时器执行间隔时�?     * @param[in] cb 定时器回调函�?     * @param[in] recurring 是否循环定时�?     */
    Timer::ptr addTimer(uint64_t ms,
                        std::function<void()> cb,
                        bool recurring = false);

    /**
     * @brief 添加条件定时�?     * @param[in] ms 定时器执行间隔时�?     * @param[in] cb 定时器回调函�?     * @param[in] weak_cond 条件
     * @param[in] recurring 是否循环
     */
    Timer::ptr addConditionTimer(uint64_t ms,
                                 std::function<void()> cb,
                                 std::weak_ptr<void> weak_cond,
                                 bool recurring = false);

    /**
     * @brief 到最近一个定时器执行的时间间�?毫秒)
     */
    uint64_t getNextTimer();

    /**
     * @brief 获取需要执行的定时器的回调函数列表
     * @param[out] cbs 回调函数数组
     */
    void listExpiredCb(std::vector<std::function<void()> >& cbs);

    /**
     * @brief 是否有定时器
     */
    bool hasTimer();

   protected:
    /**
     * @brief 当有新的定时器插入到定时器的首部,执行该函�?     */
    virtual void onTimerInsertedAtFront() = 0;

    /**
     * @brief 将定时器添加到管理器�?     */
    void addTimer(Timer::ptr val, RWMutexType::WriteLock& lock);

   private:
    /**
     * @brief 检测服务器时间是否被调后了
     */
    bool detectClockRollover(uint64_t now_ms);

   private:
    /// Mutex
    RWMutexType m_mutex;
    /// 定时器集�?    std::set<Timer::ptr, Timer::Comparator> m_timers;
    /// 是否触发onTimerInsertedAtFront
    bool m_tickled = false;
    /// 上次执行时间
    uint64_t m_previouseTime = 0;
};

}  // namespace ancfl

#endif



