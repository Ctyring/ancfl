/**
 * @file fiber.h
 * @brief 协程封装
 */
#ifndef __ANCFL_FIBER_H__
#define __ANCFL_FIBER_H__

#include <ucontext.h>
#include <functional>
#include <memory>

namespace ancfl {

class Scheduler;

/**
 * @brief 协程�? */
class Fiber : public std::enable_shared_from_this<Fiber> {
    friend class Scheduler;

   public:
    typedef std::shared_ptr<Fiber> ptr;

    /**
     * @brief 协程状�?     */
    enum State {
        /// 初始化状�?        INIT,
        /// 暂停状�?        HOLD,
        /// 执行中状�?        EXEC,
        /// 结束状�?        TERM,
        /// 可执行状�?        READY,
        /// 异常状�?        EXCEPT
    };

   private:
    /**
     * @brief 无参构造函�?     * @attention 每个线程第一个协程的构�?     */
    Fiber();

   public:
    /**
     * @brief 构造函�?     * @param[in] cb 协程执行的函�?     * @param[in] stacksize 协程栈大�?     * @param[in] use_caller 是否在MainFiber上调�?     */
    Fiber(std::function<void()> cb,
          size_t stacksize = 0,
          bool use_caller = false);

    /**
     * @brief 析构函数
     */
    ~Fiber();

    /**
     * @brief 重置协程执行函数,并设置状�?     * @pre getState() �?INIT, TERM, EXCEPT
     * @post getState() = INIT
     */
    void reset(std::function<void()> cb);

    /**
     * @brief 将当前协程切换到运行状�?     * @pre getState() != EXEC
     * @post getState() = EXEC
     */
    void swapIn();

    /**
     * @brief 将当前协程切换到后台
     */
    void swapOut();

    /**
     * @brief 将当前线程切换到执行状�?     * @pre 执行的为当前线程的主协程
     */
    void call();

    /**
     * @brief 将当前线程切换到后台
     * @pre 执行的为该协�?     * @post 返回到线程的主协�?     */
    void back();

    /**
     * @brief 返回协程id
     */
    uint64_t getId() const { return m_id; }

    /**
     * @brief 返回协程状�?     */
    State getState() const { return m_state; }

   public:
    /**
     * @brief 设置当前线程的运行协�?     * @param[in] f 运行协程
     */
    static void SetThis(Fiber* f);

    /**
     * @brief 返回当前所在的协程
     */
    static Fiber::ptr GetThis();

    /**
     * @brief 将当前协程切换到后台,并设置为READY状�?     * @post getState() = READY
     */
    static void YieldToReady();

    /**
     * @brief 将当前协程切换到后台,并设置为HOLD状�?     * @post getState() = HOLD
     */
    static void YieldToHold();

    /**
     * @brief 返回当前协程的总数�?     */
    static uint64_t TotalFibers();

    /**
     * @brief 协程执行函数
     * @post 执行完成返回到线程主协程
     */
    static void MainFunc();

    /**
     * @brief 协程执行函数
     * @post 执行完成返回到线程调度协�?     */
    static void CallerMainFunc();

    /**
     * @brief 获取当前协程的id
     */
    static uint64_t GetFiberId();

   private:
    /// 协程id
    uint64_t m_id = 0;
    /// 协程运行栈大�?    uint32_t m_stacksize = 0;
    /// 协程状�?    State m_state = INIT;
    /// 协程上下�?    ucontext_t m_ctx;
    /// 协程运行栈指�?    void* m_stack = nullptr;
    /// 协程运行函数
    std::function<void()> m_cb;
};

}  // namespace ancfl

#endif



