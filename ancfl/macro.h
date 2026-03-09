/**
 * @file macro.h
 * @brief 常用宏的封装
 */
#ifndef __ANCFL_MACRO_H__
#define __ANCFL_MACRO_H__

#include <assert.h>
#include <string.h>
#include "log.h"
#include "util.h"

#if defined __GNUC__ || defined __llvm__
/// LIKCLY 宏的封装, 告诉编译器优�?条件大概率成�?#define ANCFL_LIKELY(x) __builtin_expect(!!(x), 1)
/// LIKCLY 宏的封装, 告诉编译器优�?条件大概率不成立
#define ANCFL_UNLIKELY(x) __builtin_expect(!!(x), 0)
#else
#define ANCFL_LIKELY(x) (x)
#define ANCFL_UNLIKELY(x) (x)
#endif
/// 断言宏封�?#define ANCFL_ASSERT(x)                                  \
    if (ANCFL_UNLIKELY(!(x))) {                          \
        ANCFL_LOG_ERROR(ANCFL_LOG_ROOT())                \
            << "ASSERTION: " #x << "\nbacktrace:\n"      \
            << ancfl::BacktraceToString(100, 2, "    "); \
        assert(x);                                       \
    }
/// 断言宏封�?#define ANCFL_ASSERT2(x, w)                              \
    if (ANCFL_UNLIKELY(!(x))) {                          \
        ANCFL_LOG_ERROR(ANCFL_LOG_ROOT())                \
            << "ASSERTION: " #x << "\n"                  \
            << w << "\nbacktrace:\n"                     \
            << ancfl::BacktraceToString(100, 2, "    "); \
        assert(x);                                       \
    }
#endif



