#include <assert.h>
#include <iostream>
#include "ancfl/ancfl.h"

ancfl::Logger::ptr g_logger = ANCFL_LOG_ROOT();

void test_assert() {
    ANCFL_LOG_INFO(g_logger) << ancfl::BacktraceToString(10);
    // ANCFL_ASSERT2(0 == 1, "abcdef xx");
}

int main(int argc, char** argv) {
    test_assert();

    int arr[] = {1, 3, 5, 7, 9, 11};

    ANCFL_LOG_INFO(g_logger)
        << ancfl::BinarySearch(arr, sizeof(arr) / sizeof(arr[0]), 0);
    ANCFL_LOG_INFO(g_logger)
        << ancfl::BinarySearch(arr, sizeof(arr) / sizeof(arr[0]), 1);
    ANCFL_LOG_INFO(g_logger)
        << ancfl::BinarySearch(arr, sizeof(arr) / sizeof(arr[0]), 4);
    ANCFL_LOG_INFO(g_logger)
        << ancfl::BinarySearch(arr, sizeof(arr) / sizeof(arr[0]), 13);
    ANCFL_ASSERT(ancfl::BinarySearch(arr, sizeof(arr) / sizeof(arr[0]), 0) ==
                 -1);
    ANCFL_ASSERT(ancfl::BinarySearch(arr, sizeof(arr) / sizeof(arr[0]), 1) ==
                 0);
    ANCFL_ASSERT(ancfl::BinarySearch(arr, sizeof(arr) / sizeof(arr[0]), 2) ==
                 -2);
    ANCFL_ASSERT(ancfl::BinarySearch(arr, sizeof(arr) / sizeof(arr[0]), 3) ==
                 1);
    ANCFL_ASSERT(ancfl::BinarySearch(arr, sizeof(arr) / sizeof(arr[0]), 4) ==
                 -3);
    ANCFL_ASSERT(ancfl::BinarySearch(arr, sizeof(arr) / sizeof(arr[0]), 5) ==
                 2);
    ANCFL_ASSERT(ancfl::BinarySearch(arr, sizeof(arr) / sizeof(arr[0]), 6) ==
                 -4);
    ANCFL_ASSERT(ancfl::BinarySearch(arr, sizeof(arr) / sizeof(arr[0]), 7) ==
                 3);
    ANCFL_ASSERT(ancfl::BinarySearch(arr, sizeof(arr) / sizeof(arr[0]), 8) ==
                 -5);
    ANCFL_ASSERT(ancfl::BinarySearch(arr, sizeof(arr) / sizeof(arr[0]), 9) ==
                 4);
    ANCFL_ASSERT(ancfl::BinarySearch(arr, sizeof(arr) / sizeof(arr[0]), 10) ==
                 -6);
    ANCFL_ASSERT(ancfl::BinarySearch(arr, sizeof(arr) / sizeof(arr[0]), 11) ==
                 5);
    ANCFL_ASSERT(ancfl::BinarySearch(arr, sizeof(arr) / sizeof(arr[0]), 12) ==
                 -7);
    return 0;
}



