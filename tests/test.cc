#include <iostream>
#include "ancfl/log.h"
#include "ancfl/util.h"

int main(int argc, char const* argv[]) {
    ancfl::Logger::ptr logger(new ancfl::Logger);
    logger->addAppender(ancfl::LogAppender::ptr(new ancfl::StdoutLogAppender));

    ancfl::FileLogAppender::ptr file_appender(
        new ancfl::FileLogAppender("./log.txt"));
    ancfl::LogFormatter::ptr fmt(new ancfl::LogFormatter("%d%T%p%T%m%n"));
    file_appender->setFormatter(fmt);
    file_appender->setLevel(ancfl::LogLevel::ERROR);
    // logger->addAppender(file_appender);

    ancfl::TimeSlicingFileLogAppender::ptr ts_file_appender(
        new ancfl::TimeSlicingFileLogAppender(".", "test", ".log", 1));
    logger->addAppender(ts_file_appender);
    // ancfl::LogEvent::ptr event(new ancfl::LogEvent(__FILE__, __LINE__, 0,
    // ancfl::GetThreadId(), ancfl::GetFiberId(), 2, time(0)));
    // logger->log(ancfl::LogLevel::DEBUG, event);
    for (int i = 0; i < 10; i++) {
        ANCFL_LOG_INFO(logger) << "test macro";
        ANCFL_LOG_FMT_ERROR(logger, "test macro fmt error %s", "aa");
        sleep(10);
    }

    // auto l = ancfl::LoggerMgr::GetInstance()->getLogger("xx");
    // ANCFL_LOG_INFO(l) << "xxx";
    return 0;
}



