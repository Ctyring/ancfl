#include "ancfl/ds/dict.h"
#include "ancfl/ancfl.h"

static ancfl::Logger::ptr g_logger = ANCFL_LOG_ROOT();

struct PidVid {
    PidVid(uint32_t p = 0, uint32_t v = 0) : pid(p), vid(v) {}
    uint32_t pid;
    uint32_t vid;

    bool operator<(const PidVid& o) const {
        return memcmp(this, &o, sizeof(o)) < 0;
    }
};

void gen() {
    ancfl::ds::Dict<int, PidVid> tmp;
    for (int i = 0; i < 500000; ++i) {
        int32_t len = rand() % 10 + 5;
        int k = rand();
        std::vector<PidVid> pvs;
        for (int n = 0; n < len; ++n) {
            pvs.push_back(PidVid(rand(), rand()));
        }
        tmp.insert(k, pvs.data(), pvs.size());
    }

    std::ofstream ofs("./dict.data");
    tmp.writeTo(ofs);
}

void test() {
    for (int i = 0; i < 10000; ++i) {
        ANCFL_LOG_INFO(g_logger) << "i=" << i;
        std::ifstream ifs("./dict.data");
        ancfl::ds::Dict<int, PidVid> tmp;
        if (!tmp.readFrom(ifs)) {
            ANCFL_LOG_INFO(g_logger) << "error";
        }
        if (i % 100 == 0) {
            ANCFL_LOG_INFO(g_logger) << "over..." << (i + 1);
        }
    }
}

int main(int argc, char** argv) {
    gen();
    test();
    return 0;
}



