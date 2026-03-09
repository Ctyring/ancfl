#include "ancfl/ds/array.h"
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
    ancfl::ds::Array<int> tmp;
    std::vector<int> vs;
    for (int i = 0; i < 10000; ++i) {
        int v = rand();
        tmp.insert(v);
        vs.push_back(v);
        ANCFL_ASSERT(tmp.isSorted());
    }

    std::ofstream ofs("./array.data");
    tmp.writeTo(ofs);

    for (auto& i : vs) {
        auto idx = tmp.exists(i);
        ANCFL_ASSERT(idx >= 0);
        tmp.erase(idx);
        ANCFL_ASSERT(tmp.isSorted());
    }
    ANCFL_ASSERT(tmp.size() == 0);
}

void test() {
    for (int i = 0; i < 10000; ++i) {
        ANCFL_LOG_INFO(g_logger) << "i=" << i;
        std::ifstream ifs("./array.data");
        ancfl::ds::Array<int> tmp;
        if (!tmp.readFrom(ifs)) {
            ANCFL_LOG_INFO(g_logger) << "error";
        }
        ANCFL_ASSERT(tmp.isSorted());
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



