#include <stdlib.h>
#include <time.h>
#include "ancfl/application.h"
int main(int argc, char** argv) {
    setenv("TZ", ":/etc/localtime", 1);
    tzset();
    srand(time(0));
    ancfl::Application app;
    if (app.init(argc, argv)) {
        return app.run();
    }
    return 0;
}



