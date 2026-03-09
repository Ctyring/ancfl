#include "ancfl/application.h"

int main(int argc, char** argv) {
    ancfl::Application app;
    if (app.init(argc, argv)) {
        return app.run();
    }
    return 0;
}



