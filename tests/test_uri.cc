#include <iostream>
#include "ancfl/uri.h"

int main(int argc, char** argv) {
    // ancfl::Uri::ptr uri =
    // ancfl::Uri::Create("http://www.ancfl.top/test/uri?id=100&name=ancfl#frg");
    ancfl::Uri::ptr uri = ancfl::Uri::Create(
        "http://admin@www.ancfl.top/test/中文/"
        "uri?id=100&name=ancfl&vv=中文#frg中文");
    // ancfl::Uri::ptr uri = ancfl::Uri::Create("http://admin@www.ancfl.top");
    // ancfl::Uri::ptr uri =
    // ancfl::Uri::Create("http://www.ancfl.top/test/uri");
    std::cout << uri->toString() << std::endl;
    auto addr = uri->createAddress();
    std::cout << *addr << std::endl;
    return 0;
}



