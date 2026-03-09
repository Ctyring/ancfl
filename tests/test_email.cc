#include "ancfl/email/email.h"
#include "ancfl/email/smtp.h"

void test() {
    ancfl::EMail::ptr email =
        ancfl::EMail::Create("caotiyuan@163.com", "password", "hello world",
                             "<B>hi </B>hello world", {"173479693@qq.com"});
    ancfl::EMailEntity::ptr entity =
        ancfl::EMailEntity::CreateAttach("ancfl/ancfl.h");
    if (entity) {
        email->addEntity(entity);
    }

    entity = ancfl::EMailEntity::CreateAttach("ancfl/address.cc");
    if (entity) {
        email->addEntity(entity);
    }

    auto client = ancfl::SmtpClient::Create("smtp.163.com", 465, true);
    if (!client) {
        std::cout << "connect smtp.163.com:25 fail" << std::endl;
        return;
    }

    auto result = client->send(email, true);
    std::cout << "result=" << result->result << " msg=" << result->msg
              << std::endl;
    std::cout << client->getDebugInfo() << std::endl;
    // result = client->send(email, true);
    // std::cout << "result=" << result->result << " msg=" << result->msg <<
    // std::endl; std::cout << client->getDebugInfo() << std::endl;
}

int main(int argc, char** argv) {
    ancfl::IOManager iom(1);
    iom.schedule(test);
    iom.stop();
    return 0;
}



