#include <iostream>
#include "ancfl/db/mysql.h"
#include "ancfl/iomanager.h"

void run() {
    do {
        std::map<std::string, std::string> params;
        params["host"] = "127.0.0.1";
        params["user"] = "ancfl";
        params["passwd"] = "blog123";
        params["dbname"] = "blog";

        ancfl::MySQL::ptr mysql(new ancfl::MySQL(params));
        if (!mysql->connect()) {
            std::cout << "connect fail" << std::endl;
            return;
        }

        // auto stmt = mysql_stmt_init(mysql->getRaw());
        // std::string sql = "select * from ancfl where status >= ?";
        // mysql_stmt_prepare(stmt, sql.c_str(), sql.size());
        // MYSQL_BIND b;
        // int a = 0;
        // b.buffer_type = MYSQL_TYPE_LONG;
        // b.buffer = &a;
        // mysql_stmt_bind_param(m_

        ancfl::MySQLStmt::ptr stmt = ancfl::MySQLStmt::Create(
            mysql, "update user set update_time = ? where id = 1");
        stmt->bindString(1, "2018-01-01 10:10:10");
        int rt = stmt->execute();
        std::cout << "rt=" << rt << std::endl;

        // MYSQL_TIME mt;
        // ancfl::time_t_to_mysql_time(time(0), mt);

        // int a = 0;
        ////auto stmt = mysql->prepare("select * from ancfl where status >= ?");
        ////stmt->bind(0, a);
        ////auto res =
        ///std::dynamic_pointer_cast<ancfl::MySQLStmtRes>(stmt->query());

        // auto res = std::dynamic_pointer_cast<ancfl::MySQLStmtRes>
        //     //(mysql->queryStmt("select * from ancfl"));
        //     (mysql->queryStmt("select *, 'hello' as xx from user where status
        //     >= ? and status <= ?"
        //                       , a, a));
        //     //(mysql->queryStmt("select id,name, keyword, creator as aa,
        //     last_update_time from ancfl "
        //     //                  " where last_update_time > ?", (time_t)0));
        ////auto res = std::dynamic_pointer_cast<ancfl::MySQLRes>
        ////    (mysql->query("select * from search_brand"));
        // if(!res) {
        //     std::cout << "invalid" << std::endl;
        //     return;
        // }
        // if(res->getErrno()) {
        //     std::cout << "errno=" << res->getErrno()
        //         << " errstr=" << res->getErrStr() << std::endl;
        //     return;
        // }

        // int i = 0;
        // while(res->next()) {
        //     ++i;
        //     std::cout << res->getInt64(0)
        //         << " - " << res->getInt64(1) << std::endl;
        // }
        // std::cout << "===" << i << std::endl;
    } while (false);
    std::cout << "over" << std::endl;
}

int main(int argc, char** argv) {
    ancfl::IOManager iom(1);
    // iom.schedule(run);
    iom.addTimer(1000, run, true);
    return 0;
}



