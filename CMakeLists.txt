cmake_miniMum_required(VERSION 3.0)

project(ancfl)
set(CMAKE_MODULE_PATH ${CMAKE_MODULE_PATH} ${CMAKE_CURRENT_SOURCE_DIR}/cmake)
include (cmake/utils.cmake)
set(CMAKE_VERBOSE_MAKEFILE ON)

# 指定编译选项
# -rdynamic 将所有符号加入符号表，便于使用dlopen或者backtrace追踪到符�?# -Werror 不区分警告和错误，遇到任何警告都停止编译
# -Wall 开启大部分警告提示
# -Wno-unused-funtion 不要警告未使用函�?# -Wno-deprecated 不要警告过时特�?set(CMAKE_CXX_FLAGS "$ENV{CXXFLAGS} -rdynamic -O2 -fPIC -ggdb -std=c++11 -Wall -Wno-deprecated -Werror -Wno-unused-function -Wno-builtin-macro-redefined -Wno-deprecated-declarations")
set(CMAKE_C_FLAGS "$ENV{CXXFLAGS} -rdynamic -O2 -fPIC -ggdb -std=c11 -Wall -Wno-deprecated -Werror -Wno-unused-function -Wno-builtin-macro-redefined -Wno-deprecated-declarations")

include_directories(.)
include_directories(/yaml-cpp/include)
include_directories(/usr/local/include)
link_directories(/yaml-cpp/lib)
link_directories(/root/cty/ancfl/include)

option(TEST "ON for complile test" OFF)

message("***", ${YAMLCPP})

find_package(Protobuf)
if(Protobuf_FOUND)
include_directories(${Protobuf_INCLUDE_DIRS})
endif()

find_package(OpenSSL REQUIRED)
if(OPENSSL_FOUND)
    include_directories(${OPENSSL_INCLUDE_DIR})
endif()

find_package(MySQL REQUIRED)
if(MYSQL_FOUND)
    include_directories(${MYSQL_INCLUDE_DIR})
endif()

find_package(ZLIB REQUIRED)

if(ZLIB_FOUND)
    include_directories(${ZLIB_INCLUDE_DIR})
endif()

set(LIB_SRC 
	ancfl/config.cc
	ancfl/fiber.cc
	ancfl/hook.cc
	ancfl/fd_manager.cc
	ancfl/iomanager.cc
	ancfl/log.cc
	ancfl/scheduler.cc
	ancfl/timer.cc
	ancfl/thread.cc
	ancfl/util.cc
	ancfl/address.cc
	ancfl/socket.cc
	ancfl/bytearray.cc
	ancfl/http/http.cc
	ancfl/http/http_parser.cc
    ancfl/http/http11_parser.rl.cc
    ancfl/http/httpclient_parser.rl.cc
	ancfl/tcp_server.cc
	ancfl/streams/socket_stream.cc
    ancfl/stream.cc
	ancfl/http/http_session.cc
	ancfl/http/http_server.cc
	ancfl/http/servlet.cc
	ancfl/http/http_connection.cc
	ancfl/daemon.cc
	ancfl/env.cc
	ancfl/http/ws_connection.cc
    ancfl/http/ws_session.cc
    ancfl/http/ws_server.cc
    ancfl/http/ws_servlet.cc
	ancfl/util/hash_util.cc
	ancfl/db/redis.cc
	ancfl/application.cc
	ancfl/util/time.cc
	ancfl/worker.cc
	ancfl/mutex.cc
	ancfl/module.cc
	ancfl/library.cc
	ancfl/util/json_util.cc
	ancfl/streams/zlib_stream.cc
	ancfl/streams/async_socket_stream.cc
	ancfl/protocol.cc
    ancfl/rock/rock_protocol.cc
	ancfl/util/crypto_util.cc
	ancfl/rock/rock_server.cc
	ancfl/db/sqlite3.cc
	ancfl/streams/load_balance.cc
	ancfl/rock/rock_stream.cc
	ancfl/email/email.cc
	ancfl/email/smtp.cc
	ancfl/db/mysql.cc
	ancfl/http/session_data.cc
	ancfl/http/servlets/config_servlet.cc
    ancfl/http/servlets/status_servlet.cc
	ancfl/ns/name_server_module.cc
    ancfl/ns/ns_client.cc
    ancfl/ns/ns_protocol.cc
	ancfl/ds/bitmap.cc
	ancfl/zk_client.cc
	ancfl/streams/service_discovery.cc
	ancfl/db/fox_thread.cc
	ancfl/ds/roaring_bitmap.cc
    ancfl/ds/roaring.c
	ancfl/ds/util.cc
	)

ragelmaker(ancfl/http/http11_parser.rl LIB_SRC ${CMAKE_CURRENT_SOURCE_DIR}/ancfl/http)
ragelmaker(ancfl/http/httpclient_parser.rl LIB_SRC ${CMAKE_CURRENT_SOURCE_DIR}/ancfl/http)
ragelmaker(ancfl/uri.rl LIB_SRC ${CMAKE_CURRENT_SOURCE_DIR}/ancfl)

protobufmaker(ancfl/ns/ns_protobuf.proto LIB_SRC ${CMAKE_CURRENT_SOURCE_DIR})
# protobufmaker(ancfl/test.proto LIB_SRC ${CMAKE_CURRENT_SOURCE_DIR})

add_library(ancfl SHARED ${LIB_SRC})
force_redefine_file_macro_for_sources(ancfl)

find_library(YAMLCPP yaml-cpp)
find_library(PTHREAD pthread)

set(LIBS
        ancfl
		dl
        pthread
        yaml-cpp
		${PROTOBUF_LIBRARIES}
		${OPENSSL_LIBRARIES}
		libjsoncpp_static.a
		${ZLIB_LIBRARIES}
		sqlite3
		tinyxml2
		mysqlclient
		mysqlclient_r
		zookeeper_mt
		event
        hiredis_vip
		jemalloc
		)

message("***", ${LIBS})
if(TEST)
ancfl_add_executable(test1 "tests/test.cc" ancfl "${LIBS}")
ancfl_add_executable(test_config "tests/test_config.cc" ancfl "${LIBS}")
ancfl_add_executable(test_thread "tests/test_thread.cc" ancfl "${LIBS}")
ancfl_add_executable(test_util "tests/test_util.cc" ancfl "${LIBS}")
ancfl_add_executable(test_hashmultimap "tests/test_hashmultimap.cc" ancfl "${LIBS}")
ancfl_add_executable(test_hashmap "tests/test_hashmap.cc" ancfl "${LIBS}")
ancfl_add_executable(test_dict "tests/test_dict.cc" ancfl "${LIBS}")
ancfl_add_executable(test_array "tests/test_array.cc" ancfl "${LIBS}")
ancfl_add_executable(test_fiber "tests/test_fiber.cc" ancfl "${LIBS}")
ancfl_add_executable(test_scheduler "tests/test_scheduler.cc" ancfl "${LIBS}")
ancfl_add_executable(test_iomanager "tests/test_iomanager.cc" ancfl "${LIBS}")
ancfl_add_executable(test_hook "tests/test_hook.cc" ancfl "${LIBS}")
ancfl_add_executable(test_address "tests/test_address.cc" ancfl "${LIBS}")
ancfl_add_executable(test_socket "tests/test_socket.cc" ancfl "${LIBS}")
ancfl_add_executable(test_bytearray "tests/test_bytearray.cc" ancfl "${LIBS}")

ancfl_add_executable(test_http "tests/test_http.cc" ancfl "${LIBS}")
ancfl_add_executable(test_http_parser "tests/test_http_parser.cc" ancfl "${LIBS}")
ancfl_add_executable(test_tcp_server "tests/test_tcp_server.cc" ancfl "${LIBS}")
ancfl_add_executable(echo_server "examples/echo_server.cc" ancfl "${LIBS}")
ancfl_add_executable(test_http_server "tests/test_http_server.cc" ancfl "${LIBS}")
# ancfl_add_executable(test_http_connection "tests/test_http_connection.cc" ancfl "${LIBS}")
ancfl_add_executable(test_uri "tests/test_uri.cc" ancfl "${LIBS}")
ancfl_add_executable(my_http_server "samples/my_http_server.cc" ancfl "${LIBS}")
ancfl_add_executable(test_daemon "tests/test_daemon.cc" ancfl "${LIBS}")
ancfl_add_executable(test_env "tests/test_env.cc" ancfl "${LIBS}")
ancfl_add_executable(test_ws_server "tests/test_ws_server.cc" ancfl "${LIBS}")
ancfl_add_executable(test_ws_client "tests/test_ws_client.cc" ancfl "${LIBS}")
ancfl_add_executable(test_application "tests/test_application.cc" ancfl "${LIBS}")

ancfl_add_executable(test_http_connection "tests/test_http_connection.cc" ancfl "${LIBS}")
ancfl_add_executable(test_lru "tests/test_lru.cc" ancfl "${LIBS}")
ancfl_add_executable(test_timed_cache "tests/test_timed_cache.cc" ancfl "${LIBS}")
ancfl_add_executable(test_timed_lru_cache "tests/test_timed_lru_cache.cc" ancfl "${LIBS}")
ancfl_add_executable(test_zlib_stream "tests/test_zlib_stream.cc" ancfl "${LIBS}")

ancfl_add_executable(test_crypto "tests/test_crypto.cc" ancfl "${LIBS}")

ancfl_add_executable(test_sqlite3 "tests/test_sqlite3.cc" ancfl "${LIBS}")
ancfl_add_executable(test_rock "tests/test_rock.cc" ancfl "${LIBS}")
ancfl_add_executable(test_email "tests/test_email.cc" ancfl "${LIBS}")
ancfl_add_executable(test_mysql "tests/test_mysql.cc" ancfl "${LIBS}")

set(ORM_SRCS
    ancfl/orm/table.cc
    ancfl/orm/column.cc
    ancfl/orm/index.cc
    ancfl/orm/orm.cc
    ancfl/orm/util.cc
    )
ancfl_add_executable(orm "${ORM_SRCS}" ancfl "${LIBS}")

add_library(test_module SHARED tests/test_module.cc)

ancfl_add_executable(bin_ancfl "ancfl/main.cc" ancfl "${LIBS}")
set_target_properties(bin_ancfl PROPERTIES OUTPUT_NAME "ancfl")

add_subdirectory(${CMAKE_CURRENT_SOURCE_DIR}/orm_out)
set(OLIBS ${LIBS})
set(OLIBS ${OLIBS} orm_data)
ancfl_add_executable(test_orm "tests/test_orm.cc" orm_data "${OLIBS}")

ancfl_add_executable(test_nameserver "tests/test_nameserver.cc" ancfl "${LIBS}")
ancfl_add_executable(test_bitmap "tests/test_bitmap.cc" ancfl "${LIBS}")
endif()
ancfl_add_executable(test_zookeeper "tests/test_zookeeper.cc" ancfl "${LIBS}")
ancfl_add_executable(test_service_discovery "tests/test_service_discovery.cc" ancfl "${LIBS}")

SET(EXECUTABLE_OUTPUT_PATH ${PROJECT_SOURCE_DIR}/bin)
SET(LIBRARY_OUTPUT_PATH ${PROJECT_SOURCE_DIR}/lib)



