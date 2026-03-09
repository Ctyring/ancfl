# ancfl 框架

## 项目简介

ancfl 是一个功能强大的 C++ 网络服务器框架，提供了丰富的网络编程工具和组件，支持多种网络协议和数据库操作，适用于构建高性能的网络应用。

## 主要功能

### 核心功能
- **协程（Fiber）**：轻量级线程实现，提供高效的并发处理能力
- **IO多路复用**：基于事件驱动的IO管理，支持高并发连接
- **定时器**：高精度定时器，支持延迟执行和周期性任务
- **线程池**：可配置的线程池，优化并发性能
- **异步IO**：非阻塞IO操作，提高系统吞吐量

### 网络功能
- **HTTP服务器**：支持HTTP/1.1协议，提供完整的HTTP服务器功能
- **WebSocket**：支持WebSocket协议，实现实时双向通信
- **TCP服务器**：通用TCP服务器框架，支持自定义协议
- **服务发现**：基于Zookeeper的服务注册与发现
- **负载均衡**：内置负载均衡算法，优化服务调用

### 数据库支持
- **MySQL**：完整的MySQL客户端支持
- **SQLite3**：轻量级嵌入式数据库支持
- **Redis**：高性能键值存储支持
- **ORM**：对象关系映射，简化数据库操作

### 工具库
- **配置管理**：基于YAML的配置文件解析
- **日志系统**：可配置的多级日志系统
- **加密工具**：提供常用的加密算法
- **数据结构**：包括LRU缓存、位图等高效数据结构
- **邮件发送**：支持SMTP协议的邮件发送功能
- **JSON处理**：JSON数据的解析与生成

## 技术栈

### 编程语言
- C++11

### 构建系统
- CMake 3.0+

### 核心依赖
- **yaml-cpp**：配置文件解析
- **Protobuf**：数据序列化
- **OpenSSL**：加密功能
- **Zlib**：数据压缩
- **jemalloc**：内存分配优化

### 数据库依赖
- **MySQL客户端库**：MySQL数据库支持
- **SQLite3**：嵌入式数据库支持
- **hiredis_vip**：Redis客户端支持

### 服务发现
- **Zookeeper**：分布式服务协调

### 网络库
- **libevent**：事件处理库

## 项目结构

```
ancfl/
├── ancfl/           # 核心库代码
│   ├── db/          # 数据库相关代码
│   ├── ds/          # 数据结构
│   ├── email/       # 邮件功能
│   ├── http/        # HTTP和WebSocket实现
│   ├── ns/          # 名称服务
│   ├── orm/         # 对象关系映射
│   ├── rock/        # Rock协议
│   ├── streams/     # 流处理
│   ├── util/        # 工具函数
├── bin/             # 可执行文件和配置
├── cmake/           # CMake配置
├── examples/        # 示例代码
├── samples/         # 示例应用
├── tests/           # 测试代码
├── template/        # 模板代码
```

## 快速开始

### 构建项目

```bash
# 克隆项目
git clone <repository-url>
cd ancfl

# 配置并构建
mkdir build && cd build
cmake ..
make

# 运行测试（可选）
make test
```

### 示例应用

查看 `examples/` 和 `samples/` 目录下的示例代码，了解如何使用框架。

#### HTTP服务器示例

```cpp
#include "ancfl/http/http_server.h"
#include "ancfl/log.h"

ancfl::Logger::ptr g_logger = ANCFL_LOG_ROOT();
ancfl::IOManager::ptr worker;

void run() {
    g_logger->setLevel(ancfl::LogLevel::INFO);
    ancfl::Address::ptr addr = 
        ancfl::Address::LookupAnyIPAddress("0.0.0.0:8020");
    if (!addr) {
        ANCFL_LOG_ERROR(g_logger) << "get address error";
        return;
    }

    ancfl::http::HttpServer::ptr http_server(
        new ancfl::http::HttpServer(true, worker.get()));
    while (!http_server->bind(addr)) {
        ANCFL_LOG_ERROR(g_logger) << "bind " << *addr << " fail";
        sleep(1);
    }

    http_server->start();
}

int main(int argc, char** argv) {
    ancfl::IOManager iom(1);
    worker.reset(new ancfl::IOManager(4, false));
    iom.schedule(run);
    return 0;
}
```

#### Echo服务器示例

查看 `examples/echo_server.cc` 了解如何创建一个简单的Echo服务器。

## 配置文件

配置文件位于 `bin/conf/` 目录，使用YAML格式：

- `server.yml`：服务器配置
- `log.yml`：日志配置
- `system.yml`：系统配置
- `worker.yml`：工作进程配置