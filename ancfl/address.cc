#include "address.h"
#include <ifaddrs.h>
#include <netdb.h>
#include <stddef.h>
#include <sstream>
#include "log.h"

#include "endian.h"

namespace ancfl {

static ancfl::Logger::ptr g_logger = ANCFL_LOG_NAME("system");

template <class T>
static T CreateMask(uint32_t bits) {
    return (1 << (sizeof(T) * 8 - bits)) - 1;
}

template <class T>
static uint32_t CountBytes(T value) {
    uint32_t result = 0;
    for (; value; ++result) {
        value &= value - 1;
    }
    return result;
}

Address::ptr Address::LookupAny(const std::string& host,
                                int family,
                                int type,
                                int protocol) {
    std::vector<Address::ptr> result;
    if (Lookup(result, host, family, type, protocol)) {
        return result[0];
    }
    return nullptr;
}

IPAddress::ptr Address::LookupAnyIPAddress(const std::string& host,
                                           int family,
                                           int type,
                                           int protocol) {
    std::vector<Address::ptr> result;
    if (Lookup(result, host, family, type, protocol)) {
        // for(auto& i : result) {
        //     std::cout << i->toString() << std::endl;
        // }
        for (auto& i : result) {
            IPAddress::ptr v = std::dynamic_pointer_cast<IPAddress>(i);
            if (v) {
                return v;
            }
        }
    }
    return nullptr;
}

/**
 * @brief 根据主机名和服务名查找网络地址
 *
 * @param result 输出参数，存储查找结果的地址列表
 * @param host 主机名或IP地址字符串，可以包含端口号
 * @param family 地址族，如AF_INET(IPv4)、AF_INET6(IPv6)、AF_UNSPEC(任意)
 * @param type 套接字类型，如SOCK_STREAM(TCP)、SOCK_DGRAM(UDP)
 * @param protocol 协议类型，如IPPROTO_TCP、IPPROTO_UDP，0表示自动选择
 * @return bool 是否成功找到地址
 */
bool Address::Lookup(std::vector<Address::ptr>& result,
                     const std::string& host,
                     int family,
                     int type,
                     int protocol) {
    // 初始化addrinfo结构体，用于指定查找条件
    addrinfo hints, *results, *next;
    hints.ai_flags = 0;            // 无特殊标志
    hints.ai_family = family;      // 地址族
    hints.ai_socktype = type;      // 套接字类型
    hints.ai_protocol = protocol;  // 协议类型
    hints.ai_addrlen = 0;          // 地址长度，由getaddrinfo填充
    hints.ai_canonname = NULL;     // 规范主机名，由getaddrinfo填充
    hints.ai_addr = NULL;          // 地址指针，由getaddrinfo填充
    hints.ai_next = NULL;          // 下一个地址，由getaddrinfo填充

    std::string node;            // 存储主机名或IP地址
    const char* service = NULL;  // 存储服务名或端口号

    // 处理IPv6地址格式，如[2001:db8::1]:8080
    if (!host.empty() && host[0] == '[') {
        // 查找IPv6地址的结束符']'
        const char* endipv6 =
            (const char*)memchr(host.c_str() + 1, ']', host.size() - 1);
        if (endipv6) {
            // 检查是否包含端口号
            if (*(endipv6 + 1) == ':') {
                service = endipv6 + 2;  // 端口号部分
            }
            // 提取IPv6地址部分（去掉方括号）
            node = host.substr(1, endipv6 - host.c_str() - 1);
        }
    }

    // 处理IPv4地址或主机名格式，如192.168.1.1:8080或example.com:80
    if (node.empty()) {
        // 查找端口号分隔符':'
        service = (const char*)memchr(host.c_str(), ':', host.size());
        if (service) {
            // 确保只有一个':'，避免将IPv6地址误解析为IPv4
            if (!memchr(service + 1, ':',
                        host.c_str() + host.size() - service - 1)) {
                // 提取主机名或IPv4地址部分
                node = host.substr(0, service - host.c_str());
                ++service;  // 跳过':'，指向端口号
            }
        }
    }

    // 如果node为空，说明整个host都是主机名或IP地址（没有端口号）
    if (node.empty()) {
        node = host;
    }

    // 调用getaddrinfo进行地址解析
    int error = getaddrinfo(node.c_str(), service, &hints, &results);
    if (error) {
        // 解析失败，记录错误信息
        ANCFL_LOG_DEBUG(g_logger)
            << "Address::Lookup getaddress(" << host << ", " << family << ", "
            << type << ") err=" << error << " errstr=" << gai_strerror(error);
        return false;
    }

    // 遍历解析结果，创建Address对象并添加到结果列表
    next = results;
    while (next) {
        result.push_back(Create(next->ai_addr, (socklen_t)next->ai_addrlen));
        next = next->ai_next;
    }

    // 释放getaddrinfo分配的内存
    freeaddrinfo(results);

    // 返回是否找到有效地址
    return !result.empty();
}

bool Address::GetInterfaceAddresses(
    std::multimap<std::string, std::pair<Address::ptr, uint32_t> >& result,
    int family) {
    struct ifaddrs *next, *results;
    // 获取所有的接口地址
    if (getifaddrs(&results) != 0) {
        ANCFL_LOG_DEBUG(g_logger)
            << "Address::GetInterfaceAddresses getifaddrs "
               " err="
            << errno << " errstr=" << strerror(errno);
        return false;
    }

    try {
        for (next = results; next; next = next->ifa_next) {
            Address::ptr addr;
            uint32_t prefix_len = ~0u;
            if (family != AF_UNSPEC && family != next->ifa_addr->sa_family) {
                continue;
            }
            switch (next->ifa_addr->sa_family) {
                case AF_INET: {
                    addr = Create(next->ifa_addr, sizeof(sockaddr_in));
                    uint32_t netmask =
                        ((sockaddr_in*)next->ifa_netmask)->sin_addr.s_addr;
                    prefix_len = CountBytes(netmask);
                } break;
                case AF_INET6: {
                    addr = Create(next->ifa_addr, sizeof(sockaddr_in6));
                    in6_addr& netmask =
                        ((sockaddr_in6*)next->ifa_netmask)->sin6_addr;
                    prefix_len = 0;
                    for (int i = 0; i < 16; ++i) {
                        prefix_len += CountBytes(netmask.s6_addr[i]);
                    }
                } break;
                default:
                    break;
            }

            if (addr) {
                result.insert(std::make_pair(next->ifa_name,
                                             std::make_pair(addr, prefix_len)));
            }
        }
    } catch (...) {
        ANCFL_LOG_ERROR(g_logger) << "Address::GetInterfaceAddresses exception";
        freeifaddrs(results);
        return false;
    }
    freeifaddrs(results);
    return !result.empty();
}

bool Address::GetInterfaceAddresses(
    std::vector<std::pair<Address::ptr, uint32_t> >& result,
    const std::string& iface,
    int family) {
    if (iface.empty() || iface == "*") {
        if (family == AF_INET || family == AF_UNSPEC) {
            result.push_back(
                std::make_pair(Address::ptr(new IPv4Address()), 0u));
        }
        if (family == AF_INET6 || family == AF_UNSPEC) {
            result.push_back(
                std::make_pair(Address::ptr(new IPv6Address()), 0u));
        }
        return true;
    }

    std::multimap<std::string, std::pair<Address::ptr, uint32_t> > results;

    if (!GetInterfaceAddresses(results, family)) {
        return false;
    }

    auto its = results.equal_range(iface);
    for (; its.first != its.second; ++its.first) {
        result.push_back(its.first->second);
    }
    return !result.empty();
}

int Address::getFamily() const {
    return getAddr()->sa_family;
}

std::string Address::toString() const {
    std::stringstream ss;
    insert(ss);
    return ss.str();
}

Address::ptr Address::Create(const sockaddr* addr, socklen_t addrlen) {
    if (addr == nullptr) {
        return nullptr;
    }

    Address::ptr result;
    switch (addr->sa_family) {
        case AF_INET:
            result.reset(new IPv4Address(*(const sockaddr_in*)addr));
            break;
        case AF_INET6:
            result.reset(new IPv6Address(*(const sockaddr_in6*)addr));
            break;
        default:
            result.reset(new UnknownAddress(*addr));
            break;
    }
    return result;
}

bool Address::operator<(const Address& rhs) const {
    socklen_t minlen = std::min(getAddrLen(), rhs.getAddrLen());
    int result = memcmp(getAddr(), rhs.getAddr(), minlen);
    if (result < 0) {
        return true;
    } else if (result > 0) {
        return false;
    } else if (getAddrLen() < rhs.getAddrLen()) {
        return true;
    }
    return false;
}

bool Address::operator==(const Address& rhs) const {
    return getAddrLen() == rhs.getAddrLen() &&
           memcmp(getAddr(), rhs.getAddr(), getAddrLen()) == 0;
}

bool Address::operator!=(const Address& rhs) const {
    return !(*this == rhs);
}

IPAddress::ptr IPAddress::Create(const char* address, uint16_t port) {
    addrinfo hints, *results;
    memset(&hints, 0, sizeof(addrinfo));

    hints.ai_flags = AI_NUMERICHOST;
    hints.ai_family = AF_UNSPEC;

    int error = getaddrinfo(address, NULL, &hints, &results);
    if (error) {
        ANCFL_LOG_DEBUG(g_logger)
            << "IPAddress::Create(" << address << ", " << port
            << ") error=" << error << " errno=" << errno
            << " errstr=" << strerror(errno);
        return nullptr;
    }

    try {
        IPAddress::ptr result = std::dynamic_pointer_cast<IPAddress>(
            Address::Create(results->ai_addr, (socklen_t)results->ai_addrlen));
        if (result) {
            result->setPort(port);
        }
        freeaddrinfo(results);
        return result;
    } catch (...) {
        freeaddrinfo(results);
        return nullptr;
    }
}

IPv4Address::ptr IPv4Address::Create(const char* address, uint16_t port) {
    IPv4Address::ptr rt(new IPv4Address);
    rt->m_addr.sin_port = byteswapOnLittleEndian(port);
    // inet_pton的作用是将一个点分十进制的IP地址转换成一个32位的网络字节序的二进制数
    int result = inet_pton(AF_INET, address, &rt->m_addr.sin_addr);
    if (result <= 0) {
        ANCFL_LOG_DEBUG(g_logger)
            << "IPv4Address::Create(" << address << ", " << port
            << ") rt=" << result << " errno=" << errno
            << " errstr=" << strerror(errno);
        return nullptr;
    }
    return rt;
}

IPv4Address::IPv4Address(const sockaddr_in& address) {
    m_addr = address;
}

IPv4Address::IPv4Address(uint32_t address, uint16_t port) {
    memset(&m_addr, 0, sizeof(m_addr));
    m_addr.sin_family = AF_INET;
    m_addr.sin_port = byteswapOnLittleEndian(port);
    m_addr.sin_addr.s_addr = byteswapOnLittleEndian(address);
}

sockaddr* IPv4Address::getAddr() {
    return (sockaddr*)&m_addr;
}

const sockaddr* IPv4Address::getAddr() const {
    return (sockaddr*)&m_addr;
}

socklen_t IPv4Address::getAddrLen() const {
    return sizeof(m_addr);
}

std::ostream& IPv4Address::insert(std::ostream& os) const {
    uint32_t addr = byteswapOnLittleEndian(m_addr.sin_addr.s_addr);
    os << ((addr >> 24) & 0xff) << "." << ((addr >> 16) & 0xff) << "."
       << ((addr >> 8) & 0xff) << "." << (addr & 0xff);
    os << ":" << byteswapOnLittleEndian(m_addr.sin_port);
    return os;
}

IPAddress::ptr IPv4Address::broadcastAddress(uint32_t prefix_len) {
    if (prefix_len > 32) {
        return nullptr;
    }

    sockaddr_in baddr(m_addr);
    baddr.sin_addr.s_addr |=
        byteswapOnLittleEndian(CreateMask<uint32_t>(prefix_len));
    return IPv4Address::ptr(new IPv4Address(baddr));
}

IPAddress::ptr IPv4Address::networkAddress(uint32_t prefix_len) {
    if (prefix_len > 32) {
        return nullptr;
    }

    sockaddr_in baddr(m_addr);
    baddr.sin_addr.s_addr &=
        byteswapOnLittleEndian(CreateMask<uint32_t>(prefix_len));
    return IPv4Address::ptr(new IPv4Address(baddr));
}

IPAddress::ptr IPv4Address::subnetMask(uint32_t prefix_len) {
    sockaddr_in subnet;
    memset(&subnet, 0, sizeof(subnet));
    subnet.sin_family = AF_INET;
    subnet.sin_addr.s_addr =
        ~byteswapOnLittleEndian(CreateMask<uint32_t>(prefix_len));
    return IPv4Address::ptr(new IPv4Address(subnet));
}

uint32_t IPv4Address::getPort() const {
    return byteswapOnLittleEndian(m_addr.sin_port);
}

void IPv4Address::setPort(uint16_t v) {
    m_addr.sin_port = byteswapOnLittleEndian(v);
}

IPv6Address::ptr IPv6Address::Create(const char* address, uint16_t port) {
    IPv6Address::ptr rt(new IPv6Address);
    rt->m_addr.sin6_port = byteswapOnLittleEndian(port);
    int result = inet_pton(AF_INET6, address, &rt->m_addr.sin6_addr);
    if (result <= 0) {
        ANCFL_LOG_DEBUG(g_logger)
            << "IPv6Address::Create(" << address << ", " << port
            << ") rt=" << result << " errno=" << errno
            << " errstr=" << strerror(errno);
        return nullptr;
    }
    return rt;
}

IPv6Address::IPv6Address() {
    memset(&m_addr, 0, sizeof(m_addr));
    m_addr.sin6_family = AF_INET6;
}

IPv6Address::IPv6Address(const sockaddr_in6& address) {
    m_addr = address;
}

IPv6Address::IPv6Address(const uint8_t address[16], uint16_t port) {
    memset(&m_addr, 0, sizeof(m_addr));
    m_addr.sin6_family = AF_INET6;
    m_addr.sin6_port = byteswapOnLittleEndian(port);
    memcpy(&m_addr.sin6_addr.s6_addr, address, 16);
}

sockaddr* IPv6Address::getAddr() {
    return (sockaddr*)&m_addr;
}

const sockaddr* IPv6Address::getAddr() const {
    return (sockaddr*)&m_addr;
}

socklen_t IPv6Address::getAddrLen() const {
    return sizeof(m_addr);
}

std::ostream& IPv6Address::insert(std::ostream& os) const {
    os << "[";
    uint16_t* addr = (uint16_t*)m_addr.sin6_addr.s6_addr;
    bool used_zeros = false;
    for (size_t i = 0; i < 8; ++i) {
        if (addr[i] == 0 && !used_zeros) {
            continue;
        }
        if (i && addr[i - 1] == 0 && !used_zeros) {
            os << ":";
            used_zeros = true;
        }
        if (i) {
            os << ":";
        }
        os << std::hex << (int)byteswapOnLittleEndian(addr[i]) << std::dec;
    }

    if (!used_zeros && addr[7] == 0) {
        os << "::";
    }

    os << "]:" << byteswapOnLittleEndian(m_addr.sin6_port);
    return os;
}

IPAddress::ptr IPv6Address::broadcastAddress(uint32_t prefix_len) {
    sockaddr_in6 baddr(m_addr);
    baddr.sin6_addr.s6_addr[prefix_len / 8] |=
        CreateMask<uint8_t>(prefix_len % 8);
    for (int i = prefix_len / 8 + 1; i < 16; ++i) {
        baddr.sin6_addr.s6_addr[i] = 0xff;
    }
    return IPv6Address::ptr(new IPv6Address(baddr));
}

IPAddress::ptr IPv6Address::networkAddress(uint32_t prefix_len) {
    sockaddr_in6 baddr(m_addr);
    baddr.sin6_addr.s6_addr[prefix_len / 8] &=
        CreateMask<uint8_t>(prefix_len % 8);
    for (int i = prefix_len / 8 + 1; i < 16; ++i) {
        baddr.sin6_addr.s6_addr[i] = 0x00;
    }
    return IPv6Address::ptr(new IPv6Address(baddr));
}

IPAddress::ptr IPv6Address::subnetMask(uint32_t prefix_len) {
    sockaddr_in6 subnet;
    memset(&subnet, 0, sizeof(subnet));
    subnet.sin6_family = AF_INET6;
    subnet.sin6_addr.s6_addr[prefix_len / 8] =
        ~CreateMask<uint8_t>(prefix_len % 8);

    for (uint32_t i = 0; i < prefix_len / 8; ++i) {
        subnet.sin6_addr.s6_addr[i] = 0xff;
    }
    return IPv6Address::ptr(new IPv6Address(subnet));
}

uint32_t IPv6Address::getPort() const {
    return byteswapOnLittleEndian(m_addr.sin6_port);
}

void IPv6Address::setPort(uint16_t v) {
    m_addr.sin6_port = byteswapOnLittleEndian(v);
}

static const size_t MAX_PATH_LEN = sizeof(((sockaddr_un*)0)->sun_path) - 1;

UnixAddress::UnixAddress() {
    memset(&m_addr, 0, sizeof(m_addr));
    m_addr.sun_family = AF_UNIX;
    m_length = offsetof(sockaddr_un, sun_path) + MAX_PATH_LEN;
}

UnixAddress::UnixAddress(const std::string& path) {
    memset(&m_addr, 0, sizeof(m_addr));
    m_addr.sun_family = AF_UNIX;
    m_length = path.size() + 1;

    if (!path.empty() && path[0] == '\0') {
        --m_length;
    }

    if (m_length > sizeof(m_addr.sun_path)) {
        throw std::logic_error("path too long");
    }
    memcpy(m_addr.sun_path, path.c_str(), m_length);
    m_length += offsetof(sockaddr_un, sun_path);
}

void UnixAddress::setAddrLen(uint32_t v) {
    m_length = v;
}

sockaddr* UnixAddress::getAddr() {
    return (sockaddr*)&m_addr;
}

const sockaddr* UnixAddress::getAddr() const {
    return (sockaddr*)&m_addr;
}

socklen_t UnixAddress::getAddrLen() const {
    return m_length;
}

std::string UnixAddress::getPath() const {
    std::stringstream ss;
    if (m_length > offsetof(sockaddr_un, sun_path) &&
        m_addr.sun_path[0] == '\0') {
        ss << "\\0"
           << std::string(m_addr.sun_path + 1,
                          m_length - offsetof(sockaddr_un, sun_path) - 1);
    } else {
        ss << m_addr.sun_path;
    }
    return ss.str();
}

std::ostream& UnixAddress::insert(std::ostream& os) const {
    if (m_length > offsetof(sockaddr_un, sun_path) &&
        m_addr.sun_path[0] == '\0') {
        return os << "\\0"
                  << std::string(
                         m_addr.sun_path + 1,
                         m_length - offsetof(sockaddr_un, sun_path) - 1);
    }
    return os << m_addr.sun_path;
}

UnknownAddress::UnknownAddress(int family) {
    memset(&m_addr, 0, sizeof(m_addr));
    m_addr.sa_family = family;
}

UnknownAddress::UnknownAddress(const sockaddr& addr) {
    m_addr = addr;
}

sockaddr* UnknownAddress::getAddr() {
    return (sockaddr*)&m_addr;
}

const sockaddr* UnknownAddress::getAddr() const {
    return &m_addr;
}

socklen_t UnknownAddress::getAddrLen() const {
    return sizeof(m_addr);
}

std::ostream& UnknownAddress::insert(std::ostream& os) const {
    os << "[UnknownAddress family=" << m_addr.sa_family << "]";
    return os;
}

std::ostream& operator<<(std::ostream& os, const Address& addr) {
    return addr.insert(os);
}

}  // namespace ancfl
