#include "ck/kit.h"

#include <cstring>
#include <cstdio>
#include <cstdlib>
#include <cerrno>
#include <chrono>
#include <thread>

#if CK_WINDOWS
#  include <winsock2.h>
#  include <ws2tcpip.h>
#  include <iphlpapi.h>
#  ifndef _WINSOCK_DEPRECATED_NO_WARNINGS
#    define _WINSOCK_DEPRECATED_NO_WARNINGS
#  endif
#  pragma comment(lib, "Ws2_32.lib")
#  pragma comment(lib, "Iphlpapi.lib")
#  define CK_SOCK SOCKET
#  define CK_INVALID INVALID_SOCKET
#  define ckClosesocket closesocket
#else
#  include <sys/socket.h>
#  include <netinet/in.h>
#  include <netinet/tcp.h>
#  include <arpa/inet.h>
#  include <netdb.h>
#  include <unistd.h>
#  include <fcntl.h>
#  include <poll.h>
#  include <ifaddrs.h>
#  define CK_SOCK int
#  define CK_INVALID (-1)
#  define ckClosesocket close
#endif

namespace ck {
namespace {

bool fillSockAddr(const IpAddr& ip, uint16_t port, sockaddr* out, int& outLen, int& family) {
    memset(out, 0, sizeof(sockaddr_storage));
    if (ip.isV4()) {
        auto* s4 = (sockaddr_in*)out;
        s4->sin_family = AF_INET;
        s4->sin_port = htons(port);
        s4->sin_addr.s_addr = htonl((uint32_t)ip.toU64());
        outLen = (int)sizeof(sockaddr_in);
        family = AF_INET;
        return true;
    }
    auto* s6 = (sockaddr_in6*)out;
    s6->sin6_family = AF_INET6;
    s6->sin6_port = htons(port);
    memcpy(&s6->sin6_addr, ip.b, 16);
    outLen = (int)sizeof(sockaddr_in6);
    family = AF_INET6;
    return true;
}

}  // namespace

void netInit() {
#if CK_WINDOWS
    WSADATA w;
    WSAStartup(MAKEWORD(2, 2), &w);
#endif
}

void netShutdown() {
#if CK_WINDOWS
    WSACleanup();
#endif
}

// ------------------------------------------------------------------- ip
std::string IpAddr::str() const {
    char buf[64];
    if (family == 4) {
        snprintf(buf, sizeof(buf), "%u.%u.%u.%u", b[0], b[1], b[2], b[3]);
        return buf;
    }
    if (family == 6) {
        uint16_t g[8];
        for (int i = 0; i < 8; ++i) g[i] = (uint16_t)((b[i * 2] << 8) | b[i * 2 + 1]);
        int bestStart = -1, bestLen = 0, curStart = -1, curLen = 0;
        for (int i = 0; i < 8; ++i) {
            if (g[i] == 0) {
                if (curStart < 0) { curStart = i; curLen = 0; }
                ++curLen;
                if (curLen > bestLen) { bestLen = curLen; bestStart = curStart; }
            } else {
                curStart = -1;
                curLen = 0;
            }
        }
        std::string out;
        char tmp[16];
        for (int i = 0; i < 8;) {
            if (i == bestStart && bestLen > 1) {
                out += (i == 0) ? "::" : ":";
                i += bestLen;
                continue;
            }
            snprintf(tmp, sizeof(tmp), "%x", g[i]);
            if (i) out += ":";
            out += tmp;
            ++i;
        }
        if (out.empty()) out = "::";
        return out;
    }
    return "?";
}

uint64_t IpAddr::toU64() const {
    uint64_t v = 0;
    if (family == 4) {
        for (int i = 0; i < 4; ++i) v = (v << 8) | b[i];
    } else {
        for (int i = 0; i < 8; ++i) v = (v << 8) | ((uint64_t)b[i * 2] << 8 | b[i * 2 + 1]);
    }
    return v;
}

bool parseIp(const std::string& s, IpAddr& out) {
    struct in_addr a4;
    if (inet_pton(AF_INET, s.c_str(), &a4) == 1) {
        out.family = 4;
        uint32_t v = ntohl(a4.s_addr);
        out.b[0] = (uint8_t)(v >> 24); out.b[1] = (uint8_t)(v >> 16);
        out.b[2] = (uint8_t)(v >> 8);  out.b[3] = (uint8_t)v;
        return true;
    }
    struct in6_addr a6;
    if (inet_pton(AF_INET6, s.c_str(), &a6) == 1) {
        out.family = 6;
        memcpy(out.b, a6.s6_addr, 16);
        return true;
    }
    return false;
}

bool isPrivateIp(const IpAddr& a) {
    if (!a.isV4()) {
        if ((a.b[0] & 0xFE) == 0xFC) return true;
        if (a.b[0] == 0xFE && (a.b[1] & 0xC0) == 0x80) return true;
        if (memcmp(a.b, "\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\1", 16) == 0) return true;
        return false;
    }
    uint8_t p0 = a.b[0], p1 = a.b[1];
    if (p0 == 10) return true;
    if (p0 == 172 && p1 >= 16 && p1 <= 31) return true;
    if (p0 == 192 && p1 == 168) return true;
    if (p0 == 100 && p1 >= 64 && p1 <= 127) return true;
    if (p0 == 169 && p1 == 254) return true;
    return false;
}

bool isLoopbackIp(const IpAddr& a) {
    if (a.isV4()) return a.b[0] == 127;
    return (a.b[0] == 0 && a.b[1] == 0) || memcmp(a.b, "\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\1", 16) == 0;
}

bool isLinkLocalIp(const IpAddr& a) {
    if (a.isV4()) return a.b[0] == 169 && a.b[1] == 254;
    return a.b[0] == 0xFE && (a.b[1] & 0xC0) == 0x80;
}

// ------------------------------------------------------------------ cidr
std::string CidrBlock::str() const { return net.str() + "/" + std::to_string(prefix); }

IpAddr CidrBlock::networkAddr() const {
    IpAddr n = net;
    if (n.isV4()) {
        uint32_t mask = (prefix == 0) ? 0 : (0xFFFFFFFFu << (32 - prefix));
        uint32_t v = (uint32_t)n.toU64() & mask;
        n.b[0] = (uint8_t)(v >> 24); n.b[1] = (uint8_t)(v >> 16);
        n.b[2] = (uint8_t)(v >> 8);  n.b[3] = (uint8_t)v;
    } else {
        for (int i = 0; i < 16; ++i) {
            int bits = prefix - i * 8;
            uint8_t m = bits >= 8 ? 0xFF : (bits <= 0 ? 0x00 : (uint8_t)(0xFF << (8 - bits)));
            n.b[i] = (uint8_t)(n.b[i] & m);
        }
    }
    return n;
}

IpAddr CidrBlock::broadcastAddr() const {
    IpAddr n = networkAddr();
    if (n.isV4()) {
        uint32_t mask = (prefix >= 32) ? 0u : ~(0xFFFFFFFFu >> prefix);
        uint32_t v = (uint32_t)n.toU64() | mask;
        n.b[0] = (uint8_t)(v >> 24); n.b[1] = (uint8_t)(v >> 16);
        n.b[2] = (uint8_t)(v >> 8);  n.b[3] = (uint8_t)v;
    } else {
        for (int i = 0; i < 16; ++i) {
            int bits = prefix - i * 8;
            uint8_t m = bits <= 0 ? 0x00 : (uint8_t)(0xFF >> (bits >= 8 ? 8 - bits : bits));
            n.b[i] = (uint8_t)(n.b[i] | m);
        }
    }
    return n;
}

IpAddr CidrBlock::nth(uint64_t index) const {
    IpAddr n = networkAddr();
    if (n.isV4()) {
        uint32_t base = (uint32_t)n.toU64();
        uint32_t v = base + (uint32_t)index;
        n.b[0] = (uint8_t)(v >> 24); n.b[1] = (uint8_t)(v >> 16);
        n.b[2] = (uint8_t)(v >> 8);  n.b[3] = (uint8_t)v;
    } else {
        for (int i = 15; i >= 0 && index; --i) {
            uint32_t add = (uint32_t)(index & 0xFF);
            uint32_t v = (uint32_t)n.b[i] + add;
            n.b[i] = (uint8_t)v;
            index >>= 8;
        }
    }
    return n;
}

bool parseCidr(const std::string& s, CidrBlock& out) {
    size_t slash = s.find('/');
    if (slash == std::string::npos) {
        if (!parseIp(s, out.net)) return false;
        out.prefix = out.net.isV4() ? 32 : 128;
    } else {
        if (!parseIp(s.substr(0, slash), out.net)) return false;
        try { out.prefix = std::stoi(s.substr(slash + 1)); }
        catch (...) { return false; }
    }
    int maxBits = out.net.isV4() ? 32 : 128;
    if (out.prefix < 0 || out.prefix > maxBits) return false;
    out.net = CidrBlock{out.net, out.prefix, 0}.networkAddr();
    uint64_t hostBits = (uint64_t)maxBits - (uint64_t)out.prefix;
    out.count = hostBits >= 64 ? 0 : (1ULL << hostBits);
    if (out.prefix == 0) out.count = 0x100000000ULL;
    return true;
}

bool cidrContains(const CidrBlock& c, const IpAddr& a) {
    if (c.net.family != a.family) return false;
    CidrBlock tmp{a, c.prefix, c.count};
    IpAddr n = tmp.networkAddr();
    IpAddr na = CidrBlock{c.net, c.prefix, c.count}.networkAddr();
    return memcmp(n.b, na.b, a.isV4() ? 4 : 16) == 0;
}

uint64_t enumerateCidr(const CidrBlock& c, const std::function<bool(const IpAddr&)>& fn) {
    uint64_t count = 0;
    if (c.count == 0 || c.count > 0x1000000ULL) {
        fn(c.networkAddr());
        return 1;
    }
    for (uint64_t i = 0; i < c.count; ++i) {
        ++count;
        if (!fn(c.nth(i))) break;
    }
    return count;
}

// ----------------------------------------------------------------- ports
std::vector<uint16_t> parsePortSpec(const std::string& spec) {
    return parsePortRange(spec);
}

std::vector<uint16_t> parsePortRange(const std::string& spec) {
    std::vector<uint16_t> out;
    if (spec.empty()) return out;
    for (auto part : split(spec, ',')) {
        part = trim(part);
        if (part.empty()) continue;
        size_t dash = part.find('-');
        if (dash == std::string::npos) {
            try {
                int p = std::stoi(part);
                if (p >= 1 && p <= 65535) out.push_back((uint16_t)p);
            } catch (...) {}
        } else {
            try {
                int a = std::stoi(part.substr(0, dash));
                int b = std::stoi(part.substr(dash + 1));
                if (a > b) std::swap(a, b);
                if (a < 1) a = 1;
                if (b > 65535) b = 65535;
                for (int p = a; p <= b; ++p) out.push_back((uint16_t)p);
            } catch (...) {}
        }
    }
    return out;
}

std::string serviceName(uint16_t port) {
    switch (port) {
        case 21: return "ftp";
        case 22: return "ssh";
        case 23: return "telnet";
        case 25: return "smtp";
        case 53: return "dns";
        case 67: return "dhcp";
        case 68: return "dhcp";
        case 69: return "tftp";
        case 80: return "http";
        case 110: return "pop3";
        case 119: return "nntp";
        case 123: return "ntp";
        case 135: return "msrpc";
        case 137: return "netbios-ns";
        case 138: return "netbios-dgm";
        case 139: return "netbios-ssn";
        case 143: return "imap";
        case 161: return "snmp";
        case 389: return "ldap";
        case 443: return "https";
        case 445: return "smb";
        case 465: return "smtps";
        case 514: return "syslog";
        case 587: return "submission";
        case 623: return "ipmi";
        case 636: return "ldaps";
        case 993: return "imaps";
        case 995: return "pop3s";
        case 1433: return "mssql";
        case 1521: return "oracle";
        case 3306: return "mysql";
        case 3389: return "rdp";
        case 5432: return "postgres";
        case 5900: return "vnc";
        case 5985: return "winrm";
        case 6379: return "redis";
        case 8000: return "http-alt";
        case 8080: return "http-proxy";
        case 8443: return "https-alt";
        case 9200: return "elasticsearch";
        case 11211: return "memcached";
        case 27017: return "mongodb";
        default: return "";
    }
}

// ---------------------------------------------------------------- connect
bool tcpConnect(const std::string& host, uint16_t port, int timeoutMs, TcpResult& out,
                bool grabBanner, size_t bannerMax) {
    out = TcpResult{};
    addrinfo hints;
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    addrinfo* res = nullptr;
    char portStr[8];
    snprintf(portStr, sizeof(portStr), "%u", (unsigned)port);

    auto t0 = std::chrono::steady_clock::now();
    int rc = getaddrinfo(host.c_str(), portStr, &hints, &res);
    if (rc != 0 || !res) {
        out.error = rc ? rc : -1;
        return false;
    }
    for (addrinfo* ai = res; ai; ai = ai->ai_next) {
        CK_SOCK s = socket(ai->ai_family, ai->ai_socktype, ai->ai_protocol);
        if (s == CK_INVALID) continue;
#if CK_WINDOWS
        DWORD tm = (DWORD)timeoutMs;
        setsockopt(s, SOL_SOCKET, SO_RCVTIMEO, (const char*)&tm, sizeof(tm));
        setsockopt(s, SOL_SOCKET, SO_SNDTIMEO, (const char*)&tm, sizeof(tm));
#else
        timeval tv;
        tv.tv_sec = timeoutMs / 1000;
        tv.tv_usec = (timeoutMs % 1000) * 1000;
        setsockopt(s, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
        setsockopt(s, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));
#endif
        int cr = connect(s, ai->ai_addr, (int)ai->ai_addrlen);
        auto t1 = std::chrono::steady_clock::now();
        out.ms = std::chrono::duration<double, std::milli>(t1 - t0).count();
        if (cr == 0) {
            out.connected = true;
            out.error = 0;
            if (grabBanner) {
                Bytes probe;
                const char* probes[] = {"HEAD / HTTP/1.0\r\n\r\n", "\r\n\r\n", ""};
                for (int attempt = 0; attempt < 3 && out.banner.empty(); ++attempt) {
                    const char* p = probes[attempt];
                    size_t pl = strlen(p);
                    if (pl) send(s, p, (int)pl, 0);
                    Bytes buf(bannerMax);
                    int got = recv(s, (char*)buf.data(), (int)bannerMax, 0);
                    if (got > 0) out.banner.assign(buf.begin(), buf.begin() + got);
                }
            }
            ckClosesocket(s);
            freeaddrinfo(res);
            return true;
        }
#if CK_WINDOWS
        out.error = WSAGetLastError();
#else
        out.error = errno;
#endif
        ckClosesocket(s);
    }
    freeaddrinfo(res);
    return false;
}

bool udpProbe(const std::string& host, uint16_t port, int timeoutMs, Bytes& reply) {
    IpAddr ip;
    if (!parseIp(host, ip)) return false;
    sockaddr_storage ss;
    int ssLen = 0, family = 0;
    if (!fillSockAddr(ip, port, (sockaddr*)&ss, ssLen, family)) return false;
    CK_SOCK s = socket(family, SOCK_DGRAM, 0);
    if (s == CK_INVALID) return false;
#if CK_WINDOWS
    DWORD tm = (DWORD)timeoutMs;
    setsockopt(s, SOL_SOCKET, SO_RCVTIMEO, (const char*)&tm, sizeof(tm));
#else
    timeval tv;
    tv.tv_sec = timeoutMs / 1000;
    tv.tv_usec = (timeoutMs % 1000) * 1000;
    setsockopt(s, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
#endif
    bool ok = false;
    if (sendto(s, "argus-probe", 13, 0, (sockaddr*)&ss, ssLen) == 13) {
        Bytes buf(2048);
        int got = recv(s, (char*)buf.data(), 2048, 0);
        if (got > 0) { reply.assign(buf.begin(), buf.begin() + got); ok = true; }
    }
    ckClosesocket(s);
    return ok;
}

bool resolveHost(const std::string& host, std::vector<std::string>& ips) {
    addrinfo hints;
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    addrinfo* res = nullptr;
    if (getaddrinfo(host.c_str(), nullptr, &hints, &res) != 0) return false;
    for (addrinfo* ai = res; ai; ai = ai->ai_next) {
        char buf[64];
        if (ai->ai_family == AF_INET) {
            auto* s4 = (sockaddr_in*)ai->ai_addr;
            inet_ntop(AF_INET, &s4->sin_addr, buf, sizeof(buf));
            ips.push_back(buf);
        } else if (ai->ai_family == AF_INET6) {
            auto* s6 = (sockaddr_in6*)ai->ai_addr;
            inet_ntop(AF_INET6, &s6->sin6_addr, buf, sizeof(buf));
            ips.push_back(buf);
        }
    }
    freeaddrinfo(res);
    return !ips.empty();
}

std::string localHostName() {
    char buf[256];
    memset(buf, 0, sizeof(buf));
#if CK_WINDOWS
    DWORD n = 256;
    if (GetComputerNameA(buf, &n)) return std::string(buf, n);
#else
    if (gethostname(buf, sizeof(buf)) == 0) return std::string(buf);
#endif
    return "localhost";
}

std::vector<std::string> dnsServers() {
    std::vector<std::string> out;
#if CK_WINDOWS
    std::string s = runCapture(
        "powershell -NoProfile -Command \"(Get-DnsClientServerAddress -AddressFamily IPv4 "
        "| Select-Object -ExpandProperty ServerAddresses) -join ','\"", 25000);
    for (auto& p : split(s, ',')) if (!trim(p).empty()) out.push_back(trim(p));
#else
    std::string s;
    if (readTextFile("/etc/resolv.conf", s)) {
        for (auto& line : splitLines(s)) {
            if (startsWith(line, "nameserver")) {
                auto parts = split(line, ' ');
                if (parts.size() >= 2) out.push_back(trim(parts[1]));
            }
        }
    }
#endif
    return out;
}

std::string reverseDns(const std::string& ip) {
    IpAddr a;
    if (!parseIp(ip, a)) return "";
    sockaddr_storage ss;
    memset(&ss, 0, sizeof(ss));
    socklen_t slen;
    if (a.isV4()) {
        auto* s4 = (sockaddr_in*)&ss;
        s4->sin_family = AF_INET;
        s4->sin_addr.s_addr = htonl((uint32_t)a.toU64());
        slen = sizeof(sockaddr_in);
    } else {
        auto* s6 = (sockaddr_in6*)&ss;
        s6->sin6_family = AF_INET6;
        memcpy(&s6->sin6_addr, a.b, 16);
        slen = sizeof(sockaddr_in6);
    }
    char host[NI_MAXHOST];
    memset(host, 0, sizeof(host));
    if (getnameinfo((sockaddr*)&ss, slen, host, sizeof(host), nullptr, 0, NI_NAMEREQD) != 0)
        return "";
    return std::string(host);
}

}  // namespace ck