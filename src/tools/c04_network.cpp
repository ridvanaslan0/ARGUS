#include "common.h"

#include <cstring>
#include <map>
#include <set>
#include <mutex>
#include <algorithm>
#include <thread>
#include <chrono>

using namespace ck;
using namespace ck::tools;

namespace {

std::string netmaskStr(const CidrBlock& c);
std::string wildcardStr(const CidrBlock& c);

const std::string V_GREEN = "\033[38;5;46m";
const std::string V_RED = "\033[38;5;196m";
const std::string V_YEL = "\033[38;5;214m";
const std::string V_DIM = "\033[2;37m";
const std::string V_RESET = "\033[0m";

// ------------------------------------------------------------------ CIDR
int runCidr(const Args& a) {
    std::string spec = a.opt("cidr");
    if (spec.empty() && !a.first().empty()) spec = a.first();
    if (spec.empty()) {
        ui::fail("pass a CIDR block, e.g. argus cidr 10.0.0.0/24");
        return 1;
    }

    CidrBlock c;
    if (!parseCidr(spec, c)) {
        ui::fail("cannot parse CIDR: " + spec);
        return 1;
    }

    ui::section("SUBNET");
    int maxBits = c.net.isV4() ? 32 : 128;
    uint64_t hostBits = (uint64_t)maxBits - (uint64_t)c.prefix;
    uint64_t usable = c.count;

    ui::kv("network", c.networkAddr().str() + "/" + std::to_string(c.prefix));
    ui::kv("broadcast", c.broadcastAddr().str());
    ui::kv("first host", c.nth(c.net.isV4() && c.prefix <= 30 ? 1 : 0).str());
    ui::kv("last host", c.nth(c.net.isV4() && c.prefix <= 30 ? c.count - 2 : c.count - 1).str());
    ui::kv("address class", c.net.isV4() ? (c.net.b[0] < 128 ? "A" : c.net.b[0] < 192 ? "B" : "C") : "IPv6");
    ui::kv("scope", isPrivateIp(c.networkAddr()) ? "private (RFC1918)" :
                      isLoopbackIp(c.networkAddr()) ? "loopback" : "public");
    ui::kv("total addresses", std::to_string(c.count) + "  (2^" + std::to_string(hostBits) + ")");
    ui::kv("usable hosts", std::to_string(c.net.isV4() && c.prefix <= 30 ? c.count - 2 : c.count));
    ui::kv("netmask", netmaskStr(c));
    ui::kv("wildcard", wildcardStr(c));
    ui::line("");

    int sub = std::atoi(a.opt("split", "24").c_str());
    if (a.hasOpt("split") && sub > c.prefix && sub <= maxBits) {
        int bits = sub - c.prefix;
        uint64_t n = bits >= 40 ? 0 : (1ULL << bits);
        ui::section("SUBNET PLAN  /" + std::to_string(sub));
        std::vector<std::vector<std::string>> rows;
        uint64_t show = std::min<uint64_t>(n, 256);
        for (uint64_t i = 0; i < show; ++i) {
            uint64_t step = 1;
            for (int b = 0; b < bits; ++b) step *= 2;
            uint64_t base = (uint64_t)c.networkAddr().toU64() + i * step;
            IpAddr n2 = c.networkAddr();
            uint32_t v = (uint32_t)base;
            n2.b[0] = (uint8_t)(v >> 24); n2.b[1] = (uint8_t)(v >> 16);
            n2.b[2] = (uint8_t)(v >> 8);  n2.b[3] = (uint8_t)v;
            uint32_t bv = v + (uint32_t)step - 1;
            IpAddr b2 = n2;
            b2.b[0] = (uint8_t)(bv >> 24); b2.b[1] = (uint8_t)(bv >> 16);
            b2.b[2] = (uint8_t)(bv >> 8);  b2.b[3] = (uint8_t)bv;
            rows.push_back({n2.str(), b2.str(), std::to_string(step - 2), std::to_string(step)});
        }
        ui::table({"NETWORK", "BROADCAST", "HOSTS", "SIZE"}, rows);
        if (n > show) ui::info(std::to_string(n - show) + " more /" + std::to_string(sub) + " blocks not shown");
        ui::line("");
    }

    if (a.flag("enum")) {
        size_t limit = (size_t)std::atoll(a.opt("limit", "256").c_str());
        ui::section("ADDRESS ENUMERATION");
        std::vector<std::vector<std::string>> rows;
        uint64_t n = 0;
        enumerateCidr(c, [&](const IpAddr& ip) {
            ++n;
            if (rows.size() < limit) {
                rows.push_back({std::to_string(n), ip.str(),
                                isPrivateIp(ip) ? "private" : isLoopbackIp(ip) ? "loopback" : "public"});
            }
            return n < limit;
        });
        ui::table({"#", "ADDRESS", "SCOPE"}, rows);
        ui::line("");
        ui::kv("enumerated", std::to_string(n) + (n >= limit ? " (truncated)" : ""));
        ui::line("");
    }

    if (a.hasOpt("ports")) {
        auto ports = parsePortRange(a.opt("ports"));
        std::vector<std::vector<std::string>> rows;
        for (size_t i = 0; i < ports.size() && i < 128; ++i)
            rows.push_back({std::to_string(ports[i]), serviceName(ports[i]),
                            ports[i] < 1024 ? "privileged" : "ephemeral-range/high"});
        ui::section("PORTS");
        ui::table({"PORT", "SERVICE", "CLASS"}, rows);
        ui::line("");
    }

    ui::info("run argus portscan against a block only with written authorization");
    ui::line("");
    return 0;
}

std::string netmaskStr(const CidrBlock& c) {
    IpAddr n = c.networkAddr();
    IpAddr b = c.broadcastAddr();
    std::string out;
    for (int i = 0; i < 4; ++i) {
        if (i) out += ".";
        out += std::to_string((uint8_t)(255 - (uint8_t)(n.b[i] ^ b.b[i])));
    }
    return out;
}

std::string wildcardStr(const CidrBlock& c) {
    IpAddr n = c.networkAddr();
    IpAddr b = c.broadcastAddr();
    std::string out;
    for (int i = 0; i < 4; ++i) {
        if (i) out += ".";
        out += std::to_string((uint8_t)(n.b[i] ^ b.b[i]));
    }
    return out;
}

// ------------------------------------------------------------- portscan
struct ScanRow {
    uint16_t port = 0;
    bool open = false;
    double ms = 0;
    std::string banner;
    int code = 0;
};

int runPortScan(const Args& a) {
    ui::section("TCP PORT SCANNER");

    std::string target = a.opt("target");
    if (target.empty() && !a.first().empty()) target = a.first();
    if (target.empty()) {
        ui::fail("pass a target: argus portscan 127.0.0.1 --ports 22,80,443");
        return 1;
    }
    if (!requireAuthorization(a, target)) return 2;

    std::string portSpec = a.opt("ports", "22,80,443,445,3389,8080");
    auto ports = parsePortRange(portSpec);
    if (ports.empty()) {
        ui::fail("no valid ports in --ports " + portSpec);
        return 1;
    }
    int timeout = std::atoi(a.opt("timeout", "1200").c_str());
    bool grabBanner = a.flag("banner");
    bool skipClosed = !a.flag("show-closed");
    size_t maxPorts = (size_t)std::atoll(a.opt("max", "1024").c_str());
    if (ports.size() > maxPorts) ports.resize(maxPorts);

    std::vector<std::string> resolved;
    if (!resolveHost(target, resolved)) {
        ui::warn("could not resolve " + target + ", treating it as a literal address");
        resolved.push_back(target);
    }

    ui::kv("target", target + "  ->  " + join(resolved, ", "));
    ui::kv("ports", std::to_string(ports.size()) + " (" + ui::truncateTo(portSpec, 44) + ")");
    ui::kv("timeout", std::to_string(timeout) + " ms per port");
    ui::kv("method", "TCP connect (half-open detection unavailable, no SYN flood)");
    ui::line("");

    std::vector<ScanRow> rows;
    std::map<uint16_t, ScanRow> found;
    size_t done = 0;

    spinnerStart("connecting");
    for (size_t p = 0; p < ports.size(); ++p) {
        for (auto& host : resolved) {
            TcpResult r;
            tcpConnect(host, ports[p], timeout, r, grabBanner);
            ScanRow row;
            row.port = ports[p];
            row.open = r.connected;
            row.ms = r.ms;
            row.banner = r.banner;
            row.code = r.error;
            found[ports[p]] = row;
        }
        ++done;
        if (done % 4 == 0 || done == ports.size()) {
            spinnerStop();
            progressBar("scanning", done, ports.size());
        }
    }
    spinnerStop();
    fputs("\r\033[K", stdout);

    int openCount = 0;
    std::vector<std::vector<std::string>> table;
    for (auto& kv : found) {
        if (kv.second.open) ++openCount;
        if (!kv.second.open && skipClosed) continue;
        table.push_back({std::to_string(kv.second.port),
                         kv.second.open ? (std::string(V_GREEN) + "OPEN" + V_RESET) : (std::string(V_DIM) + "closed" + V_RESET),
                         fmt(kv.second.ms, 1),
                         serviceName(kv.second.port),
                         kv.second.banner.empty() ? "" : ui::truncateTo(bytesToText(textToBytes(kv.second.banner), 60), 34)});
    }

    ui::section("RESULTS");
    ui::table({"PORT", "STATE", "MS", "SERVICE", "BANNER"}, table);
    ui::line("");
    ui::kv("open", std::to_string(openCount) + " of " + std::to_string(found.size()));
    ui::line("");

    std::vector<Finding> fs;
    int risky = 0;
    for (auto& kv : found) {
        if (!kv.second.open) continue;
        uint16_t port = kv.first;
        if (port == 21 || port == 23 || port == 69)
            { fs.push_back({"P-CLEARTEXT", "port " + std::to_string(port) + " (" + serviceName(port) +
                                          ") transmits credentials in clear text", 3}); ++risky; }
        if (port == 445)
            { fs.push_back({"P-SMB", "SMB on 445: check signing, SMBv1 and share enumeration", 2}); ++risky; }
        if (port == 3389)
            { fs.push_back({"P-RDP", "RDP exposed: enforce NLA and lockout policy", 2}); ++risky; }
        if (port == 23)
            { fs.push_back({"P-TELNET", "telnet exposed: disable it entirely", 3}); ++risky; }
    }
    if (openCount > 12)
        fs.push_back({"P-WIDE", std::to_string(openCount) + " open ports: high attack surface, close what is unused", 2});

    if (!fs.empty()) {
        renderFindings(fs);
    } else {
        ui::ok("no clear-text or otherwise high-risk services detected");
        ui::line("");
    }
    return 0;
}

// ----------------------------------------------------------- hostdisc
int runHostDisc(const Args& a) {
    ui::section("HOST DISCOVERY");

    std::string spec = a.opt("cidr");
    if (spec.empty() && !a.first().empty()) spec = a.first();
    if (spec.empty()) {
        ui::fail("pass a CIDR block, e.g. argus hostdisc 192.168.1.0/24");
        return 1;
    }
    if (!requireAuthorization(a, split(spec, '/')[0])) return 2;

    CidrBlock c;
    if (!parseCidr(spec, c)) {
        ui::fail("cannot parse CIDR: " + spec);
        return 1;
    }
    if (c.count > 65536) {
        ui::fail("block has " + std::to_string(c.count) + " addresses; narrow it below /16 or pass --allow-large");
        return 1;
    }

    std::vector<uint16_t> ports = {80, 443, 22, 445, 3389};
    if (a.hasOpt("ports")) ports = parsePortRange(a.opt("ports"));
    std::vector<std::string> portNames;
    for (uint16_t p : ports) portNames.push_back(std::to_string(p));
    int timeout = std::atoi(a.opt("timeout", "700").c_str());
    int threads = std::atoi(a.opt("threads", "64").c_str());
    if (threads < 1) threads = 1;
    if (threads > 512) threads = 512;

    ui::kv("block", c.str());
    ui::kv("addresses", std::to_string(c.count));
    ui::kv("probe ports", join(portNames, ", "));
    ui::kv("timeout", std::to_string(timeout) + " ms");
    ui::kv("concurrency", std::to_string(threads));
    ui::line("");

    std::vector<std::string> alive;
    std::mutex m;
    size_t idx = 0;
    uint64_t total = c.count;
    size_t done = 0;

    auto worker = [&]() {
        while (true) {
            size_t i;
            {
                std::lock_guard<std::mutex> lk(m);
                if (idx >= total) return;
                i = idx++;
            }
            IpAddr ip = c.nth(i);
            std::vector<uint16_t> hit;
            for (uint16_t p : ports) {
                TcpResult r;
                if (tcpConnect(ip.str(), p, timeout, r)) hit.push_back(p);
            }
            if (!hit.empty()) {
                std::vector<std::string> ps;
                for (uint16_t p : hit) ps.push_back(std::to_string(p));
                std::lock_guard<std::mutex> lk(m);
                alive.push_back(ip.str() + "\t" + join(ps, ","));
            }
            {
                std::lock_guard<std::mutex> lk(m);
                ++done;
            }
        }
    };

    spinnerStart("probing");
    std::vector<std::thread> pool;
    for (int i = 0; i < threads; ++i) pool.emplace_back(worker);
    for (auto& t : pool) t.join();
    spinnerStop();
    fputs("\r\033[K", stdout);

    std::sort(alive.begin(), alive.end());
    std::vector<std::vector<std::string>> rows;
    for (auto& line : alive) {
        auto parts = split(line, '\t');
        std::string ip = parts.empty() ? "" : parts[0];
        std::string pl = parts.size() > 1 ? parts[1] : "";
        std::string rdns = reverseDns(ip);
        rows.push_back({ip, pl, rdns.empty() ? (V_DIM + "-" + V_RESET) : ui::truncateTo(rdns, 28)});
    }

    ui::section("ALIVE HOSTS");
    ui::table({"IP", "OPEN PORTS", "PTR"}, rows);
    ui::line("");
    ui::kv("alive", std::to_string(alive.size()) + " of " + std::to_string(total) +
                      "  (" + fmt(alive.empty() ? 0 : alive.size() * 100.0 / total, 1) + "%)");
    ui::line("");
    if (alive.empty())
        ui::warn("no hosts answered; confirm subnet mask, VLAN and firewall rules");
    else
        ui::ok(std::to_string(alive.size()) + " host(s) responded to a TCP probe");
    ui::line("");
    return 0;
}

}  // namespace

CK_TOOL("cidr", "network", "Subnet math: network/broadcast/hosts, mask, split plan, address enumeration",
        "argus cidr 10.0.0.0/24 --split 26 --enum", runCidr);
CK_TOOL("portscan", "network", "Rate-limited TCP connect scanner with banner capture (authorized targets only)",
        "argus portscan <host|cidr-host> --ports 22,80,443 [--banner] [--timeout 1200]", runPortScan);
CK_TOOL("hostdisc", "network", "TCP host-discovery sweep with PTR lookups (authorized targets only)",
        "argus hostdisc <cidr> [--ports 80,443,22] [--threads 64]", runHostDisc);