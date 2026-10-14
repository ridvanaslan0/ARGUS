#include "common.h"

#include <cstring>
#include <map>
#include <set>
#include <algorithm>

using namespace ck;
using namespace ck::tools;

namespace {

const std::string V_GREEN = "\033[38;5;46m";
const std::string V_YEL = "\033[38;5;214m";
const std::string V_RED = "\033[38;5;196m";
const std::string V_DIM = "\033[2;37m";
const std::string V_RESET = "\033[0m";

uint16_t rd16(const Bytes& b, size_t o) {
    return (uint16_t)((b[o] << 8) | b[o + 1]);
}
uint32_t rd32(const Bytes& b, size_t o) {
    return ((uint32_t)b[o] << 24) | ((uint32_t)b[o + 1] << 16) | ((uint32_t)b[o + 2] << 8) | b[o + 3];
}

struct PktInfo {
    std::string src = "-";
    std::string dst = "-";
    std::string proto = "-";
    std::string info = "";
    uint16_t sport = 0, dport = 0;
    uint8_t ipProto = 0;
    bool tcpFlags = false;
    std::string flagStr;
};

std::string tcpFlagsStr(uint8_t f) {
    std::string s;
    if (f & 0x02) s += "S";
    if (f & 0x10) s += "A";
    if (f & 0x01) s += "F";
    if (f & 0x08) s += "P";
    if (f & 0x04) s += "R";
    if (f & 0x20) s += "U";
    if (f & 0x40) s += "E";
    if (f & 0x80) s += "C";
    return s.empty() ? "-" : s;
}

std::string decodeTcpOptions(const Bytes& b, size_t o, size_t end) {
    std::string s;
    while (o < end && o < b.size()) {
        uint8_t kind = b[o];
        if (kind == 0) break;
        if (kind == 1) { s += "NOP "; ++o; continue; }
        if (o + 1 >= b.size()) break;
        uint8_t len = b[o + 1];
        if (len < 2 || o + len > end) break;
        if (kind == 2 && len == 4) { s += "MSS=" + std::to_string(rd16(b, o + 2)) + " "; }
        else if (kind == 3 && len == 3) { s += "WS=" + std::to_string(b[o + 2]) + " "; }
        else if (kind == 4 && len == 2) { s += "SACKok "; }
        else if (kind == 5 && len >= 10) {
            s += "SAck:" + std::to_string(rd16(b, o + 2)) + "-" + std::to_string(rd16(b, o + 4)) + " ";
        }
        else if (kind == 8 && len == 10) { s += "Timestamps "; }
        else if (kind == 28 && len == 4) { s += "UA "; }
        else if (kind == 29 && len == 5) { s += "TOCO "; }
        o += len;
    }
    return trim(s);
}

PktInfo parsePacket(const Bytes& b, bool linkType) {
    PktInfo p;
    if (b.size() < (linkType ? 14u : 0u)) return p;
    size_t off = 0;
    uint16_t ethertype = 0x0800;
    if (linkType) {
        ethertype = (uint16_t)((b[12] << 8) | b[13]);
        off = 14;
        while (ethertype == 0x8100 || ethertype == 0x88A8) {
            if (off + 4 > b.size()) return p;
            ethertype = (uint16_t)((b[off + 2] << 8) | b[off + 3]);
            off += 4;
        }
    }

    if (ethertype == 0x0800) {
        if (off + 20 > b.size()) return p;
        uint8_t ihl = (uint8_t)(b[off] & 0x0F);
        p.ipProto = b[off + 9];
        p.src = std::to_string(b[off + 12]) + "." + std::to_string(b[off + 13]) + "." +
                std::to_string(b[off + 14]) + "." + std::to_string(b[off + 15]);
        p.dst = std::to_string(b[off + 16]) + "." + std::to_string(b[off + 17]) + "." +
                std::to_string(b[off + 18]) + "." + std::to_string(b[off + 19]);
        size_t ipTot = rd16(b, off + 2);
        size_t ipStart = off;
        off += ihl * 4;
        if (ipTot && off > ipStart + ipTot) return p;
    } else if (ethertype == 0x86DD) {
        if (off + 40 > b.size()) return p;
        p.ipProto = b[off + 6];
        std::string sb, db;
        for (int i = 0; i < 8; ++i) {
            char h[8];
            snprintf(h, sizeof(h), "%02x%02x", b[off + 8 + i * 2], b[off + 9 + i * 2]);
            sb += h;
        }
        for (int i = 0; i < 8; ++i) {
            char h[8];
            snprintf(h, sizeof(h), "%02x%02x", b[off + 24 + i * 2], b[off + 25 + i * 2]);
            db += h;
        }
        IpAddr si, di;
        parseIp(replaceAll(sb, ":", ""), si);
        IpAddr di2;
        parseIp(replaceAll(db, ":", ""), di2);
        p.src = si.str();
        p.dst = di2.str();
        off += 40;
        p.proto = "IPv6/" + std::to_string(p.ipProto);
    } else if (ethertype == 0x0806) {
        p.proto = "ARP";
        p.src = "arp";
        p.dst = "arp";
        off += 28;
    } else {
        char buf[16];
        snprintf(buf, sizeof(buf), "eth 0x%04x", ethertype);
        p.proto = buf;
        off = b.size();
    }

    switch (p.ipProto) {
        case 6: {
            p.proto = "TCP";
            if (off + 20 > b.size()) return p;
            p.sport = rd16(b, off);
            p.dport = rd16(b, off + 2);
            size_t doff = (size_t)(b[off + 12] >> 4) * 4;
            uint8_t flags = b[off + 13];
            p.flagStr = tcpFlagsStr(flags);
            p.tcpFlags = true;
            p.info = std::to_string(p.sport) + " -> " + std::to_string(p.dport) + " [" + p.flagStr + "]";
            if (doff > 20 && off + doff <= b.size()) {
                std::string opts = decodeTcpOptions(b, off + 20, off + doff);
                if (!opts.empty()) p.info += "  opts{" + ui::truncateTo(opts, 24) + "}";
            }
            break;
        }
        case 17:
            p.proto = "UDP";
            if (off + 8 > b.size()) return p;
            p.sport = rd16(b, off);
            p.dport = rd16(b, off + 2);
            p.info = std::to_string(p.sport) + " -> " + std::to_string(p.dport) +
                     " len=" + std::to_string(rd16(b, off + 4));
            break;
        case 1: {
            p.proto = "ICMP";
            if (off + 4 > b.size()) return p;
            static const char* icmpType[] = {"echo-reply","dest-unreach","source-quench","redirect",
                "echo-request","alt-host","router-advert","router-solicit","time-exceeded",
                "parameter-problem","timestamp-req","timestamp-reply","info-req","info-reply",
                "mask-req","mask-reply"};
            p.info = b[off] < 16 ? std::string(icmpType[b[off]]) : ("type" + std::to_string(b[off]));
            break;
        }
        case 47: p.proto = "GRE"; p.info = "gre"; break;
        case 50: p.proto = "ESP"; p.info = "esp (encrypted)"; break;
        case 51: p.proto = "AH"; p.info = "ah"; break;
        case 89: p.proto = "OSPF"; p.info = "ospf"; break;
        default: {
            char buf[16];
            snprintf(buf, sizeof(buf), "ip proto %u", p.ipProto);
            p.proto = buf;
            p.info = "proto " + std::to_string(p.ipProto);
        }
    }

    if (p.proto == "TCP" || p.proto == "UDP") {
        if (serviceName(p.dport).empty() && serviceName(p.sport).empty())
            p.info += "   [uncommon port]";
    }
    return p;
}

int runPcap(const Args& a) {
    ui::section("PCAP / PCAPNG ANALYSIS");

    std::string file = a.opt("file");
    if (file.empty() && !a.first().empty()) file = a.first();
    if (file.empty()) {
        ui::fail("pass --file capture.pcap");
        return 1;
    }
    Bytes data;
    std::string err;
    if (!readFile(file, data, &err)) { ui::fail(err); return 1; }
    if (data.size() < 24) { ui::fail("file too small to be a capture"); return 1; }

    uint32_t magic = rd32(data, 0);
    bool swapped = false;
    bool littleEndian = true;
    bool nanosecond = false;
    bool pcapng = false;

if (magic == 0xA1B2C3D4) { littleEndian = false; }
else if (magic == 0xD4C3B2A1) { littleEndian = true; }
else if (magic == 0xA1B23C4D) { littleEndian = false; nanosecond = true; }
else if (magic == 0x4D3CB2A1) { littleEndian = true; nanosecond = true; }
    else if (magic == 0x0A0D0D0A) { pcapng = true; }
    else {
        ui::fail("not a pcap/pcapng file (magic=" + hexEncode(data.data(), 4) + ")");
        return 1;
    }

    auto rd16e = [&](size_t o) -> uint16_t {
        if (o + 2 > data.size()) return 0;
        return littleEndian ? (uint16_t)(data[o] | (data[o + 1] << 8))
                            : (uint16_t)((data[o] << 8) | data[o + 1]);
    };
    auto rd32e = [&](size_t o) -> uint32_t {
        if (o + 4 > data.size()) return 0;
        return littleEndian ? ((uint32_t)data[o] | ((uint32_t)data[o + 1] << 8) |
                               ((uint32_t)data[o + 2] << 16) | ((uint32_t)data[o + 3] << 24))
                            : rd32(data, o);
    };

    if (pcapng) {
        ui::info("pcapng detected: reading classic block stream only, some interfaces may be skipped");
    }

    uint32_t linkType = 1;
    size_t off = 24;
    if (!pcapng) {
        linkType = rd32e(20);
        ui::kv("format", std::string("pcap") + (nanosecond ? " (nanosecond)" : " (microsecond)"));
    } else {
        linkType = 1;
        ui::kv("format", "pcapng (best-effort)");
    }
    ui::kv("endianness", littleEndian ? "little" : "big");
    if (linkType != 0 && linkType != 1 && linkType != 101 && linkType != 113 && linkType != 276)
        linkType = 1;
    ui::kv("link type", linkType == 1 ? "Ethernet (1)" : linkType == 0 ? "NULL/loopback (0)" :
                                  linkType == 101 ? "Raw IP (101)" : "type " + std::to_string(linkType));
    ui::kv("file size", std::to_string(data.size()) + " bytes");
    (void)swapped;

    std::map<std::string, size_t> protoCount;
    std::map<std::string, size_t> talkers, responders;
    std::map<std::pair<std::string, int>, size_t> dstPorts;
    std::vector<std::string> synSweep;
    std::map<std::string, std::set<uint16_t>> synBySrc;
    std::map<std::string, std::string> synTimes;
    std::vector<PktInfo> packets;
    size_t parsed = 0, truncated = 0;

    while (off + 16 <= data.size()) {
        if (pcapng && data[off] == 6 && off + 20 <= data.size()) {
            uint32_t blen = rd32e(off + 4);
            if (blen < 12 || off + blen > data.size()) break;
            off += blen;
            continue;
        }
        uint32_t inclLen = rd32e(off + 8);
        size_t hdrLen = 16;
        if (off + hdrLen + inclLen > data.size()) {
            truncated = 1;
            break;
        }
        Bytes pkt(data.begin() + off + hdrLen, data.begin() + off + hdrLen + inclLen);
        off += hdrLen + inclLen;
        ++parsed;

        PktInfo info = parsePacket(pkt, linkType != 101);
        if (info.proto == "-") continue;
        protoCount[info.proto]++;
        if (info.src != "-") talkers[info.src]++;
        if (info.dst != "-") responders[info.dst]++;
        if (info.proto == "TCP") dstPorts[{info.src, info.dport}]++;
        if (info.flagStr.size() == 1 && info.flagStr[0] == 'S')
            synBySrc[info.src].insert(info.dport);
        if (packets.size() < 20000) packets.push_back(info);
        if (parsed % 5000 == 0) progressBar("parsing", parsed, data.size());
    }
    if (parsed > 5000) fputs("\r\033[K", stdout);

    ui::line("");
    ui::kv("packets", std::to_string(parsed));
    ui::line("");

    ui::section("PROTOCOL DISTRIBUTION");
    std::vector<std::vector<std::string>> rows;
    size_t total = 0;
    for (auto& kv : protoCount) total += kv.second;
    for (auto& kv : protoCount)
        rows.push_back({kv.first, std::to_string(kv.second),
                        fmt(total ? kv.second * 100.0 / total : 0, 1) + "%",
                        ui::bar(total ? (double)kv.second / total : 0, 18)});
    ui::table({"PROTO", "PACKETS", "PCT", "SHARE"}, rows);

    ui::section("TOP TALKERS (source)");
    rows.clear();
    std::vector<std::pair<std::string, size_t>> t(talkers.begin(), talkers.end());
    std::sort(t.begin(), t.end(), [](auto& x, auto& y) { return x.second > y.second; });
    for (size_t i = 0; i < t.size() && i < 12; ++i) {
        IpAddr ip;
        std::string kind = parseIp(t[i].first, ip) ? (isPrivateIp(ip) ? "private" : "public") : "-";
        rows.push_back({t[i].first, std::to_string(t[i].second), kind, ""});
    }
    ui::table({"IP", "PACKETS SENT", "SCOPE", ""}, rows);

    ui::section("TOP DESTINATION PORTS");
    rows.clear();
    std::vector<std::pair<std::pair<std::string, int>, size_t>> d(dstPorts.begin(), dstPorts.end());
    std::sort(d.begin(), d.end(), [](auto& x, auto& y) { return x.second > y.second; });
    for (size_t i = 0; i < d.size() && i < 12; ++i)
        rows.push_back({d[i].first.second == 0 ? std::to_string(0) : std::to_string(d[i].first.second),
                        serviceName((uint16_t)d[i].first.second), std::to_string(d[i].second), ""});
    ui::table({"PORT", "SERVICE", "SYN COUNT", ""}, rows);

    std::vector<Finding> fs;
    for (auto& kv : synBySrc) {
        if (kv.second.size() >= 20) {
            std::vector<std::string> ps;
            for (uint16_t p : kv.second) ps.push_back(std::to_string(p));
            std::string sample;
            for (size_t i = 0; i < ps.size() && i < 8; ++i) sample += ps[i] + " ";
            synSweep.push_back(kv.first + " -> " + std::to_string(kv.second.size()) + " ports (" +
                               ui::truncateTo(sample, 30) + ")");
            fs.push_back({"P-SWEEP", kv.first + " sent SYNs to " + std::to_string(kv.second.size()) +
                                      " distinct ports in this capture: horizontal or vertical port scan", 3});
        }
    }
    int cleartext = 0;
    for (auto& kv : protoCount) {
        if (kv.first == "TCP") {
            for (auto& dp : dstPorts) {
                uint16_t p = (uint16_t)dp.first.second;
                if (p == 21 || p == 23 || p == 25 || p == 110 || p == 143) ++cleartext;
            }
        }
    }
    if (cleartext > 0)
        fs.push_back({"P-CLEARTEXT", "clear-text protocols present (ftp/telnet/smtp/pop3/imap) in capture", 2});

    if (!synSweep.empty()) {
        ui::section("SUSPECTED SCANS");
        for (auto& s : synSweep) ui::bullet(s);
        ui::line("");
    }

    if (truncated) fs.push_back({"P-TRUNC", "capture file ends mid-packet: it may be truncated", 1});
    if (fs.empty()) {
        ui::ok("no scan signatures or clear-text protocols detected");
        ui::line("");
    } else {
        renderFindings(fs);
    }

    if (a.flag("detail")) {
        size_t show = std::min<size_t>(packets.size(), 60);
        rows.clear();
        for (size_t i = 0; i < show; ++i)
            rows.push_back({std::to_string(i + 1), packets[i].src, packets[i].dst,
                            packets[i].proto + "  " + ui::truncateTo(packets[i].info, 26)});
        ui::section("PACKET DETAIL (first " + std::to_string(show) + ")");
        ui::table({"#", "SRC", "DST", "PROTO / INFO"}, rows);
        ui::line("");
    }
    return 0;
}

// ------------------------------------------------------------ sigmatch
struct SigRule {
    std::string name;
    std::vector<std::string> magic;
    std::vector<std::string> strings;
    int minScore = 1;
    std::string desc;
};

int runSigMatch(const Args& a) {
    ui::section("SIGNATURE MATCHER (YARA-lite)");

    static const SigRule rules[] = {
        {"PK-ZIP", {"504b0304"}, {"[Content_Types].xml", "docProps/", "mimetype"}, 1, "ZIP/OOXML/APK archive"},
        {"GZIP", {"1f8b08"}, {}, 1, "gzip stream"},
        {"PE-EXE", {"4d5a"}, {"PE\\x00\\x00", "This program cannot be run in DOS mode"}, 2, "Windows PE executable"},
        {"ELF", {"7f454c46"}, {}, 1, "Linux ELF binary"},
        {"MACHO", {"feedface", "cefaedfe", "cffaedfe", "cafebabe"}, {}, 1, "Mach-O binary"},
        {"RAR", {"526172211a0700"}, {}, 1, "RAR archive"},
        {"7Z", {"377abcaf271c"}, {}, 1, "7-Zip archive"},
        {"PDF", {"25504446"}, {"/JavaScript", "/OpenAction", "/AA", "/Launch"}, 1, "PDF with active content"},
        {"SCRIPT-PS1", {}, {"powershell", "-enc", "-EncodedCommand", "Invoke-Expression", "IEX", "DownloadString",
                            "FromBase64String", "Net.WebClient"}, 2, "PowerShell living-off-the-land indicators"},
        {"LOLBIN", {}, {"certutil -urlcache", "bitsadmin /transfer", "regsvr32 /i:http", "mshta http",
                        "rundll32 shell32,Control_RunDLL", "wmic process call create"}, 1, "living-off-the-land binary abuse"},
        {"CRED-DUMP", {}, {"lsass.exe", "sekurlsa", "mimikatz", "procdump", "ntds.dit",
                           "reg save HKLM\\SAM", "reg save HKLM\\SECURITY"}, 1, "credential access tooling"},
        {"PERSIST-RUN", {}, {"CurrentVersion\\Run", "schtasks /create", "sc create", "New-Service",
                             "Winlogon\\Shell", "Image File Execution"}, 1, "persistence mechanism reference"},
        {"RANSOM-NOTE", {}, {"Your files have been encrypted", "decrypt my files", "restore-my-files",
                             "All your files are encrypted", "how to decrypt"}, 1, "ransom note language"},
        {"CRYPTO-MINER", {}, {"stratum+tcp://", "xmrig", "minerd", "--donate-level", "coinhive"}, 1, "cryptominer reference"},
        {"WEBSHELL", {}, {"eval($_POST", "system($_GET", "passthru(", "shell_exec(", "assert($_POST"}, 1, "PHP webshell one-liner"},
        {"SQLI", {}, {"' OR 1=1--", "UNION SELECT", "SLEEP(", "BENCHMARK(", "information_schema"}, 1, "SQL injection payload"},
        {"XSS", {}, {"<script>alert(", "javascript:", "onerror=", "document.cookie"}, 1, "XSS payload"},
        {"SUSPICIOUS-C2", {}, {"User-Agent: Mozilla/4.0 (compatible; MSIE 6.0", "powershell -nop -w hidden",
                               "certutil -f -decode", "reg add HKCU\\Software\\Classes"}, 2, "command-and-control tooling"},
        {"DEBUG-KEY", {}, {"android:debuggable", "ro.debuggable=1", "ro.secure=0"}, 1, "debuggable production build"},
    };

    std::string target = a.opt("path");
    if (target.empty() && !a.first().empty()) target = a.first();
    if (target.empty()) {
        ui::fail("pass a file or directory: argus sigmatch ./samples");
        ui::info("argus sigmatch ./samples --show-clean");
        return 1;
    }

    std::vector<std::string> files = globFiles({target}, {}, true);
    size_t maxBytes = (size_t)std::atoll(a.opt("max-size", "33554432").c_str());

    ui::kv("target", target);
    ui::kv("files", std::to_string(files.size()));
    ui::kv("rule set", std::to_string(sizeof(rules) / sizeof(SigRule)) + " rules");
    ui::line("");

    std::vector<std::vector<std::string>> rows;
    std::vector<Finding> fs;
    int hits = 0, scanned = 0, skipped = 0;

    for (auto& f : files) {
        uint64_t sz = fileSize(f);
        if (sz == 0 || sz > maxBytes) { ++skipped; continue; }
        std::string content;
        std::string err;
        if (!readTextFile(f, content, &err)) { ++skipped; continue; }
        if (content.empty()) continue;
        ++scanned;
        std::string lower = toLower(content);
        std::string magic = hexEncode((const uint8_t*)content.data(),
                                      std::min<size_t>(16, content.size()));

        std::vector<std::string> matched;
        for (auto& r : rules) {
            int score = 0;
            std::vector<std::string> why;
            for (auto& m : r.magic) {
                if (magic.find(toLower(m)) != std::string::npos) { ++score; break; }
            }
            size_t strHits = 0;
            std::vector<std::string> hitStrs;
            for (auto& s : r.strings) {
                std::string ls = toLower(s);
                bool found = ls.find("\\\\x") != std::string::npos
                                 ? icontains(content, s)
                                 : lower.find(ls) != std::string::npos;
                if (found) { ++strHits; hitStrs.push_back(s); }
            }
            if (strHits) { score += (strHits >= 2) ? 2 : 1; }
            if (score >= r.minScore && score > 0) {
                matched.push_back(r.name);
                std::string ev = "matched " + r.name + " (" + r.desc + ")";
                if (!hitStrs.empty()) {
                    std::string sample;
                    for (size_t i = 0; i < hitStrs.size() && i < 4; ++i)
                        sample += ui::truncateTo(hitStrs[i], 22) + " ";
                    ev += " indicators: " + sample;
                }
                fs.push_back({"S-" + r.name, ui::truncateTo(f, 40) + " :: " + ui::truncateTo(ev, 34),
                              r.name == "PE-EXE" || r.name == "ELF" || r.name == "PK-ZIP" ||
                                      r.name == "GZIP" || r.name == "PDF" ? 0 : 3});
                ++hits;
            }
        }
        if (matched.empty() && a.flag("show-clean"))
            rows.push_back({"clean", ui::truncateTo(f, 40), std::to_string(sz)});
        else if (!matched.empty())
            rows.push_back({join(matched, "+"), ui::truncateTo(f, 40), std::to_string(sz)});
    }

    if (!rows.empty()) ui::table({"MATCH", "FILE", "BYTES"}, rows);
    ui::line("");
    ui::kv("scanned", std::to_string(scanned));
    ui::kv("skipped (size/unreadable)", std::to_string(skipped));
    ui::kv("files with matches", std::to_string(hits));
    ui::line("");
    renderFindings(fs);
    ui::info("signature matches are indicators, not verdicts: verify against a known-good baseline");
    ui::line("");
    return fs.empty() ? 0 : 1;
}

}  // namespace

CK_TOOL("pcap", "forensics", "Read pcap/pcapng: protocol mix, talkers, port histograms, SYN-scan detection",
        "argus pcap --file capture.pcap [--detail]", runPcap);
CK_TOOL("sigmatch", "forensics", "YARA-lite rule engine for magic bytes, LOLBins, webshells, miner and injection strings",
        "argus sigmatch ./samples [--show-clean]", runSigMatch);