#pragma once

#include "ck/tool.h"
#include "ck/kit.h"

#include <algorithm>
#include <cctype>
#include <cstdio>
#include <cstdlib>
#include <cmath>
#include <iostream>

#if CK_WINDOWS
#  include <windows.h>
#else
#  include <termios.h>
#  include <unistd.h>
#endif

namespace ck {
namespace tools {

inline std::string fmt(double v, int prec = 3) {
    char buf[64];
    snprintf(buf, sizeof(buf), "%.*f", prec, v);
    return std::string(buf);
}

inline std::string fmtLong(double v) {
    char buf[64];
    snprintf(buf, sizeof(buf), "%lld", (long long)v);
    return std::string(buf);
}

inline bool allHexDigits(const std::string& s) {
    if (s.empty()) return false;
    for (char c : s)
        if (!isxdigit((unsigned char)c)) return false;
    return true;
}

inline bool isAllZero(const Bytes& b) {
    for (uint8_t c : b) if (c) return false;
    return true;
}

struct Finding {
    std::string id;
    std::string text;
    int sev;
};

inline std::vector<std::vector<std::string>> findingRows(const std::vector<Finding>& fs) {
    std::vector<std::vector<std::string>> rows;
    for (auto& f : fs) {
        const char* lvl = f.sev == 0 ? "LOW" : f.sev == 1 ? "MED" : f.sev == 2 ? "HIGH" : "CRIT";
        rows.push_back({lvl, f.id, ui::truncateTo(f.text, 50)});
    }
    return rows;
}

inline void counts(const std::vector<Finding>& fs, int& low, int& med, int& high, int& crit) {
    low = med = high = crit = 0;
    for (auto& f : fs) {
        if (f.sev == 0) ++low;
        else if (f.sev == 1) ++med;
        else if (f.sev == 2) ++high;
        else ++crit;
    }
}

inline void renderFindings(const std::vector<Finding>& fs, bool withTable = true) {
    if (fs.empty()) {
        ui::ok("no findings");
        return;
    }
    if (withTable) ui::table({"LVL", "ID", "FINDING"}, findingRows(fs));
    int low, med, high, crit;
    counts(fs, low, med, high, crit);
    double score = ui::severityScore(low, med, high, crit);
    if (score > 100) score = 100;
    ui::line("");
    ui::kv("findings", std::to_string(fs.size()) + "   low " + std::to_string(low) + " / med " +
                          std::to_string(med) + " / high " + std::to_string(high) +
                          " / crit " + std::to_string(crit));
    ui::kv("risk score", fmtLong(score) + " / 100");
    ui::kv("severity", ui::severityLabel(score));
    ui::line("  " + ui::bar(score / 100.0, 40));
    ui::line("");
}

inline void reportFinding(const Finding& f) {
    if (f.sev == 0) ui::ok(f.id + ": " + f.text);
    else if (f.sev == 1) ui::warn(f.id + ": " + f.text);
    else if (f.sev == 2) ui::warn(f.id + ": " + f.text);
    else ui::fail(f.id + ": " + f.text);
}

inline std::vector<std::string> readLinesOrStdin(const Args& a, const char* flagName = "file") {
    std::string file = a.opt(flagName);
    if (file.empty()) {
        std::string all = readStdin();
        return splitLines(all);
    }
    std::string content;
    std::string err;
    if (!readTextFile(file, content, &err)) {
        ui::fail(err);
        return {};
    }
    return splitLines(content);
}

inline std::string allowListPath() {
#if CK_WINDOWS
    const char* h = getenv("USERPROFILE");
#else
    const char* h = getenv("HOME");
#endif
    std::string home = h ? h : ".";
    return home + "/.argus/allow.txt";
}

inline bool targetAllowed(const std::string& host) {
    IpAddr ip;
    if (parseIp(host, ip) && (isLoopbackIp(ip) || isPrivateIp(ip))) return true;
    std::string content;
    if (!readTextFile(allowListPath(), content)) return false;
    for (auto& l : splitLines(content)) {
        std::string e = trim(l);
        if (e.empty() || e[0] == '#') continue;
        if (e == "*" || e == host) return true;
        if (e.find('*') != std::string::npos) {
            std::string pat;
            for (size_t i = 0; i < e.size(); ++i) {
                if (e[i] == '*') { pat += '\x01'; continue; }
                pat += (char)tolower((unsigned char)e[i]);
            }
            std::string h = toLower(host);
            size_t p = 0;
            for (char c : pat) {
                if (c == '\x01') { if (p >= h.size()) return false; continue; }
                if (p >= h.size() || h[p] != c) return false;
                ++p;
            }
        }
    }
    return false;
}

inline bool requireAuthorization(const Args& a, const std::string& host) {
    if (a.flag("i-own-this")) return true;
    if (targetAllowed(host)) return true;
    ui::line("");
    ui::fail("REFUSING to scan a non-local host without explicit authorization");
    ui::line("");
    ui::kv("target", host);
    ui::line("  Only scan systems you own or have written permission to test.");
    ui::line("  Re-run with " + std::string("\033[38;5;250m--i-own-this\033[0m") +
             " once you have that permission in writing,");
    ui::line("  or add the host to " + std::string("\033[38;5;250m~/.argus/allow.txt\033[0m") + ".");
    ui::line("");
    return false;
}

inline std::string readSecret(const std::string& prompt) {
    fputs(("  " + std::string("\033[38;5;250m") + prompt + "\033[0m").c_str(), stdout);
    fflush(stdout);
    std::string k;
#if CK_WINDOWS
    char buf[2048];
    DWORD n = 0;
    HANDLE hin = GetStdHandle(STD_INPUT_HANDLE);
    DWORD mode = 0;
    GetConsoleMode(hin, &mode);
    SetConsoleMode(hin, mode & ~ENABLE_ECHO_INPUT);
    if (ReadConsoleA(hin, buf, sizeof(buf) - 1, &n, nullptr)) k.assign(buf, n);
    SetConsoleMode(hin, mode);
    while (!k.empty() && (k.back() == '\r' || k.back() == '\n')) k.pop_back();
#else
    struct termios oldt, newt;
    tcgetattr(STDIN_FILENO, &oldt);
    newt = oldt;
    newt.c_lflag &= (tcflag_t)~ECHO;
    tcsetattr(STDIN_FILENO, TCSANOW, &newt);
    std::getline(std::cin, k);
    tcsetattr(STDIN_FILENO, TCSANOW, &oldt);
#endif
    fputs("\n", stdout);
    return k;
}

inline int popcount8(uint8_t v) {
    static const int table[16] = {0,1,1,2,1,2,2,3,1,2,2,3,2,3,3,4};
    return table[v & 0x0F] + table[v >> 4];
}

inline double levenShannon(const std::string& s) {
    double total = 0;
    size_t n = s.size();
    for (size_t i = 0; i < n; ++i) {
        double p = 0;
        for (size_t j = std::max<size_t>(i, n - 20); j < n; ++j)
            if (s[j] == s[i]) ++p;
        p /= (double)(n - std::max<size_t>(i, n - 20));
        if (p > 0) total -= p * std::log2(p);
    }
    return total;
}

inline std::string pwMask(const std::string& pw) {
    std::string out;
    for (size_t i = 0; i < pw.size(); ++i) {
        char c = pw[i];
        if (isdigit((unsigned char)c) && pw.size() > 2 && i >= 2) out += c;
        else out += '*';
    }
    return out;
}

inline Bytes readInputBytes(const Args& a) {
    std::string file = a.opt("file");
    if (!file.empty()) {
        Bytes b;
        std::string err;
        if (!readFile(file, b, &err)) ui::fail(err);
        return b;
    }
    if (a.flag("stdin") || a.all().empty()) return textToBytes(readStdin());
    return textToBytes(a.first());
}

}  // namespace tools
}  // namespace ck