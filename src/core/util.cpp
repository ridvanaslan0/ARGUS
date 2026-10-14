#include "ck/kit.h"

#include <algorithm>
#include <cmath>
#include <cstring>
#include <fstream>
#include <sstream>
#include <regex>
#include <filesystem>
#include <iostream>
#include <iomanip>

#if CK_WINDOWS
#  include <windows.h>
#  include <io.h>
#  include <fcntl.h>
#else
#  include <unistd.h>
#  include <dirent.h>
#  include <sys/stat.h>
#endif

namespace fs = std::filesystem;

namespace ck {

// ------------------------------------------------------------------ bytes
std::string hexEncode(const uint8_t* data, size_t len, const std::string& sep) {
    static const char* d = "0123456789abcdef";
    std::string out;
    out.reserve(len * (2 + sep.size()));
    for (size_t i = 0; i < len; ++i) {
        if (i && !sep.empty()) out += sep;
        out += d[data[i] >> 4];
        out += d[data[i] & 0xF];
    }
    return out;
}

static int hexVal(char c) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

Bytes hexDecode(const std::string& hex) {
    std::string s;
    s.reserve(hex.size());
    for (char c : hex) {
        if (c == ' ' || c == ':' || c == '-' || c == '\n' || c == '\r' || c == '\t') continue;
        s += c;
    }
    if (s.size() % 2) s.insert(s.begin(), '0');
    Bytes out;
    out.reserve(s.size() / 2);
    for (size_t i = 0; i + 1 < s.size(); i += 2) {
        int hi = hexVal(s[i]), lo = hexVal(s[i + 1]);
        if (hi < 0 || lo < 0) return Bytes();
        out.push_back((uint8_t)((hi << 4) | lo));
    }
    return out;
}

bool isPrintable(const uint8_t* d, size_t n) {
    for (size_t i = 0; i < n; ++i)
        if (d[i] < 0x20 || d[i] > 0x7E) return false;
    return true;
}

Bytes textToBytes(const std::string& s) {
    return Bytes(s.begin(), s.end());
}

std::string bytesToText(const Bytes& b, size_t max) {
    std::string out;
    size_t n = b.size();
    bool truncated = n > max;
    if (truncated) n = max;
    for (size_t i = 0; i < n; ++i) {
        uint8_t c = b[i];
        if (c == '\n') out += "\\n";
        else if (c == '\r') out += "\\r";
        else if (c == '\t') out += "\\t";
        else if (c == '\\') out += "\\\\";
        else if (c >= 0x20 && c < 0x7F) out += (char)c;
        else {
            char buf[8];
            snprintf(buf, sizeof(buf), "\\x%02x", c);
            out += buf;
        }
    }
    if (truncated) out += "...";
    return out;
}

// ------------------------------------------------------------------ base64
static const char* B64 = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
static const char* B64U = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
static const char* B32 = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
static const char* B58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

std::string base64Encode(const Bytes& b, bool urlSafe, bool pad) {
    const char* tbl = urlSafe ? B64U : B64;
    std::string out;
    size_t i = 0;
    while (i + 2 < b.size()) {
        uint32_t v = ((uint32_t)b[i] << 16) | ((uint32_t)b[i + 1] << 8) | b[i + 2];
        out += tbl[(v >> 18) & 63];
        out += tbl[(v >> 12) & 63];
        out += tbl[(v >> 6) & 63];
        out += tbl[v & 63];
        i += 3;
    }
    size_t rem = b.size() - i;
    if (rem == 1) {
        uint32_t v = (uint32_t)b[i] << 16;
        out += tbl[(v >> 18) & 63];
        out += tbl[(v >> 12) & 63];
        if (pad) out += "==";
    } else if (rem == 2) {
        uint32_t v = ((uint32_t)b[i] << 16) | ((uint32_t)b[i + 1] << 8);
        out += tbl[(v >> 18) & 63];
        out += tbl[(v >> 12) & 63];
        out += tbl[(v >> 6) & 63];
        if (pad) out += "=";
    }
    return out;
}

Bytes base64Decode(const std::string& s) {
    int rev[256];
    for (int i = 0; i < 256; ++i) rev[i] = -1;
    for (int i = 0; i < 64; ++i) rev[(uint8_t)B64[i]] = i;
    rev[(uint8_t)'-'] = 62;
    rev[(uint8_t)'_'] = 63;

    Bytes out;
    uint32_t buf = 0;
    int bits = 0;
    for (char c : s) {
        if (c == '=') break;
        int v = rev[(uint8_t)c];
        if (v < 0) continue;
        buf = (buf << 6) | (uint32_t)v;
        bits += 6;
        if (bits >= 8) {
            bits -= 8;
            out.push_back((uint8_t)((buf >> bits) & 0xFF));
        }
    }
    return out;
}

std::string base32Encode(const Bytes& b) {
    std::string out;
    uint32_t buf = 0;
    int bits = 0;
    for (uint8_t c : b) {
        buf = (buf << 8) | c;
        bits += 8;
        while (bits >= 5) {
            bits -= 5;
            out += B32[(buf >> bits) & 31];
        }
    }
    if (bits > 0) out += B32[(buf << (5 - bits)) & 31];
    while (out.size() % 8 != 0) out += '=';
    return out;
}

Bytes base32Decode(const std::string& s) {
    int rev[256];
    for (int i = 0; i < 256; ++i) rev[i] = -1;
    for (int i = 0; i < 32; ++i) rev[(uint8_t)B32[i]] = i;
    Bytes out;
    uint32_t buf = 0;
    int bits = 0;
    for (char c : s) {
        if (c == '=') continue;
        int v = rev[(uint8_t)c];
        if (v < 0) continue;
        buf = (buf << 5) | (uint32_t)v;
        bits += 5;
        if (bits >= 8) {
            bits -= 8;
            out.push_back((uint8_t)((buf >> bits) & 0xFF));
        }
    }
    return out;
}

std::string base58Encode(const Bytes& b) {
    size_t zeros = 0;
    while (zeros < b.size() && b[zeros] == 0) ++zeros;
    std::vector<uint8_t> num(b.begin() + zeros, b.end());
    std::string out;
    while (!num.empty()) {
        uint32_t carry = 0;
        for (size_t i = 0; i < num.size(); ++i) {
            uint32_t cur = carry * 256 + num[i];
            num[i] = (uint8_t)(cur / 58);
            carry = cur % 58;
        }
        out += B58[carry];
        while (!num.empty() && num.back() == 0) num.pop_back();
    }
    for (size_t i = 0; i < zeros; ++i) out += B58[0];
    std::reverse(out.begin(), out.end());
    return out;
}

Bytes base58Decode(const std::string& s) {
    Bytes out;
    size_t zeros = 0;
    while (zeros < s.size() && s[zeros] == B58[0]) ++zeros;
    std::vector<uint8_t> num;
    for (char c : s) {
        const char* p = strchr(B58, c);
        if (!p || c == 0) continue;
        uint32_t carry = (uint32_t)(p - B58);
        for (size_t i = 0; i < num.size(); ++i) {
            uint32_t cur = num[i] * 58 + carry;
            num[i] = (uint8_t)(cur & 0xFF);
            carry = cur >> 8;
        }
        while (carry) { num.push_back((uint8_t)(carry & 0xFF)); carry >>= 8; }
    }
    for (size_t i = 0; i < zeros; ++i) out.push_back(0);
    for (size_t i = num.size(); i > 0; --i) out.push_back(num[i - 1]);
    return out;
}

// ---------------------------------------------------------------- strings
std::string toLower(std::string s) {
    for (auto& c : s) c = (char)tolower((unsigned char)c);
    return s;
}

std::string toUpper(std::string s) {
    for (auto& c : s) c = (char)toupper((unsigned char)c);
    return s;
}

std::string trim(const std::string& s) {
    size_t a = s.find_first_not_of(" \t\r\n");
    if (a == std::string::npos) return "";
    size_t b = s.find_last_not_of(" \t\r\n");
    return s.substr(a, b - a + 1);
}

std::vector<std::string> split(const std::string& s, char sep) {
    std::vector<std::string> out;
    std::string cur;
    std::istringstream ss(s);
    while (std::getline(ss, cur, sep)) out.push_back(cur);
    if (!s.empty() && s.back() == sep) out.push_back("");
    return out;
}

std::vector<std::string> splitLines(const std::string& s) {
    std::vector<std::string> out;
    std::string cur;
    for (char c : s) {
        if (c == '\n') { if (!cur.empty() && cur.back() == '\r') cur.pop_back(); out.push_back(cur); cur.clear(); }
        else cur += c;
    }
    if (!cur.empty()) { if (cur.back() == '\r') cur.pop_back(); out.push_back(cur); }
    return out;
}

std::string join(const std::vector<std::string>& parts, const std::string& sep) {
    std::string out;
    for (size_t i = 0; i < parts.size(); ++i) {
        if (i) out += sep;
        out += parts[i];
    }
    return out;
}

bool startsWith(const std::string& s, const std::string& p) {
    return s.size() >= p.size() && s.compare(0, p.size(), p) == 0;
}

bool endsWith(const std::string& s, const std::string& p) {
    return s.size() >= p.size() && s.compare(s.size() - p.size(), p.size(), p) == 0;
}

bool icontains(const std::string& s, const std::string& needle) {
    if (needle.empty()) return true;
    return toLower(s).find(toLower(needle)) != std::string::npos;
}

std::string replaceAll(std::string s, const std::string& from, const std::string& to) {
    if (from.empty()) return s;
    size_t pos = 0;
    while ((pos = s.find(from, pos)) != std::string::npos) {
        s.replace(pos, from.size(), to);
        pos += to.size();
    }
    return s;
}

std::string regexFind(const std::string& s, const std::string& pattern, size_t group,
                      size_t* outLen, std::string* allOut, size_t maxMatches) {
    if (outLen) *outLen = 0;
    try {
        std::regex re(pattern, std::regex::ECMAScript | std::regex::optimize);
        auto begin = std::sregex_iterator(s.begin(), s.end(), re);
        auto end = std::sregex_iterator();
        std::string result;
        size_t count = 0;
        for (auto it = begin; it != end; ++it) {
            const std::smatch& m = *it;
            if (group < m.size()) {
                if (result.empty() && !allOut) result = m[group].str();
                if (outLen) *outLen = m[group].length();
                if (allOut && (maxMatches == 0 || count < maxMatches)) { *allOut += m[group].str(); *allOut += '\n'; }
            }
            ++count;
        }
        return result;
    } catch (...) {
        return "";
    }
}

// ---------------------------------------------------------------- entropy
double shannonEntropy(const uint8_t* d, size_t n) {
    if (n == 0) return 0;
    double freq[256] = {0};
    for (size_t i = 0; i < n; ++i) freq[d[i]] += 1.0;
    double h = 0;
    for (int i = 0; i < 256; ++i) {
        if (freq[i] == 0) continue;
        double p = freq[i] / (double)n;
        h -= p * std::log2(p);
    }
    return h;
}

double shannonEntropy(const std::string& s) {
    return shannonEntropy((const uint8_t*)s.data(), s.size());
}

double chiSquare(const Bytes& b) {
    if (b.empty()) return 0;
    double freq[256] = {0};
    for (uint8_t c : b) freq[c] += 1.0;
    double expected = (double)b.size() / 256.0;
    double chi = 0;
    for (int i = 0; i < 256; ++i) chi += (freq[i] - expected) * (freq[i] - expected) / expected;
    return chi;
}

static Bytes lz77Compress(const Bytes& in) {
    const size_t kHashSize = 1 << 15;
    const int kMinMatch = 3, kMaxMatch = 258, kWindow = 32768;
    std::vector<int> head(kHashSize, -1);
    std::vector<int> prev(in.size() ? in.size() : 1, -1);
    Bytes out;
    if (in.empty()) return out;
    size_t i = 0;
    while (i < in.size()) {
        size_t bestLen = 0, bestDist = 0;
        if (i + kMinMatch <= in.size()) {
            uint32_t h = ((uint32_t)in[i] << 10) ^ ((uint32_t)in[i + 1] << 5) ^ in[i + 2];
            h &= (kHashSize - 1);
            int cand = head[h];
            int tries = 0;
            while (cand >= 0 && tries < 32) {
                if (i - (size_t)cand > kWindow) break;
                size_t l = 0;
                while (l < kMaxMatch && i + l < in.size() && in[cand + l] == in[i + l]) ++l;
                if (l > bestLen) { bestLen = l; bestDist = i - (size_t)cand; }
                cand = prev[cand];
                ++tries;
            }
            prev[i] = head[h];
            head[h] = (int)i;
        }
        if (bestLen >= kMinMatch) {
            out.push_back((uint8_t)(bestLen - kMinMatch));
            out.push_back((uint8_t)(bestDist >> 8));
            out.push_back((uint8_t)(bestDist & 0xFF));
            for (size_t k = 0; k < bestLen; ++k) {
                size_t j = i + k;
                if (j + kMinMatch <= in.size()) {
                    uint32_t h = ((uint32_t)in[j] << 10) ^ ((uint32_t)in[j + 1] << 5) ^ in[j + 2];
                    h &= (kHashSize - 1);
                    prev[j] = head[h];
                    head[h] = (int)j;
                }
            }
            i += bestLen;
        } else {
            out.push_back(in[i]);
            ++i;
        }
    }
    return out;
}

double compressionRatio(const Bytes& b) {
    if (b.empty()) return 1.0;
    Bytes c = lz77Compress(b);
    if (c.size() >= b.size()) return 1.0;
    return (double)b.size() / (double)c.size();
}

double compressionEstimate(const Bytes& b) {
    return compressionRatio(b);
}

std::string charsetAnalysis(const Bytes& b) {
    size_t printable = 0, upper = 0, lower = 0, digit = 0, punct = 0, ctrl = 0, high = 0;
    for (uint8_t c : b) {
        if (c == 0) { ctrl++; continue; }
        if (c < 0x20 || c == 0x7F) ctrl++;
        else if (c >= 0x80) high++;
        else if ((c >= 'A' && c <= 'Z')) { printable++; upper++; }
        else if ((c >= 'a' && c <= 'z')) { printable++; lower++; }
        else if (c >= '0' && c <= '9') { printable++; digit++; }
        else { printable++; punct++; }
    }
    size_t n = b.size() ? b.size() : 1;
    char buf[256];
    snprintf(buf, sizeof(buf),
             "printable=%.1f%% upper=%.1f%% lower=%.1f%% digits=%.1f%% punct=%.1f%% ctrl=%.1f%% high=%.1f%%",
             printable * 100.0 / n, upper * 100.0 / n, lower * 100.0 / n, digit * 100.0 / n,
             punct * 100.0 / n, ctrl * 100.0 / n, high * 100.0 / n);
    return buf;
}

// ------------------------------------------------------------------- file
bool readFile(const std::string& path, Bytes& out, std::string* err) {
    std::ifstream f(path, std::ios::binary);
    if (!f) { if (err) *err = "cannot open: " + path; return false; }
    out.assign(std::istreambuf_iterator<char>(f), std::istreambuf_iterator<char>());
    return true;
}

bool readTextFile(const std::string& path, std::string& out, std::string* err) {
    Bytes b;
    if (!readFile(path, b, err)) return false;
    out.assign(b.begin(), b.end());
    return true;
}

bool writeFile(const std::string& path, const Bytes& b, std::string* err) {
    std::ofstream f(path, std::ios::binary);
    if (!f) { if (err) *err = "cannot write: " + path; return false; }
    if (!b.empty()) f.write((const char*)b.data(), (std::streamsize)b.size());
    return true;
}

bool writeTextFile(const std::string& path, const std::string& s, std::string* err) {
    return writeFile(path, textToBytes(s), err);
}

bool fileExists(const std::string& path) {
    std::error_code ec;
    return fs::exists(path, ec) && !fs::is_directory(path, ec);
}

uint64_t fileSize(const std::string& path) {
    std::error_code ec;
    auto sz = fs::file_size(path, ec);
    return ec ? 0 : (uint64_t)sz;
}

bool listDir(const std::string& path, std::vector<std::string>& names, bool recursive,
             bool dirsOnly) {
    std::error_code ec;
    if (!fs::exists(path, ec)) return false;
    if (fs::is_directory(path, ec)) {
        for (auto& e : fs::directory_iterator(path, fs::directory_options::skip_permission_denied, ec)) {
            if (dirsOnly && !e.is_directory(ec)) continue;
            names.push_back(e.path().string());
            if (recursive && e.is_directory(ec)) listDir(e.path().string(), names, true, dirsOnly);
        }
        std::sort(names.begin(), names.end());
        return true;
    }
    names.push_back(path);
    return true;
}

std::vector<std::string> globFiles(const std::vector<std::string>& roots,
                                   const std::vector<std::string>& exts,
                                   bool recursive) {
    std::vector<std::string> out;
    std::vector<std::string> all;
    for (auto& r : roots) listDir(r, all, recursive, false);
    for (auto& p : all) {
        if (exts.empty()) { out.push_back(p); continue; }
        std::string low = toLower(p);
        for (auto& e : exts)
            if (endsWith(low, e)) { out.push_back(p); break; }
    }
    return out;
}

std::string readStdin(size_t maxBytes) {
    std::string out;
#if CK_WINDOWS
    for (size_t i = 0; i < maxBytes; ++i) {
        int c = fgetc(stdin);
        if (c == EOF) break;
        out += (char)c;
    }
#else
    char buf[65536];
    size_t n;
    while (out.size() < maxBytes && (n = fread(buf, 1, sizeof(buf), stdin)) > 0)
        out.append(buf, n);
#endif
    return out;
}

}  // namespace ck