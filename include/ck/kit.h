#pragma once

#if !defined(NOMINMAX)
#  define NOMINMAX
#endif
#if !defined(WIN32_LEAN_AND_MEAN)
#  define WIN32_LEAN_AND_MEAN
#endif

#include <cstdint>
#include <cstddef>
#include <string>
#include <vector>
#include <functional>
#include <optional>

namespace ck {

// ---------------------------------------------------------------- platform
#if defined(_WIN32)
#  define CK_WINDOWS 1
#else
#  define CK_WINDOWS 0
#endif

// ------------------------------------------------------------------ bytes
using Bytes = std::vector<uint8_t>;

std::string hexEncode(const uint8_t* data, size_t len, const std::string& sep = "");
Bytes hexDecode(const std::string& hex);
std::string bytesToText(const Bytes& b, size_t max = 512);
bool isPrintable(const uint8_t* d, size_t n);
Bytes textToBytes(const std::string& s);

// ------------------------------------------------------------------ base64
std::string base64Encode(const Bytes& b, bool urlSafe = false, bool pad = true);
Bytes base64Decode(const std::string& s);
std::string base32Encode(const Bytes& b);
Bytes base32Decode(const std::string& s);
std::string base58Encode(const Bytes& b);
Bytes base58Decode(const std::string& s);

// ---------------------------------------------------------------- strings
std::string toLower(std::string s);
std::string toUpper(std::string s);
std::string trim(const std::string& s);
std::vector<std::string> split(const std::string& s, char sep);
std::vector<std::string> splitLines(const std::string& s);
std::string join(const std::vector<std::string>& parts, const std::string& sep);
bool startsWith(const std::string& s, const std::string& p);
bool endsWith(const std::string& s, const std::string& p);
bool icontains(const std::string& s, const std::string& needle);
std::string replaceAll(std::string s, const std::string& from, const std::string& to);
std::string regexFind(const std::string& s, const std::string& pattern,
                      size_t group = 0, size_t* outLen = nullptr,
                      std::string* allOut = nullptr, size_t maxMatches = 0);

// ---------------------------------------------------------------- entropy
double shannonEntropy(const uint8_t* d, size_t n);
double shannonEntropy(const std::string& s);
double chiSquare(const Bytes& b);
double compressionRatio(const Bytes& b);
std::string charsetAnalysis(const Bytes& b);
double compressionEstimate(const Bytes& b);

// ------------------------------------------------------------------- file
bool readFile(const std::string& path, Bytes& out, std::string* err = nullptr);
bool readTextFile(const std::string& path, std::string& out, std::string* err = nullptr);
bool writeFile(const std::string& path, const Bytes& b, std::string* err = nullptr);
bool writeTextFile(const std::string& path, const std::string& s, std::string* err = nullptr);
bool fileExists(const std::string& path);
uint64_t fileSize(const std::string& path);
bool listDir(const std::string& path, std::vector<std::string>& names, bool recursive = false,
             bool dirsOnly = false);
std::vector<std::string> globFiles(const std::vector<std::string>& roots,
                                   const std::vector<std::string>& exts,
                                   bool recursive = true);
std::string readStdin(size_t maxBytes = 16u * 1024 * 1024);

// -------------------------------------------------------------------- rng
void randomBytes(uint8_t* out, size_t n);
Bytes randomBytes(size_t n);
bool secureRandomAvailable();
uint32_t randomU32();
uint32_t randomRange(uint32_t loInclusive, uint32_t hiExclusive);
std::string randomHex(size_t bytes);
std::string uuidV4();
std::string secureToken(size_t bytes = 32);

// ------------------------------------------------------------------- hash
struct Digest {
    Bytes bytes;
    std::string hex() const { return hexEncode(bytes.data(), bytes.size()); }
    std::string b64() const { return base64Encode(bytes); }
};

struct HashSpec {
    std::string name;
    int digestSize = 0;
    int blockSize = 0;
    bool sha3 = false;
    bool legacy = false;
};

const std::vector<HashSpec>& allHashes();
const HashSpec* findHash(const std::string& name);
bool isKnownHashName(const std::string& name);

Digest hashBytes(const std::string& alg, const uint8_t* data, size_t len);
Digest hashBytes(const std::string& alg, const std::string& data);
Digest hashFile(const std::string& alg, const std::string& path, std::string* err = nullptr);

Digest hmacBytes(const std::string& alg, const Bytes& key, const uint8_t* msg, size_t len);
Digest hmacBytes(const std::string& alg, const Bytes& key, const std::string& msg);
std::string hmacHex(const std::string& alg, const std::string& key, const std::string& msg);

Bytes pbkdf2(const std::string& password, const Bytes& salt, int iterations, size_t dkLen,
             const std::string& prf = "sha256");

// -------------------------------------------------------------------- aes
namespace aes {
constexpr size_t kBlock = 16;
Bytes expandKey(const Bytes& key);
Bytes encryptBlock(const Bytes& roundKeys, const Bytes& block);
Bytes decryptBlock(const Bytes& roundKeys, const Bytes& block);

Bytes cbcEncrypt(const Bytes& key, const Bytes& iv, const Bytes& pt);
Bytes cbcDecrypt(const Bytes& key, const Bytes& iv, const Bytes& ct);
Bytes ctrCrypt(const Bytes& key, const Bytes& iv, const Bytes& in, uint64_t counter = 1);
Bytes ecbEncrypt(const Bytes& key, const Bytes& in);

struct GcmResult {
    Bytes ct;
    Bytes tag;
};
GcmResult gcmEncrypt(const Bytes& key, const Bytes& iv, const Bytes& pt,
                     const Bytes& aad = Bytes(), size_t tagSize = 16);
bool gcmDecrypt(const Bytes& key, const Bytes& iv, const Bytes& ct, const Bytes& tag,
                const Bytes& aad = Bytes(), Bytes* out = nullptr);

Bytes randomBytesOnly(size_t n);
std::string name();
size_t keyBitsFromName(const std::string& s);
}

// -------------------------------------------------------------------- net
struct IpAddr {
    int family = 0;
    uint8_t b[16] = {0};

    bool isV4() const { return family == 4; }
    bool valid() const { return family == 4 || family == 6; }
    std::string str() const;
    uint64_t toU64() const;
};

bool parseIp(const std::string& s, IpAddr& out);
bool isPrivateIp(const IpAddr& a);
bool isLoopbackIp(const IpAddr& a);
bool isLinkLocalIp(const IpAddr& a);

struct CidrBlock {
    IpAddr net;
    int prefix = 0;
    uint64_t count = 0;
    std::string str() const;
    IpAddr networkAddr() const;
    IpAddr broadcastAddr() const;
    IpAddr nth(uint64_t index) const;
};

bool parseCidr(const std::string& s, CidrBlock& out);
bool cidrContains(const CidrBlock& c, const IpAddr& a);
uint64_t enumerateCidr(const CidrBlock& c, const std::function<bool(const IpAddr&)>& fn);
std::vector<uint16_t> parsePortSpec(const std::string& spec);
std::vector<uint16_t> parsePortRange(const std::string& spec);
std::string serviceName(uint16_t port);

struct TcpResult {
    bool connected = false;
    int error = 0;
    double ms = 0;
    std::string banner;
};

void netInit();
void netShutdown();
bool tcpConnect(const std::string& host, uint16_t port, int timeoutMs, TcpResult& out,
                bool grabBanner = false, size_t bannerMax = 512);
bool udpProbe(const std::string& host, uint16_t port, int timeoutMs, Bytes& reply);
bool resolveHost(const std::string& host, std::vector<std::string>& ips);
std::string localHostName();
std::vector<std::string> dnsServers();
std::string reverseDns(const std::string& ip);

// ------------------------------------------------------------------- proc
std::string runCapture(const std::string& cmd, int timeoutMs = 20000, bool* ok = nullptr);
int runInteractive(const std::string& cmd);
std::string which(const std::string& exe);

// --------------------------------------------------------------------- ui
namespace ui {
bool colorEnabled();
void setColor(bool on);
bool unicodeOk();
void initConsole();
size_t displayWidth(const std::string& s);
std::string padTo(const std::string& s, size_t w);
std::string truncateTo(const std::string& s, size_t w);

std::string translit(const std::string& s);
void emit(const std::string& s);
void emitf(const char* fmt, ...);

void title(const std::string& s);
void section(const std::string& s);
void kv(const std::string& k, const std::string& v);
void line(const std::string& s);
void ok(const std::string& s);
void warn(const std::string& s);
void fail(const std::string& s);
void info(const std::string& s);
void bullet(const std::string& s);
void raw(const std::string& s);
void table(const std::vector<std::string>& headers, const std::vector<std::vector<std::string>>& rows);
void printCard(const std::string& t, const std::vector<std::string>& rows, int tone = 0);
std::string bar(double fraction, int width = 24);
double severityScore(int low, int med, int high, int crit);
std::string severityLabel(double score);
int severityColor(double score);
}

void progressBar(const std::string& label, size_t done, size_t total, int width = 30);
void spinnerStart(const std::string& msg);
void spinnerStop();

}  // namespace ck