#include "common.h"

#include <cstring>

using namespace ck;
using namespace ck::tools;

namespace {

std::vector<std::string> inputText(const Args& a) {
    std::string file = a.opt("file");
    if (!file.empty()) {
        std::string content;
        std::string err;
        if (!readTextFile(file, content, &err)) {
            ui::fail(err);
            return {};
        }
        return splitLines(content);
    }
    if (a.flag("stdin") || a.all().empty()) return splitLines(readStdin());
    return {a.first()};
}

int runHash(const Args& a) {
    ui::section("DIGEST ENGINE");

    std::vector<std::string> algs;
    if (a.hasOpt("alg")) algs = split(a.opt("alg"), ',');
    if (algs.empty()) algs = {"sha256"};

    Bytes dataBytes;
    std::string label;
    std::string file = a.opt("file");
    if (!file.empty()) {
        std::string err;
        if (!readFile(file, dataBytes, &err)) {
            ui::fail(err);
            return 1;
        }
        label = file;
    } else {
        std::string s = a.opt("data");
        if (s.empty()) s = a.first();
        if (s.empty()) s = readStdin();
        dataBytes = textToBytes(s);
        label = "string";
    }

    ui::kv("source", label + "  (" + std::to_string(dataBytes.size()) + " bytes)");
    ui::kv("algorithms", join(algs, ", "));
    ui::line("");

    for (auto& alg : algs) {
        const HashSpec* spec = findHash(alg);
        if (!spec) {
            ui::fail("unknown algorithm: " + alg);
            continue;
        }
        Digest d = hashBytes(spec->name, dataBytes.data(), dataBytes.size());
        std::string note = spec->legacy ? "  \033[38;5;214mlegacy / collision-prone\033[0m"
                                       : spec->sha3 ? "  \033[38;5;46msha3 (keccak)\033[0m"
                                                    : "  \033[38;5;250mstandard\033[0m";
        ui::kv(spec->name, d.hex() + note);
        if (a.flag("b64")) ui::kv(spec->name + " b64", d.b64());
    }
    ui::line("");
    ui::info("algorithms available: md5 sha1 sha224 sha256 sha384 sha512 sha3-224 sha3-256 sha3-384 sha3-512");
    ui::line("");
    return 0;
}

int runHashId(const Args& a) {
    ui::section("HASH IDENTIFIER");
    auto inputs = inputText(a);
    if (inputs.empty()) {
        ui::warn("no input; pass a hash string or --file hashes.txt");
        return 1;
    }

    static const struct { size_t len; const char* name; } table[] = {
        {16, "md5-half / crc64"}, {32, "md5 / sha256-half / blake2s-128 / argon2i"},
        {40, "sha1 / ripemd160 / has160"}, {56, "sha224 / sha3-224 / blake2s-224"},
        {64, "sha256 / sha3-256 / blake2s / argon2i"},
        {96, "sha384 / sha3-384 / blake2b-384"},
        {128, "sha512 / sha3-512 / blake2b-512"},
    };

    for (auto& raw : inputs) {
        std::string s = trim(raw);
        if (s.empty()) continue;

        bool hexLike = true;
        for (char c : s)
            if (!isxdigit((unsigned char)c) && c != ' ' && c != ':' && c != '-') hexLike = false;

        size_t len = hexLike ? hexDecode(s).size() : s.size();
        if (!hexLike && !s.empty() && s[0] == '$') {
            if (startsWith(s, "$2") || startsWith(s, "$argon2")) {
                ui::kv("input", ui::truncateTo(s, 58));
                ui::kv("type", "password hash (modular crypt format)");
                ui::line("");
                if (startsWith(s, "$2")) {
                    int cost = 10;
                    size_t l = 0;
                    std::string c = regexFind(s, "\\$2[aby]\\$(\\d+)\\$", 1, &l);
                    if (!c.empty()) cost = std::atoi(c.c_str());
                    ui::ok("bcrypt, cost factor " + std::to_string(cost));
                    if (cost < 10) ui::warn("bcrypt cost " + std::to_string(cost) + " is weak, use >= 12");
                } else {
                    ui::ok("argon2 - memory-hard KDF");
                }
                ui::line("");
                continue;
            }
            if (startsWith(s, "$6$") || startsWith(s, "$5$") || startsWith(s, "$1$")) {
                ui::kv("input", ui::truncateTo(s, 58));
                ui::kv("type", "unix modular crypt string");
                ui::line("");
                if (startsWith(s, "$1$")) ui::fail("$1$ = md5crypt, cryptographically obsolete");
                else ui::ok("sha-crypt variant");
                ui::line("");
                continue;
            }
        }

        std::vector<std::vector<std::string>> rows;
        for (auto& t : table)
            if (t.len == len) rows.push_back({t.name, std::to_string(len), hexLike ? "hex" : "text"});

        ui::kv("input", ui::truncateTo(s, 58));
        ui::kv("length", std::to_string(len) + " bytes");
        ui::kv("form", hexLike ? "hex" : "text");
        ui::line("");

        std::vector<Finding> fs;
        if (rows.empty()) {
            ui::warn("no common algorithm produces " + std::to_string(len) + " bytes");
            fs.push_back({"H-UNKNOWN", "length does not match any standard digest", 2});
        } else {
            ui::table({"CANDIDATE", "BYTES", "FORM"}, rows);
        }

        if (len == 32) fs.push_back({"H-MD5-LEN", "32 bytes also matches MD5, which has practical collisions", 3});
        if (len == 40) fs.push_back({"H-SHA1-LEN", "40 bytes matches SHA-1, collisions demonstrated (2017)", 3});
        if (hexLike && s.size() >= 32) {
            size_t ones = 0;
            for (auto c : s) if (c == '1') ++ones;
            double frac = (double)ones / s.size();
            if (frac > 0.62 || frac < 0.38)
                fs.push_back({"H-BIAS", "skewed hex nibble distribution (" + fmt(frac * 100, 1) +
                                            "% ones): not a well-formed digest", 2});
        }
        if (len == 128 && !fs.empty()) {
            fs.push_back({"H-SHA512", "512-bit digest: acceptable for integrity and signatures", 0});
        }

        ui::line("");
        renderFindings(fs);
    }
    return 0;
}

int runHmac(const Args& a) {
    ui::section("HMAC");

    std::string key = a.opt("key");
    Bytes keyBytes;
    bool keyIsHex = a.hasOpt("key-hex");
    if (keyIsHex) keyBytes = hexDecode(a.opt("key-hex"));
    else if (!key.empty()) keyBytes = textToBytes(key);

    if (keyBytes.empty()) {
        keyBytes = textToBytes(readSecret("key (input hidden): "));
    }
    if (keyBytes.empty()) {
        ui::fail("key required (--key, --key-hex or interactive prompt)");
        return 1;
    }

    Bytes msgBytes;
    std::string file = a.opt("file");
    if (!file.empty()) {
        std::string err;
        if (!readFile(file, msgBytes, &err)) { ui::fail(err); return 1; }
    } else {
        std::string m = a.opt("msg");
        if (m.empty()) m = a.first();
        if (m.empty()) m = readStdin();
        msgBytes = textToBytes(m);
    }

    std::vector<std::string> algs;
    if (a.hasOpt("alg")) algs = split(a.opt("alg"), ',');
    if (algs.empty()) algs = {"sha256"};

    ui::kv("key", std::to_string(keyBytes.size()) + " bytes " + (keyIsHex ? "(hex)" : "(raw)"));
    ui::kv("message", ui::truncateTo(std::string(msgBytes.begin(), msgBytes.end()), 54) + "  (" +
                          std::to_string(msgBytes.size()) + " bytes)");
    ui::line("");

    for (auto& an : algs) {
        const HashSpec* spec = findHash(an);
        if (!spec) { ui::fail("unknown algorithm " + an); continue; }
        ui::kv(spec->name, hmacBytes(spec->name, keyBytes, msgBytes.data(), msgBytes.size()).hex());
    }
    ui::line("");

    std::vector<Finding> fs;
    if (keyBytes.size() < 16) fs.push_back({"HMAC-KEY-SHORT", "key under 16 bytes: brute-forceable offline", 2});
    else if (keyBytes.size() < 32) fs.push_back({"HMAC-KEY-OK", "key length acceptable; >= 32 bytes is better", 0});
    else fs.push_back({"HMAC-KEY-STRONG", std::to_string(keyBytes.size()) + "-byte key", 0});
    if (keyBytes.size() > 128) fs.push_back({"HMAC-KEY-LONG", "keys over block size are hashed first; prefer HKDF", 1});
    if (keyBytes.size() < 32)
        fs.push_back({"HMAC-NIST", "NIST SP 800-107 recommends >= 112-bit keys", 1});
    renderFindings(fs, false);

    ui::info("verify: argus hmac --key <k> --msg <m> --alg sha256  |  compare hex");
    ui::line("");
    return 0;
}

int runCodec(const Args& a) {
    ui::section("CODEC");

    std::string dec = toLower(a.opt("dec"));
    std::string e = toLower(a.opt("enc", dec.empty() ? "base64" : "base64"));

    std::string input;
    if (a.hasOpt("in")) input = a.opt("in");
    else if (!a.first().empty()) input = a.first();
    else input = readStdin();
    if (a.flag("stdin") && a.first().empty()) input = readStdin();

    if (input.empty()) {
        ui::fail("no input");
        ui::info("usage: argus codec --enc base64 \"hello\"  |  argus codec --dec base64 \"aGVsbG8=\"");
        return 1;
    }

    if (!dec.empty()) {
        Bytes out;
        std::string kind = dec;
        if (dec == "base64" || dec == "b64") out = base64Decode(input);
        else if (dec == "base64url" || dec == "b64url" || dec == "url") out = base64Decode(input);
        else if (dec == "base32") out = base32Decode(input);
        else if (dec == "base58") out = base58Decode(input);
        else if (dec == "hex") out = hexDecode(input);
        else if (dec == "raw") out = textToBytes(input);
        else { ui::fail("unknown encoding: " + dec); return 1; }

        ui::kv("mode", "decode " + kind);
        ui::kv("input", ui::truncateTo(input, 56) + "  (" + std::to_string(input.size()) + " chars)");
        ui::kv("output", std::to_string(out.size()) + " bytes");
        ui::line("");
        if (out.empty()) {
            ui::warn("decoded to zero bytes (invalid input?)");
        } else if (isPrintable(out.data(), out.size())) {
            ui::line("  " + std::string(out.begin(), out.end()));
        } else {
            ui::line("  " + hexEncode(out.data(), std::min<size_t>(out.size(), 256), " "));
            if (out.size() > 256) ui::line("  ... (" + std::to_string(out.size() - 256) + " more bytes)");
        }
        ui::line("");
        ui::info("charset: " + charsetAnalysis(out));
        return 0;
    }

    Bytes in = (e == "hex") ? hexDecode(input) : textToBytes(input);
    std::string out;
    if (e == "base64" || e == "b64") out = base64Encode(in, false, true);
    else if (e == "base64url" || e == "b64url" || e == "url") out = base64Encode(in, true, false);
    else if (e == "base32") out = base32Encode(in);
    else if (e == "base58") out = base58Encode(in);
    else if (e == "hex") out = hexEncode(in.data(), in.size(), a.opt("sep", " "));
    else if (e == "raw") out = std::string(in.begin(), in.end());
    else if (e == "urlencode") {
        static const char* h = "0123456789ABCDEF";
        for (unsigned char c : in) {
            if (isalnum(c) || c == '-' || c == '_' || c == '.' || c == '~') out += (char)c;
            else { out += '%'; out += h[c >> 4]; out += h[c & 15]; }
        }
    } else {
        ui::fail("unknown encoding: " + e);
        ui::info("supported: base64 base64url base32 base58 hex raw urlencode");
        return 1;
    }

    ui::kv("mode", "encode " + e);
    ui::kv("input", std::to_string(in.size()) + " bytes");
    ui::kv("output", std::to_string(out.size()) + " chars");
    ui::line("");
    ui::line("  " + out);
    ui::line("");
    return 0;
}

int runEntropy(const Args& a) {
    ui::section("ENTROPY / RANDOMNESS FORENSICS");

    Bytes data;
    std::string label;
    std::string file = a.opt("file");
    if (!file.empty()) {
        std::string err;
        if (!readFile(file, data, &err)) { ui::fail(err); return 1; }
        label = file;
    } else {
        std::string s;
        if (a.hasOpt("in")) s = a.opt("in");
        else if (!a.first().empty()) s = a.first();
        else s = readStdin();
        data = textToBytes(s);
        label = "string/stdin";
    }

    if (data.empty()) {
        ui::fail("no input");
        return 1;
    }

    double h = shannonEntropy(data.data(), data.size());
    double chi = chiSquare(data);
    double cr = compressionRatio(data);

    ui::kv("source", label);
    ui::kv("size", std::to_string(data.size()) + " bytes");
    ui::kv("shannon entropy", fmt(h, 4) + " bits/byte   max 8.0");
    ui::kv("entropy fill", ui::bar(h / 8.0, 34));
    ui::kv("chi-square", fmt(chi, 2) + "     uniform random ~255, english text ~3000+");
    ui::kv("compressibility", fmt(cr, 2) + "x   (lz77 estimate)");
    ui::kv("charset", charsetAnalysis(data));
    ui::line("");

    std::vector<Finding> fs;
    if (data.size() >= 64) {
        if (h > 7.5) {
            fs.push_back({"E-OPAQUE", "entropy " + fmt(h, 2) + ": no structure, consistent with encryption or CSPRNG output", 1});
        } else if (h < 4.0) {
            fs.push_back({"E-PLAIN", "entropy " + fmt(h, 2) + ": highly predictable, plaintext or fixed records", 0});
        } else if (h < 6.0) {
            fs.push_back({"E-MIXED", "entropy " + fmt(h, 2) + ": binary container or light obfuscation", 1});
        } else {
            fs.push_back({"E-BALANCED", "entropy " + fmt(h, 2) + ": typical compressed or mixed content", 0});
        }
        if (cr > 3.0)
            fs.push_back({"E-PACKED", "compresses " + fmt(cr, 1) + "x: packed, compressed, or encoded payload", 2});
        if (chi > 400)
            fs.push_back({"E-CHI2", "byte distribution skewed (chi2=" + fmt(chi, 0) + "): not uniform", 2});
    } else {
        fs.push_back({"E-SMALL", "sample under 64 bytes; entropy statistics are unreliable", 1});
    }
    for (size_t i = 0; i + 4 < data.size(); i += 4) {
        if (data[i] == 0 && data[i + 1] == 0 && data[i + 2] == 0 && data[i + 3] == 0) {
            fs.push_back({"E-NULLRUN", "4-byte null run at offset " + std::to_string(i) + ": padding or sparse file", 1});
            break;
        }
    }

    renderFindings(fs);
    return 0;
}

}  // namespace

CK_TOOL("hash", "cryptography", "Compute MD5/SHA-1/SHA-2/SHA-3 digests of strings or files",
        "argus hash --alg sha256,sha512 [--file <path> | <string> | --stdin]", runHash);
CK_TOOL("hash-id", "cryptography", "Identify which algorithm produced a hash, with collision-risk flags",
        "argus hash-id <hash>  |  argus hash-id --file hashes.txt", runHashId);
CK_TOOL("hmac", "cryptography", "HMAC over any supported digest, with key-strength guidance",
        "argus hmac --key <secret> [--msg <text> | --file <path>] [--alg sha256,sha512]",
        runHmac);
CK_TOOL("codec", "cryptography", "base64 / base64url / base32 / base58 / hex / urlencode codec",
        "argus codec --enc base64 <text>  |  argus codec --dec base64 <b64>", runCodec);
CK_TOOL("entropy", "cryptography", "Shannon entropy, chi-square and packer/compression forensics",
        "argus entropy [--file <path> | <string> | --stdin]", runEntropy);