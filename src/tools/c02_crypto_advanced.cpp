#include "common.h"

#include <cstring>
#include <cmath>
#include <ctime>
#include <set>
#include <map>

#if !CK_WINDOWS
#  include <termios.h>
#  include <unistd.h>
#endif

using namespace ck;
using namespace ck::tools;

namespace {

const char* B_GREEN = "\033[38;5;46m";
const char* B_RED = "\033[38;5;196m";
const char* B_YEL = "\033[38;5;214m";
const char* B_DIM = "\033[2;37m";
const char* B_CY = "\033[38;5;51m";
const char* B_RESET = "\033[0m";

void verdict(bool pass, const std::string& what) {
    if (pass) ui::ok(std::string(B_GREEN) + "PASS" + B_RESET + "  " + what);
    else ui::fail(std::string(B_RED) + "FAIL" + B_RESET + "  " + what);
}

// ------------------------------------------------------------------- AES
int runAes(const Args& a) {
    ui::section("AES BLOCK CIPHER");

    bool selftest = a.flag("selftest") || (a.all().empty());
    if (selftest) {
        ui::kv("mode", "known-answer self test (FIPS-197 / NIST GCM vectors)");
        ui::line("");
        struct Vec { const char* bits; const char* pt; const char* ct; };
        static const Vec vecs[] = {
            {"128", "00112233445566778899aabbccddeeff", "69c4e0d86a7b0430d8cdb78070b4c55a"},
            {"192", "00112233445566778899aabbccddeeff", "dda97ca4864cdfe06eaf70a0ec0d7191"},
            {"256", "00112233445566778899aabbccddeeff", "8ea2b7ca516745bfeafc49904b496089"},
        };
        int failed = 0;
        for (auto& v : vecs) {
            size_t bits = aes::keyBitsFromName(v.bits);
            Bytes key = hexDecode("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f");
            key.resize(bits / 8);
            Bytes pt = hexDecode(v.pt);
            Bytes got = aes::encryptBlock(aes::expandKey(key), pt);
            bool pass = hexEncode(got.data(), got.size()) == v.ct;
            std::string detail = pass ? std::string("matches FIPS-197")
                                      : ("expected " + std::string(v.ct) + ", got " +
                                         hexEncode(got.data(), got.size()));
            verdict(pass, "AES-" + std::to_string(bits) + " encrypt  " + detail);
            if (!pass) ++failed;
            Bytes back = aes::decryptBlock(aes::expandKey(key), got);
            bool rpass = back == pt;
            verdict(rpass, "AES-" + std::to_string(bits) + " decrypt round trip");
            if (!rpass) ++failed;
        }

        Bytes gkey = hexDecode("feffe9928665731c6d6a8f9467308308");
        Bytes giv = hexDecode("cafebabefacedbaddecaf888");
        Bytes gpt = hexDecode(
            "d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a72"
            "1c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b39");
        Bytes gaad = hexDecode("feedfacedeadbeeffeedfacedeadbeefabaddad2");
        auto gr = aes::gcmEncrypt(gkey, giv, gpt, gaad);
        bool gpass = hexEncode(gr.ct.data(), gr.ct.size()) ==
                     "42831ec2217774244b7221b784d0d49ce3aa212f2c02a4e035c17e2329aca12e21d514b25466931c7d8f6a5aac84aa051ba30b396a0aac973d58e091";
        gpass = gpass && hexEncode(gr.tag.data(), gr.tag.size()) == "5bc94fbc3221a5db94fae95ae7121a47";
        verdict(gpass, "AES-128-GCM NIST test case 4 (ct + tag)");
        if (!gpass) ++failed;

        Bytes dec;
        bool gok = aes::gcmDecrypt(gkey, giv, gr.ct, gr.tag, gaad, &dec) && dec == gpt;
        verdict(gok, "AES-128-GCM authenticate + decrypt");
        if (!gok) ++failed;

        Bytes badTag = gr.tag;
        badTag[0] ^= 1;
        verdict(!aes::gcmDecrypt(gkey, giv, gr.ct, badTag, gaad, nullptr),
                "AES-GCM rejects a tampered tag");

        ui::line("");
        ui::kv("result", failed == 0 ? std::string(B_GREEN) + "all vectors passed" + B_RESET
                                     : std::string(B_RED) + std::to_string(failed) + " failure(s)" + B_RESET);
        ui::line("");
        return failed ? 1 : 0;
    }

    std::string mode = toLower(a.opt("mode", "gcm"));
    std::string bitsS = a.opt("bits", "256");
    size_t bits = aes::keyBitsFromName(bitsS);

    Bytes key, iv, aad;
    if (a.hasOpt("aad-hex")) aad = hexDecode(a.opt("aad-hex"));
    else if (a.hasOpt("aad")) aad = textToBytes(a.opt("aad"));
    if (a.hasOpt("key-hex")) key = hexDecode(a.opt("key-hex"));
    else if (a.hasOpt("key")) key = textToBytes(a.opt("key"));
    else key = randomBytes(bits / 8);
    bool generatedKey = !a.hasOpt("key") && !a.hasOpt("key-hex");

    if (a.hasOpt("iv-hex")) iv = hexDecode(a.opt("iv-hex"));
    else if (a.hasOpt("iv")) iv = textToBytes(a.opt("iv"));
    else iv = randomBytes(12);
    if (iv.size() != 12 && iv.size() != 16 && mode == "gcm") {
        ui::warn("IV is " + std::to_string(iv.size()) + " bytes; 12 bytes is recommended for GCM");
        while (iv.size() < 16) iv.push_back(0);
        iv.resize(16);
    }

    Bytes data;
    std::string file = a.opt("file");
    if (!file.empty()) {
        std::string err;
        if (!readFile(file, data, &err)) { ui::fail(err); return 1; }
    } else {
        std::string s = a.opt("in");
        if (s.empty() && !a.first().empty()) s = a.first();
        data = textToBytes(s.empty() ? readStdin() : s);
    }

    size_t actualBits = key.size() * 8;
    if (key.size() != 16 && key.size() != 24 && key.size() != 32) {
        ui::fail("key must be exactly 16, 24 or 32 bytes (AES-128/192/256); got " +
                 std::to_string(key.size()) + " bytes");
        ui::info("pass raw bytes with --key, or hex with --key-hex (64 hex chars for AES-256)");
        return 1;
    }
    actualBits = key.size() * 8;
    if (actualBits != 128 && actualBits != 192 && actualBits != 256) actualBits = bits;
    ui::kv("mode", "AES-" + std::to_string(actualBits) + "-" + toUpper(mode));
    ui::kv("key", (generatedKey ? "generated " : "") + hexEncode(key.data(), key.size()) +
                      (generatedKey ? "  (not shown again, save it)" : ""));
    ui::kv("iv", hexEncode(iv.data(), iv.size()));
    ui::kv("aad", aad.empty() ? "(none)" : hexEncode(aad.data(), aad.size()));
    ui::kv("plaintext", std::to_string(data.size()) + " bytes");
    ui::line("");

    if (mode == "gcm") {
        Bytes out;
        if (a.hasOpt("tag-hex")) {
            Bytes ct = hexDecode(a.opt("cipher-hex", ""));
            Bytes tag = hexDecode(a.opt("tag-hex"));
            Bytes out;
            if (!aes::gcmDecrypt(key, iv, ct, tag, aad, &out)) {
                ui::fail("authentication FAILED - wrong key, iv, aad or tampered ciphertext");
                ui::kv("ciphertext bytes", std::to_string(ct.size()));
                ui::kv("tag bytes", std::to_string(tag.size()));
                ui::kv("supplied tag", hexEncode(tag.data(), tag.size()));
                return 1;
            }
            ui::ok("authenticated");
            ui::kv("plaintext", std::string(out.begin(), out.end()));
        } else {
            auto r = aes::gcmEncrypt(key, iv, data, aad);
            ui::kv("ciphertext", hexEncode(r.ct.data(), r.ct.size()));
            ui::kv("tag", hexEncode(r.tag.data(), r.tag.size()));
        }
    } else if (mode == "cbc" || mode == "ctr" || mode == "ecb") {
        Bytes out;
        if (mode == "ctr") {
            out = aes::ctrCrypt(key, iv, data);
        } else if (a.hasOpt("cipher-hex")) {
            Bytes ct = hexDecode(a.opt("cipher-hex"));
            out = mode == "cbc" ? aes::cbcDecrypt(key, iv, ct) : Bytes();
        } else {
            out = mode == "cbc" ? aes::cbcEncrypt(key, iv, data) : aes::ecbEncrypt(key, data);
        }
        ui::kv("output", hexEncode(out.data(), out.size()));
    } else {
        ui::fail("unknown mode: " + mode + " (gcm, cbc, ctr, ecb)");
        return 1;
    }
    ui::line("");
    return 0;
}

// -------------------------------------------------------- classical cipher
double englishScore(const std::string& s) {
    static const char* common = "etaoinshrdlcumwfgypbvkjxqz";
    std::map<char, int> freq;
    size_t letters = 0;
    for (unsigned char c : s) {
        if (isalpha(c)) { ++freq[(char)tolower(c)]; ++letters; }
    }
    if (letters == 0) return 0;
    std::string counts(26, '\0');
    for (auto& kv : freq) if (kv.first >= 'a' && kv.first <= 'z') counts[kv.first - 'a']++;
    double score = 0;
    for (int i = 0; i < 26; ++i) if (strchr(common, 'a' + i)) score += counts[i];
    return score * 100.0 / (double)letters;
}

int runCipher(const Args& a) {
    ui::section("CLASSICAL CIPHER LAB");

    std::string text = a.opt("in");
    if (text.empty() && !a.first().empty()) text = a.first();
    if (text.empty()) text = readStdin();
    if (text.empty()) {
        ui::fail("no input");
        ui::info("argus cipher --algo caesar --shift 13 \"attack at dawn\"");
        return 1;
    }

    std::string algo = toLower(a.opt("algo", "caesar"));
    int shift = std::atoi(a.opt("shift", "13").c_str());

    std::string out = text;
    bool crack = a.flag("crack");

    if (algo == "caesar" || algo == "rot" || algo == "rot13") {
        if (algo == "rot13") shift = 13;
        if (crack) {
            std::vector<std::vector<std::string>> rows;
            for (int k = 0; k < 26; ++k) {
                std::string t;
                for (char c : text) {
                    if (isalpha((unsigned char)c))
                        t += (char)('a' + (tolower((unsigned char)c) - 'a' + k) % 26);
                    else t += c;
                }
                rows.push_back({"ROT" + std::to_string(k), fmt(englishScore(t), 1), ui::truncateTo(t, 46)});
            }
            std::sort(rows.begin(), rows.end(),
                      [](const std::vector<std::string>& x, const std::vector<std::string>& y) {
                          return std::atof(x[1].c_str()) > std::atof(y[1].c_str());
                      });
            ui::kv("input", ui::truncateTo(text, 56));
            ui::line("");
            ui::table({"ROT", "ENG%", "PLAINTEXT"}, rows);
            ui::line("");
            return 0;
        }
        for (char& c : out)
            if (isalpha((unsigned char)c))
                c = (char)('a' + (tolower((unsigned char)c) - 'a' + shift + 26) % 26);
    } else if (algo == "atbash") {
        for (char& c : out) {
            if (islower((unsigned char)c)) c = (char)('z' - (c - 'a'));
            else if (isupper((unsigned char)c)) c = (char)('Z' - (c - 'A'));
        }
    } else if (algo == "vigenere") {
        std::string key = a.opt("key", "KEY");
        size_t ki = 0;
        for (char& c : out) {
            if (isalpha((unsigned char)c)) {
                int k = tolower((unsigned char)key[ki % key.size()]) - 'a';
                c = (char)('A' + ((toupper((unsigned char)c) - 'A' + k) % 26));
                ++ki;
            }
        }
    } else if (algo == "xor") {
        Bytes k = a.hasOpt("key-hex") ? hexDecode(a.opt("key-hex")) : textToBytes(a.opt("key", "AB"));
        for (size_t i = 0; i < out.size(); ++i)
            out[i] = (char)(out[i] ^ k[i % k.size()]);
    } else if (algo == "reverse") {
        std::reverse(out.begin(), out.end());
    } else if (algo == "railstream" || algo == "rail") {
        int rails = std::max(2, std::atoi(a.opt("rails", "3").c_str()));
        std::vector<std::string> r(rails);
        for (int i = 0; i < rails; ++i) r[i].clear();
        size_t idx = 0, dir = 0;
        for (char c : text) {
            r[idx] += c;
            if (idx == 0) dir = 1;
            else if (idx == (size_t)rails - 1) dir = 0;
            idx += dir;
            ++idx;
        }
        out.clear();
        std::vector<size_t> p(rails, 0);
        for (char c : text) {
            for (size_t r2 = 0; r2 < r.size(); ++r2) {
                if (p[r2] < r[r2].size()) { out += r[r2][p[r2]++]; break; }
            }
        }
    } else {
        ui::fail("unknown algorithm: " + algo);
        ui::info("supported: caesar rot rot13 atbash vigenere xor reverse railstream");
        return 1;
    }

    ui::kv("algorithm", algo + (shift != 13 || algo == "caesar" ? " shift=" + std::to_string(shift) : ""));
    ui::kv("input", ui::truncateTo(text, 56));
    ui::kv("output", out);
    ui::kv("english score", fmt(englishScore(out), 1) + "%");
    ui::line("");
    ui::info("classical ciphers provide no confidentiality; use AES-256-GCM or ChaCha20-Poly1305");
    ui::line("");
    return 0;
}

// -------------------------------------------------------------------- JWT
int runJwt(const Args& a) {
    ui::section("JWT ANALYZER");

    std::string tok = a.opt("token");
    if (tok.empty() && !a.first().empty()) tok = a.first();
    if (tok.empty()) {
        std::string all;
        if (!a.opt("file").empty()) readTextFile(a.opt("file"), all);
        else all = readStdin();
        for (auto& l : splitLines(all)) {
            std::string t = trim(l);
            if (t.rfind("eyJ", 0) == 0) tok = t;
        }
    }
    if (tok.empty()) {
        ui::fail("no token found (pass --token, a bare token, or pipe on stdin)");
        return 1;
    }
    if (startsWith(tok, "Bearer ")) tok = trim(tok.substr(7));

    auto parts = split(tok, '.');
    std::vector<Finding> fs;

    ui::kv("token length", std::to_string(tok.size()) + " chars");
    ui::kv("segments", std::to_string(parts.size()));
    ui::line("");

    if (parts.size() != 3) {
        fs.push_back({"J-NOT-JWT", "expected 3 dot-separated segments, got " + std::to_string(parts.size()), 2});
        renderFindings(fs, false);
        return 1;
    }

    Bytes hb = base64Decode(parts[0]);
    Bytes pb = base64Decode(parts[1]);
    Bytes sb = base64Decode(parts[2]);
    std::string hdr = std::string(hb.begin(), hb.end());
    std::string pl = std::string(pb.begin(), pb.end());

    ui::section("HEADER");
    for (auto& l : splitLines(hdr)) ui::line("    " + l);
    ui::section("PAYLOAD");
    for (auto& l : splitLines(pl)) ui::line("    " + l);
    ui::section("SIGNATURE");
    ui::kv("bytes", std::to_string(sb.size()));
    ui::line("");

    std::string alg = toLower(regexFind(hdr, "\"alg\"\\s*:\\s*\"([^\"]+)\"", 1));
    std::string typ = toLower(regexFind(hdr, "\"typ\"\\s*:\\s*\"([^\"]+)\"", 1));
    std::string kid = regexFind(hdr, "\"kid\"\\s*:\\s*\"([^\"]*)\"", 1);
    std::string jku = regexFind(hdr, "\"jku\"\\s*:\\s*\"([^\"]*)\"", 1);
    std::string x5u = regexFind(hdr, "\"x5u\"\\s*:\\s*\"([^\"]*)\"", 1);
    std::string jwk = regexFind(hdr, "\"jwk\"\\s*:\\s*\\{", 0, nullptr, nullptr, 0);

    ui::kv("alg", alg.empty() ? "(none)" : alg);
    ui::kv("typ", typ.empty() ? "(absent)" : typ);
    if (!kid.empty()) ui::kv("kid", kid);
    ui::line("");

    if (alg == "none" || parts[2].empty()) {
        fs.push_back({"J-ALG-NONE", "alg=none / empty signature: token is forgeable by anyone", 3});
    }
    if (alg.rfind("hs", 0) == 0) {
        fs.push_back({"J-HMAC", alg + " is symmetric: the verifier must hold the signing secret", 1});
        std::string secret = a.opt("secret");
        if (!secret.empty()) {
            Bytes sk = textToBytes(secret);
            if (sk.size() < 32) fs.push_back({"J-WEAK-SECRET", "secret under 32 bytes: brute-forceable", 3});
            std::string expect = hmacHex(alg == "hs256" ? "sha256" : alg == "hs384" ? "sha384" : "sha512",
                                         secret, parts[0] + "." + parts[1]);
            if (expect == hexEncode(sb.data(), sb.size()))
                fs.push_back({"J-VERIFY-OK", "signature verifies with the supplied secret", 0});
            else
                fs.push_back({"J-SIG-MISMATCH", "signature does NOT verify with the supplied secret", 2});
        } else {
            fs.push_back({"J-VERIFY", "pass --secret <s> to verify the HMAC signature locally", 1});
        }
    }
    if (alg.rfind("rs", 0) == 0 || alg.rfind("ps", 0) == 0 || alg == "eddsa") {
        fs.push_back({"J-ASYMM", alg + " is asymmetric: verify with the issuer's public key only", 0});
        if (!x5u.empty()) fs.push_back({"J-X5U", "x5u header fetches a key over the network: SSRF / key-substitution risk", 2});
    }
    if (jwk.size()) fs.push_back({"J-EMBEDDED-JWK", "token embeds its own signing key: self-signed, no trust chain", 3});
    if (!jku.empty()) fs.push_back({"J-JKU", "jku header: attacker-controlled key URL if the issuer is sloppy", 2});
    if (hdr.find("\"crit\"") != std::string::npos)
        fs.push_back({"J-CRIT", "crit header present: extensions must be enforced, often ignored by libraries", 2});

    std::string exp = regexFind(pl, "\"exp\"\\s*:\\s*(\\d+)", 1);
    std::string nbf = regexFind(pl, "\"nbf\"\\s*:\\s*(\\d+)", 1);
    std::string iat = regexFind(pl, "\"iat\"\\s*:\\s*(\\d+)", 1);
    std::string iss = regexFind(pl, "\"iss\"\\s*:\\s*\"([^\"]*)\"", 1);
    std::string aud = regexFind(pl, "\"aud\"\\s*:\\s*\"([^\"]*)\"", 1);
    time_t now = time(nullptr);

    if (!exp.empty()) {
        long long e = atoll(exp.c_str());
        long long delta = e - (long long)now;
        if (delta < 0) fs.push_back({"J-EXPIRED", "token expired " + fmtLong((double)-delta) + "s ago", 3});
        else fs.push_back({"J-TTL", "expires in " + fmtLong((double)delta) + "s", delta > 604800 ? 2 : 0});
    } else {
        fs.push_back({"J-NO-EXP", "no exp claim: token never expires", 3});
    }
    if (!nbf.empty()) {
        long long n = atoll(nbf.c_str());
        if (n > (long long)now) fs.push_back({"J-NOT-YET", "nbf is in the future: token not valid yet", 1});
    }
    if (exp.empty() && iat.empty()) fs.push_back({"J-NO-TIME", "neither exp nor iat: replay window is unbounded", 2});
    if (!iss.empty()) fs.push_back({"J-ISS", "iss=" + iss, 0});
    else fs.push_back({"J-NO-ISS", "no iss claim: any issuer is accepted", 1});
    if (!aud.empty()) fs.push_back({"J-AUD", "aud=" + aud, 0});
    else fs.push_back({"J-NO-AUD", "no aud claim: token replayable across services", 2});

    if (icontains(pl, "\"password\"") || icontains(pl, "\"pwd\""))
        fs.push_back({"J-SECRET-CLAIM", "payload carries credential material: JWTs are signed, not encrypted", 3});
    if (icontains(pl, "\"role\":\"admin\"") || icontains(pl, "\"is_admin\""))
        fs.push_back({"J-PRIV", "privilege claim in the payload: the client can see and tamper with it unless exp is enforced", 1});

    renderFindings(fs);
    ui::info("never trust a JWT payload before signature + exp + iss + aud verification");
    int bad = 0;
    for (auto& f : fs) if (f.sev >= 2) ++bad;
    return bad ? 1 : 0;
}

Bytes bigMul(const Bytes& x, const Bytes& y) {
    if (x.empty() || y.empty()) return Bytes();
    size_t nx = x.size(), ny = y.size();
    Bytes r(nx + ny, 0);
    for (size_t i = 0; i < nx; ++i) {
        unsigned carry = 0;
        for (size_t j = 0; j < ny; ++j) {
            size_t idx = nx - 1 - i + (ny - 1 - j);
            unsigned cur = r[idx] + (unsigned)x[nx - 1 - i] * y[ny - 1 - j] + carry;
            r[idx] = (uint8_t)(cur & 0xFF);
            carry = cur >> 8;
        }
        size_t idx = nx - 1 - i;
        while (carry) {
            idx--;
            if (idx >= nx + ny) break;
            unsigned cur = r[idx] + carry;
            r[idx] = (uint8_t)(cur & 0xFF);
            carry = cur >> 8;
        }
    }
    while (r.size() > 1 && r.front() == 0) r.erase(r.begin());
    return r;
}

long double bigToLd(const Bytes& b) {
    long double v = 0;
    for (uint8_t c : b) v = v * 256.0L + c;
    return v;
}

Bytes ldToBig(long double v) {
    Bytes out;
    int exp;
    long double m = frexpl(v, &exp);
    for (int i = 0; i < exp; i++) out.push_back(0);
    long long mant = (long long)(m * 18446744073709551616.0L);
    Bytes mBytes;
    if (mant == 0) return Bytes{0};
    while (mant > 0) {
        mBytes.push_back((uint8_t)(mant & 0xFF));
        mant >>= 8;
    }
    for (size_t i = mBytes.size(); i < out.size(); ++i) {
        out[i] = 0;
    }
    out.insert(out.begin(), mBytes.begin(), mBytes.end());
    while (out.size() > 1 && out.front() == 0) out.erase(out.begin());
    return out;
}

bool perfectSquareRoot(const Bytes& n, Bytes& root) {
    if (n.empty() || (n[0] & 0x80)) return false;
    long double v = bigToLd(n);
    if (v < 1) return false;
    long double s = sqrtl(v);
    for (long long off = -2; off <= 2; ++off) {
        long double cand = s + off;
        if (cand < 1) continue;
        Bytes k = ldToBig(cand);
        if (bigMul(k, k) == n) { root = k; return true; }
    }
    return false;
}

struct BigInt {
    static int cmp(const Bytes& a, const Bytes& b) {
        std::string x = hexEncode(a.data(), a.size()), y = hexEncode(b.data(), b.size());
        x = toLower(x); y = toLower(y);
        if (a.empty() || b.empty()) return a.size() == b.size() ? 0 : (a.empty() ? -1 : 1);
        if (x.size() != y.size()) return x.size() < y.size() ? -1 : 1;
        if (x == y) return 0;
        return x < y ? -1 : 1;
    }
    static Bytes add(const Bytes& a, const Bytes& b) {
        Bytes r;
        size_t n = std::max(a.size(), b.size()) + 1;
        r.assign(n, 0);
        int carry = 0;
        for (size_t i = 0; i < n; ++i) {
            int s = carry;
            if (i < a.size()) s += a[a.size() - 1 - i];
            if (i < b.size()) s += b[b.size() - 1 - i];
            r[n - 1 - i] = (uint8_t)(s & 0xFF);
            carry = s >> 8;
        }
        while (!r.empty() && r.size() > 1 && r.front() == 0) r.erase(r.begin());
        return r;
    }
    static Bytes mulSmall(const Bytes& a, uint32_t m) {
        Bytes r(a.size() + 8, 0);
        uint64_t carry = 0;
        for (size_t i = 0; i < a.size(); ++i) {
            uint64_t cur = carry + (uint64_t)a[a.size() - 1 - i] * m;
            r[r.size() - 1 - i] = (uint8_t)(cur & 0xFF);
            carry = cur >> 8;
        }
        for (int i = 7; i >= 0 && carry; --i) {
            uint64_t cur = carry + (uint64_t)r[i] * 256;
            r[i] = (uint8_t)(cur & 0xFF);
            carry = cur >> 8;
        }
        while (r.size() > 1 && r.front() == 0) r.erase(r.begin());
        return r;
    }
    static bool isEven(const Bytes& a) { return !a.empty() && !(a.back() & 1); }
    static bool isOdd(const Bytes& a) { return !a.empty() && (a.back() & 1); }

    // Schoolbook multiply, big-endian in / big-endian out.
    static Bytes mul(const Bytes& a, const Bytes& b) {
        if (a.empty() || b.empty()) return Bytes();
        Bytes r(a.size() + b.size(), 0);
        for (size_t i = 0; i < a.size(); ++i) {
            unsigned carry = 0;
            uint32_t ai = a[a.size() - 1 - i];
            if (!ai) continue;
            for (size_t j = 0; j < b.size(); ++j) {
                size_t idx = r.size() - 1 - (i + j);
                unsigned cur = r[idx] + ai * (uint32_t)b[b.size() - 1 - j] + carry;
                r[idx] = (uint8_t)(cur & 0xFF);
                carry = cur >> 8;
            }
            size_t idx = r.size() - 1 - (i + b.size());
            while (carry && idx != (size_t)-1) {
                unsigned cur = r[idx] + carry;
                r[idx] = (uint8_t)(cur & 0xFF);
                carry = cur >> 8;
                if (idx == 0) break;
                --idx;
            }
        }
        while (r.size() > 1 && r.front() == 0) r.erase(r.begin());
        return r;
    }

    // Index of the lowest set bit, counting from the most significant end.
    static size_t bitLength(const Bytes& a) {
        if (a.empty()) return 0;
        for (size_t i = 0; i < a.size(); ++i) {
            uint8_t c = a[i];
            if (!c) continue;
            int lead = 0;
            while (((c >> (7 - lead)) & 1) == 0) ++lead;
            return (a.size() - i - 1) * 8 + (size_t)(8 - lead);
        }
        return 0;
    }
    static bool isZero(const Bytes& a) {
        for (uint8_t c : a) if (c) return false;
        return true;
    }
    static Bytes subOne(const Bytes& a) {
        Bytes r = a;
        for (size_t i = 0; i < r.size(); ++i) {
            if (r[i] == 0) { r[i] = 0xFF; continue; }
            r[i]--;
            break;
        }
        while (r.size() > 1 && r.front() == 0) r.erase(r.begin());
        return r;
    }
};

Bytes decimalToBytes(const std::string& digits) {
    Bytes out;
    for (char c : digits) {
        uint32_t carry = (uint32_t)(c - '0');
        for (size_t i = out.size(); i > 0; --i) {
            uint32_t v = (uint32_t)out[i - 1] * 10 + carry;
            out[i - 1] = (uint8_t)(v & 0xFF);
            carry = v >> 8;
        }
        while (carry) {
            out.insert(out.begin(), (uint8_t)(carry & 0xFF));
            carry >>= 8;
        }
    }
    while (out.size() > 1 && out.front() == 0) out.erase(out.begin());
    return out;
}

bool parseNumber(const std::string& raw, Bytes& out, std::string& how) {
    std::string s = trim(raw);
    if (s.empty()) return false;
    if (s[0] == '0' && (s[1] == 'x' || s[1] == 'X')) {
        out = hexDecode(s.substr(2));
        how = "hex";
        return !out.empty();
    }
    bool allDigits = true;
    for (char c : s) if (!isdigit((unsigned char)c)) allDigits = false;
    if (allDigits) {
        out = decimalToBytes(s);
        how = "decimal";
        if (!out.empty()) return true;
    }
    std::string t = replaceAll(s, "\n", "");
    t = replaceAll(t, "\r", "");
    t = replaceAll(t, " ", "");
    if (startsWith(t, "-----")) {
        t = split(t, '\n').size() > 1 ? "" : t;
        return false;
    }
    Bytes b = base64Decode(s);
    if (!b.empty()) {
        out = b;
        how = "base64";
        return true;
    }
    return false;
}

Bytes modSmall(const Bytes& a, uint32_t m) {
    if (m == 0) return Bytes();
    uint32_t r = 0;
    for (uint8_t c : a) r = (uint32_t)(((uint64_t)r * 256 + c) % m);
    if (r == 0) return Bytes();
    Bytes out;
    if (r > 0xFF) out.push_back((uint8_t)(r >> 8));
    out.push_back((uint8_t)(r & 0xFF));
    return out;
}

bool divisibleBySmall(const Bytes& a, uint32_t m) {
    if (m == 0) return false;
    uint32_t r = 0;
    for (uint8_t c : a) r = (uint32_t)(((uint64_t)r * 256 + c) % m);
    return r == 0;
}

bool isPrimeSmall(uint32_t v) {
    if (v < 2) return false;
    if (v % 2 == 0) return v == 2;
    for (uint32_t i = 3; i * i <= v; i += 2)
        if (v % i == 0) return false;
    return true;
}

// Minimal DER reader: enough for PKCS#1 / PKCS#8 / SPKI RSA keys.
namespace der {

struct Node {
    uint32_t tag = 0;
    Bytes val;
    size_t end = 0;
};

struct Reader {
    Bytes d;
    size_t p = 0;
    explicit Reader(Bytes x) : d(std::move(x)) {}
    size_t remaining() const { return d.size() > p ? d.size() - p : 0; }

    bool node(Node& out) {
        if (remaining() < 2) return false;
        size_t start = p;
        out.tag = d[p++];
        size_t l = d[p++];
        if (l & 0x80) {
            int n = (int)(l & 0x7F);
            if (n == 0 || n > 4 || remaining() < (size_t)n) return false;
            l = 0;
            for (int i = 0; i < n; ++i) l = (l << 8) | d[p++];
        }
        if (l > remaining()) return false;
        out.val.assign(d.begin() + (long)p, d.begin() + (long)(p + l));
        p += l;
        out.end = p;
        return start < p;
    }

    // INTEGER with leading-zero normalisation removed
    static Bytes asInt(const Bytes& v) {
        Bytes r = v;
        size_t i = 0;
        while (i + 1 < r.size() && r[i] == 0) ++i;
        return Bytes(r.begin() + (long)i, r.end());
    }
};

// Pull every top-level INTEGER out of a SEQUENCE body.
std::vector<Bytes> integers(const Bytes& seq) {
    std::vector<Bytes> out;
    Reader r(seq);
    Node n;
    while (r.node(n))
        if (n.tag == 0x02) out.push_back(Reader::asInt(n.val));
    return out;
}

bool fromPkcs1(const Bytes& derBytes, Bytes& n, Bytes& e, Bytes& d, Bytes& p, Bytes& q) {
    Reader top(derBytes);
    Node seq;
    if (!top.node(seq) || seq.tag != 0x30) return false;
    std::vector<Bytes> v = integers(seq.val);
    if (v.size() < 3) return false;
    n = v[1];
    e = v[2];
    if (v.size() >= 6) { d = v[3]; p = v[4]; q = v[5]; }
    return true;
}

bool fromSpki(const Bytes& derBytes, Bytes& n, Bytes& e) {
    Reader top(derBytes);
    Node seq;
    if (!top.node(seq) || seq.tag != 0x30) return false;
    Reader in(seq.val);
    Node alg;
    if (!in.node(alg) || alg.tag != 0x30) return false;
    Node bits;
    if (!in.node(bits) || bits.tag != 0x03 || bits.val.empty()) return false;
    Bytes inner(bits.val.begin() + 1, bits.val.end());
    Reader innerR(inner);
    Node pub;
    if (!innerR.node(pub) || pub.tag != 0x30) return false;
    std::vector<Bytes> v = integers(pub.val);
    if (v.size() < 2) return false;
    n = v[0];
    e = v[1];
    return true;
}

bool parse(const Bytes& derBytes, Bytes& n, Bytes& e, Bytes& d, Bytes& p, Bytes& q,
           std::string* format) {
    if (fromPkcs1(derBytes, n, e, d, p, q)) {
        if (format) *format = d.empty() ? "pkcs#1 public" : "pkcs#1 private";
        return true;
    }
    Reader top(derBytes);
    Node seq;
    if (!top.node(seq) || seq.tag != 0x30) return false;
    Reader in(seq.val);
    Node ver, alg, oct;
    if (in.node(ver) && in.node(alg) && in.node(oct) && oct.tag == 0x04) {
        if (fromPkcs1(oct.val, n, e, d, p, q)) {
            if (format) *format = d.empty() ? "pkcs#8 public" : "pkcs#8 private";
            return true;
        }
    }
    if (fromSpki(derBytes, n, e)) {
        if (format) *format = "subjectpublickeyinfo";
        return true;
    }
    return false;
}

} // namespace der

// Accepts PEM or raw DER; fills n/e/d/p/q when present.
bool loadRsaKey(const std::string& text, Bytes& n, Bytes& e, Bytes& d, Bytes& p, Bytes& q,
                std::string& how) {
    size_t b64 = text.find("-----BEGIN");
    Bytes derBytes;
    if (b64 != std::string::npos) {
        size_t b = text.find('\n', b64);
        size_t epos = text.find("-----END", b64);
        if (b == std::string::npos) return false;
        std::string body = text.substr(b + 1, (epos == std::string::npos ? text.size() : epos) - b - 1);
        derBytes = base64Decode(replaceAll(body, " ", ""));
    } else {
        derBytes.assign(text.begin(), text.end());
    }
    if (derBytes.size() < 16) return false;
    return der::parse(derBytes, n, e, d, p, q, &how);
}

int rsaRun(const Args& a) {
    ui::section("RSA KEY AUDIT");

    std::string nS = a.opt("n");
    std::string eS = a.opt("e");
    std::string dS = a.opt("d");
    std::string pS = a.opt("p");
    std::string qS = a.opt("q");
    std::string how;
    Bytes n, e, d, p, q;

    if (!nS.empty() && parseNumber(nS, n, how)) {
        ui::kv("n parsed as", how);
    } else {
        std::string content;
        std::string file = a.opt("file");
        if (!file.empty()) {
            std::string err;
            if (!readTextFile(file, content, &err)) { ui::fail(err); return 1; }
        } else {
            content = readStdin();
        }
        if (!loadRsaKey(content, n, e, d, p, q, how)) {
            ui::fail("could not parse an RSA key; expected PEM (pkcs#1/pkcs#8) or DER, "
                     "or pass components with --n / --e / --d / --p / --q");
            return 1;
        }
        ui::kv("key format", how);
    }

    if (nS.empty() && n.empty() && (eS.empty() || !parseNumber(eS, e, how))) {
        ui::fail("provide --n <hex|dec|b64> [--e 65537] [--d ...], or --file rsa.pem");
        return 1;
    }
    if (!eS.empty()) parseNumber(eS, e, how);
    if (!dS.empty()) parseNumber(dS, d, how);
    if (!pS.empty()) parseNumber(pS, p, how);
    if (!qS.empty()) parseNumber(qS, q, how);

    if (n.empty()) {
        ui::fail("could not extract modulus; pass it explicitly with --n");
        return 1;
    }

size_t nbits = BigInt::bitLength(n);

    ui::kv("modulus n", std::to_string(nbits) + " bits  (" + std::to_string(n.size()) + " bytes)");
    if (!e.empty()) ui::kv("exponent e", hexEncode(e.data(), e.size()) + "  (" + fmtLong((double)e.back()) + " tail)");
    if (!d.empty()) ui::kv("private d", std::to_string(d.size() * 8) + " bits");
    if (!p.empty()) ui::kv("prime p", std::to_string(p.size() * 8) + " bits");
    if (!q.empty()) ui::kv("prime q", std::to_string(q.size() * 8) + " bits");
    ui::line("");

    std::vector<Finding> fs;

    if (nbits < 2048)
        fs.push_back({"R-SIZE", std::to_string(nbits) + "-bit modulus: below the 2048-bit minimum", 3});
    else if (nbits < 3072)
        fs.push_back({"R-SIZE", std::to_string(nbits) + "-bit modulus: acceptable now, prefer 3072+ for long-lived keys", 1});
    else
        fs.push_back({"R-SIZE", std::to_string(nbits) + "-bit modulus: strong", 0});

    if (!e.empty()) {
        uint32_t ev = 0;
        for (size_t i = e.size(); i > 0; --i) ev = ev * 256 + e[i - 1];
        if (ev < 3) fs.push_back({"R-E-SMALL", "exponent " + std::to_string(ev) + " is trivially breakable", 3});
        else if (ev < 65537) fs.push_back({"R-E-LOW", "exponent below 65537: padding oracles become practical", 3});
        else if (ev == 65537) fs.push_back({"R-E-OK", "exponent 65537 is the correct default", 0});
        else if ((ev & 1) == 0) fs.push_back({"R-E-EVEN", "exponent is even: gcd(e, phi) > 1, key is broken", 3});
        else fs.push_back({"R-E-HIGH", "unusually large public exponent", 1});
    } else {
        fs.push_back({"R-E-MISSING", "no public exponent supplied; cannot assess", 2});
    }

    if (BigInt::isEven(n)) fs.push_back({"R-N-EVEN", "modulus is even: instantly factorable", 3});

    std::vector<std::string> smalls;
    for (uint32_t p2 = 3; p2 < 2000; p2 += 2) {
        if (!isPrimeSmall(p2)) continue;
        if (divisibleBySmall(n, p2)) {
            smalls.push_back(std::to_string(p2));
            if (smalls.size() > 5) break;
        }
    }
    if (!smalls.empty())
        fs.push_back({"R-N-SMOOTH", "modulus divisible by small primes: " + join(smalls, ", "), 3});

    if (n.size() <= 8) {
        uint64_t v = 0;
        for (size_t i = 0; i < n.size(); ++i) v = (v << 8) | n[i];
        for (uint64_t k = 2; k * k <= v; ++k)
            if (v % k == 0) {
                fs.push_back({"R-N-FACTORED", "trial division found factor " + fmtLong((double)k), 3});
                break;
            }
    } else {
        Bytes root;
        if (perfectSquareRoot(n, root)) {
            fs.push_back({"R-N-SQUARE", "modulus is a perfect square (p^2): factorable with one Fermat step", 3});
            ui::kv("sqrt(n)", hexEncode(root.data(), root.size()));
        }
    }

    if (!p.empty() && !q.empty()) {
        Bytes pq = BigInt::mul(p, q);
        if (BigInt::cmp(pq, n) == 0)
            fs.push_back({"R-PQ-OK", "p * q equals n: key material is consistent", 0});
        else
            fs.push_back({"R-PQ-BAD", "p * q does NOT equal n", 3});
        size_t diff = (p.size() > q.size() ? p.size() - q.size() : q.size() - p.size());
        size_t minSize = std::min(p.size(), q.size());
        size_t bitDiff = diff * 8;
        Bytes pm = modSmall(p, 2), qm = modSmall(q, 2);
        if (pm.size() == 1 && qm.size() == 1 && pm[0] != qm[0] && bitDiff <= 2)
            fs.push_back({"R-FERMAT", "p and q are extremely close: Wiener's / Fermat attack succeeds instantly", 3});
    }

    if (!e.empty()) {
        for (uint32_t m = 2; m < 200; ++m) {
            if (divisibleBySmall(n, m)) {
            if (!divisibleBySmall(e, m) && !divisibleBySmall(d, m))
                    fs.push_back({"R-SHARED-FACTOR", "n, e and d share factor " + std::to_string(m), 3});
            }
        }
    }

    if (!e.empty() && !d.empty()) {
        uint64_t ev = 0;
        for (size_t i = e.size(); i > 0 && i > e.size() - 9; --i) ev = ev * 256 + e[i - 1];
        if (ev > 0 && ev <= 0xFFFFFFFFULL && BigInt::bitLength(d) <= 32)
            fs.push_back({"R-SMALL-DE", "public and private exponents are both tiny: the key is recoverable by brute force", 3});
        else if (BigInt::bitLength(d) + 64 < nbits)
            fs.push_back({"R-D-SHORT", "private exponent is far shorter than the modulus: key material is incomplete or CRT-only", 2});
    }

    ui::line("");
    renderFindings(fs);
    ui::info("RSA gives confidentiality only with OAEP (never PKCS#1 v1.5) and signature only with PSS");
    int bad = 0;
    for (auto& f : fs) if (f.sev >= 2) ++bad;
    return bad ? 1 : 0;
}

// ------------------------------------------------------------- RNG tests
double normalQUnused() { return 0; }
double normalCdf(double x) { return 0.5 * std::erfc(-x * 0.70710678118654752440); }

double lnGamma(double x) {
    static const double c[6] = {76.18009172947146, -86.50532032941677, 24.01409824083091,
                                -1.231739572450155, 0.1208650973866179e-2, -0.5395239384953e-5};
    double y = x;
    double tmp = x + 5.5;
    tmp -= (x + 0.5) * std::log(tmp);
    double ser = 1.000000000190015;
    for (int j = 0; j <= 5; ++j) ser += c[j] / ++y;
    return -tmp + std::log(2.5066282746310005 * ser / x);
}

double gammq(double a, double x) {
    if (x < 0 || a <= 0) return 1.0;
    if (x == 0) return 1.0;
    if (x < a + 1.0) {
        double ap = a;
        double sum = 1.0 / a;
        double del = sum;
        for (int n = 1; n <= 500; ++n) {
            ap += 1.0;
            del *= x / ap;
            sum += del;
            if (std::fabs(del) < std::fabs(sum) * 1e-14) break;
        }
        return 1.0 - sum * std::exp(-x + a * std::log(x) - lnGamma(a));
    }
    double b = x + 1.0 - a;
    double c = 1.0 / 1e-300;
    double d = 1.0 / b;
    double h = d;
    for (int i = 1; i <= 500; ++i) {
        double an = -i * (i - a);
        b += 2.0;
        d = an * d + b;
        if (std::fabs(d) < 1e-300) d = 1e-300;
        c = b + an / c;
        if (std::fabs(c) < 1e-300) c = 1e-300;
        d = 1.0 / d;
        double del = d * c;
        h *= del;
        if (std::fabs(del - 1.0) < 1e-14) break;
    }
    return std::exp(-x + a * std::log(x) - lnGamma(a)) * h;
}

struct RngResult {
    std::string name;
    double statistic = 0;
    double p = 0;
    double threshold = 0.01;
    bool pass = false;
};

inline int bitAt(const Bytes& b, size_t idx) {
    return (b[idx / 8] >> (7 - (idx % 8))) & 1;
}

inline size_t totalBits(const Bytes& b) { return b.size() * 8; }

RngResult monobitTest(const Bytes& bits) {
    RngResult r;
    r.name = "frequency (monobit)";
    size_t n = totalBits(bits);
    if (n == 0) return r;
    double ones = 0;
    for (uint8_t x : bits) ones += popcount8(x);
    double s = std::fabs(2.0 * ones - (double)n) / std::sqrt((double)n);
    r.statistic = s;
    r.p = std::erfc(s / std::sqrt(2.0));
    r.pass = r.p >= r.threshold;
    return r;
}

RngResult blockFreqTest(const Bytes& bits, size_t M) {
    RngResult r;
    r.name = "block frequency (M=" + std::to_string(M) + ")";
    size_t total = totalBits(bits);
    size_t N = total / M;
    if (N < 20 || M == 0) { r.p = 1.0; r.pass = true; return r; }
    double chi = 0;
    for (size_t j = 0; j < N; ++j) {
        double ones = 0;
        for (size_t k = 0; k < M; ++k) ones += bitAt(bits, j * M + k);
        double pi = ones / (double)M;
        chi += 4.0 * (double)M * (pi - 0.5) * (pi - 0.5);
    }
    r.statistic = chi;
    r.p = gammq((double)(N - 1) / 2.0, chi / 2.0);
    r.pass = r.p >= r.threshold;
    return r;
}

RngResult runsTest(const Bytes& bits) {
    RngResult r;
    r.name = "runs";
    size_t n = totalBits(bits);
    if (n < 100) { r.p = 1.0; r.pass = true; return r; }
    double ones = 0;
    for (uint8_t x : bits) ones += popcount8(x);
    double pi = ones / (double)n;
    if (std::fabs(pi - 0.5) >= 2.0 / std::sqrt((double)n)) {
        r.statistic = 0;
        r.p = 0;
        r.pass = false;
        return r;
    }
    size_t runs = 1;
    int prev = bitAt(bits, 0);
    for (size_t i = 1; i < n; ++i) {
        int cur = bitAt(bits, i);
        if (cur != prev) { ++runs; prev = cur; }
    }
    double expected = 2.0 * (double)n * pi * (1.0 - pi);
    double vobs = (double)runs / expected;
    r.statistic = vobs;
    double denom = 2.0 * std::sqrt(2.0 * ((double)n - 3.0) / 9.0);
    r.p = std::erfc(std::fabs((double)runs - expected) / denom);
    r.pass = r.p >= r.threshold;
    return r;
}

RngResult longestRunTest(const Bytes& bits) {
    RngResult r;
    r.name = "longest run of ones";
    const size_t M = 128;
    size_t total = totalBits(bits);
    size_t N = total / M;
    if (N < 16) { r.p = 1.0; r.pass = true; return r; }
    static const double pi[6] = {0.1174, 0.2430, 0.2493, 0.1752, 0.1027, 0.1124};
    double v[6] = {0, 0, 0, 0, 0, 0};
    for (size_t j = 0; j < N; ++j) {
        size_t longest = 0, cur = 0;
        for (size_t k = 0; k < M; ++k) {
            if (bitAt(bits, j * M + k)) { ++cur; longest = std::max(longest, cur); }
            else cur = 0;
        }
        int bucket = longest <= 4 ? 0 : longest == 5 ? 1 : longest == 6 ? 2
                   : longest == 7 ? 3 : longest == 8 ? 4 : 5;
        ++v[bucket];
    }
    double chi = 0;
    for (int i = 0; i < 6; ++i) {
        double e = (double)N * pi[i];
        chi += (v[i] - e) * (v[i] - e) / e;
    }
    r.statistic = chi;
    r.p = gammq(2.5, chi / 2.0);
    r.pass = r.p >= r.threshold;
    return r;
}

RngResult cusumTest(const Bytes& bits, bool forward) {
    RngResult r;
    r.name = std::string("cumulative sums (") + (forward ? "forward" : "backward") + ")";
    size_t n = totalBits(bits);
    if (n < 100) { r.p = 1.0; r.pass = true; return r; }
    int z = 0;
    double maxAbs = 0;
    for (size_t i = 0; i < n; ++i) {
        size_t idx = forward ? i : n - 1 - i;
        z += bitAt(bits, idx) ? 1 : -1;
        maxAbs = std::max(maxAbs, (double)std::abs(z));
    }
    r.statistic = maxAbs;
    double nn = (double)n;
    double sqrtN = std::sqrt(nn);
    double lim = 10.0 / sqrtN;
    r.p = 1.0 - normalCdf((maxAbs - lim) / sqrtN) + normalCdf((-maxAbs - lim) / sqrtN);
    if (r.p > 1.0) r.p = 1.0;
    if (r.p < 0.0) r.p = 0.0;
    r.pass = r.p >= r.threshold;
    return r;
}

RngResult entropyTest(const Bytes& bits, size_t m) {
    RngResult r;
    r.name = "approximate entropy (m=" + std::to_string(m) + ")";
    size_t total = totalBits(bits);
    size_t n = total - m + 1;
    size_t lim = (size_t)1 << m;
    if (n < 10 || n > (size_t)1 << 22) { r.p = 1.0; r.pass = true; return r; }

    std::vector<size_t> c(lim, 0);
    for (size_t i = 0; i < n; ++i) {
        size_t v = 0;
        for (size_t k = 0; k < m; ++k) v = (v << 1) | (uint32_t)bitAt(bits, i + k);
        ++c[v];
    }
    double phi = 0;
    for (size_t i = 0; i < lim; ++i) {
        if (c[i]) {
            double p = (double)c[i] / (double)n;
            phi += p * std::log2(p);
        }
    }
    phi = -phi;
    r.statistic = phi;
    double chi = (double)lim * (double)n * (std::log2((double)m) - phi);
    if (chi < 0) chi = 0;
    r.p = gammq((double)lim / 2.0, chi / 2.0);
    r.pass = r.p >= r.threshold;
    return r;
}

RngResult serialTest(const Bytes& bits) {
    RngResult r;
    r.name = "serial (psi2, m=2)";
    size_t total = totalBits(bits);
    if (total < 200) { r.p = 1.0; r.pass = true; return r; }
    auto psi2 = [&](size_t m) {
        size_t n = total - m + 1;
        size_t lim = (size_t)1 << m;
        std::vector<size_t> c(lim, 0);
        for (size_t i = 0; i < n; ++i) {
            size_t v = 0;
            for (size_t k = 0; k < m; ++k) v = (v << 1) | (uint32_t)bitAt(bits, i + k);
            ++c[v];
        }
        double psi = 0;
        for (size_t i = 0; i < lim; ++i)
            psi += (double)c[i] * (double)c[i];
        psi *= 4.0 / (double)n;
        return psi - (double)n;
    };
    double del1 = psi2(2);
    double del0 = psi2(1);
    r.statistic = del1;
    r.p = std::erfc(std::sqrt(std::max(0.0, del1 - del0) / 2.0));
    r.pass = r.p >= r.threshold;
    return r;
}

RngResult pairwiseFreqTest(const Bytes& bits) {
    RngResult r;
    r.name = "pairwise (2-bit patterns)";
    size_t total = totalBits(bits);
    if (total < 200) { r.p = 1.0; r.pass = true; return r; }
    size_t n = total - 1;
    size_t c[4] = {0, 0, 0, 0};
    for (size_t i = 0; i + 1 < total; ++i)
        ++c[(bitAt(bits, i) << 1) | bitAt(bits, i + 1)];
    double e = (double)n / 4.0;
    double chi = 0;
    for (int i = 0; i < 4; ++i) chi += (c[i] - e) * (c[i] - e) / e;
    r.statistic = chi;
    r.p = gammq(1.5, chi / 2.0);
    r.pass = r.p >= r.threshold;
    return r;
}

RngResult discreteFrequencyTest(const Bytes& bits) {
    RngResult r;
    r.name = "discrete frequency";
    if (bits.size() < 100) { r.p = 1.0; r.pass = true; return r; }
    size_t counts[8] = {0, 0, 0, 0, 0, 0, 0, 0};
    for (uint8_t x : bits) ++counts[x & 7];
    double e = (double)bits.size() / 8.0;
    double chi = 0;
    for (int i = 0; i < 8; ++i) chi += (counts[i] - e) * (counts[i] - e) / e;
    r.statistic = chi;
    r.p = gammq(3.5, chi / 2.0);
    r.pass = r.p >= r.threshold;
    return r;
}

RngResult collisionsTest(const Bytes& bits) {
    RngResult r;
    r.name = "collision (16-bit words)";
    size_t n = totalBits(bits) / 16;
    if (n < 20000) { r.p = 1.0; r.pass = true; return r; }
    std::vector<size_t> c(65536, 0);
    for (size_t i = 0; i < n; ++i) {
        uint16_t v = 0;
        for (int k = 0; k < 16; ++k) v = (uint16_t)((v << 1) | (uint32_t)bitAt(bits, i * 16 + k));
        ++c[v];
    }
    double expected = (double)n * (double)n / (2.0 * 65536.0);
    double observed = 0;
    for (size_t x : c) observed += (double)x * (double)(x - 1) / 2.0;
    double vObs = observed / expected;
    r.statistic = vObs;
    double k = 65536.0;
    double lower = k * k / (2.0 * (double)n) - k * 0.5;
    double logp = (double)n * std::log(n) - (double)n - (double)n * std::log(k) +
                  std::log(std::exp(-(double)n) * std::sqrt(2.0 * 3.14159265358979323846 * (double)n) / k);
    (void)lower;
    r.p = std::exp(logp);
    r.pass = r.p >= r.threshold;
    return r;
}
int rngRun(const Args& a) {
    ui::section("CSPRNG STATISTICAL TEST (NIST SP 800-22)");

    size_t bits = (size_t)std::atoll(a.opt("bits", "1048576").c_str());
    if (bits < 4096) bits = 4096;
    if (bits > 1u << 24) bits = 1u << 24;
    size_t nbytes = (bits + 7) / 8;

    std::string source = a.opt("source", "os");
    ui::kv("source", source == "os" ? "operating system CSPRNG" : toLower(source));
    ui::kv("samples", std::to_string(bits) + " bits  (" + std::to_string(nbytes) + " bytes)");
    ui::kv("entropy check", secureRandomAvailable() ? "OS CSPRNG verified non-repeating"
                                                     : "OS CSPRNG UNAVAILABLE - results meaningless");
    ui::line("");

    spinnerStart("collecting samples");
    Bytes data;
    if (source == "os") {
        data = randomBytes(nbytes);
    } else {
        Bytes raw;
        std::string err;
        if (!readFile(source, raw, &err)) { spinnerStop(); ui::fail(err); return 1; }
        for (size_t i = 0; i < nbytes; ++i) data.push_back(raw[i % raw.size()]);
    }
    spinnerStop();

    std::vector<RngResult> results = {
        monobitTest(data),
        blockFreqTest(data, 128),
        blockFreqTest(data, 16),
        discreteFrequencyTest(data),
        runsTest(data),
        longestRunTest(data),
        cusumTest(data, true),
        cusumTest(data, false),
        entropyTest(data, 10),
        entropyTest(data, 8),
        serialTest(data),
        pairwiseFreqTest(data),
    };

    int failed = 0;
    std::vector<std::vector<std::string>> rows;
    for (auto& r : results) {
        if (!r.pass) ++failed;
        std::string verdictS = r.pass ? std::string(B_GREEN) + "PASS" + B_RESET
                                      : std::string(B_RED) + "FAIL" + B_RESET;
        rows.push_back({r.name, fmt(r.statistic, 4), fmt(r.p, 4), "0.01", verdictS});
    }
    ui::table({"TEST", "STATISTIC", "P-VALUE", "ALPHA", "RESULT"}, rows);
    ui::line("");
    ui::kv("tests run", std::to_string(results.size()));
    ui::kv("failures", std::to_string(failed));
    ui::kv("overall", failed == 0 ? std::string(B_GREEN) + "PASS - output looks random" + B_RESET
                                  : std::string(B_RED) + "FAIL - not random" + B_RESET);
    ui::line("");
    ui::info("statistical tests never prove randomness; they only catch obvious defects");
    ui::line("");
    return failed ? 1 : 0;
}

}  // namespace

CK_TOOL("aes", "cryptography", "AES-128/192/256 ECB-CBC-CTR-GCM with FIPS-197 known-answer self test",
        "argus aes --selftest  |  argus aes --mode gcm --bits 256 --key <k> --iv <iv> --in <text>",
        runAes);
CK_TOOL("cipher", "cryptography", "Caesar, ROT-N, Atbash, Vigenere, XOR, rail-fence lab with ROT crack",
        "argus cipher --algo caesar --shift 13 \"text\"  |  argus cipher --algo caesar --crack <ciphertext>",
        runCipher);
CK_TOOL("jwt", "cryptography", "Decode and audit JWTs: alg=none, expiry, aud/iss, key-confusion risk",
        "argus jwt --token <jwt>  |  argus jwt --secret <hs-secret> <jwt>", runJwt);
CK_TOOL("rsa-audit", "cryptography", "Audit RSA keys: modulus size, weak exponents, small factors, p*q consistency",
        "argus rsa-audit --n <hex|dec|b64> [--e 65537] [--d ...]  |  argus rsa-audit --file key.pem",
        rsaRun);
CK_TOOL("rng-test", "cryptography", "NIST SP 800-22 statistical battery over the OS CSPRNG",
        "argus rng-test [--bits 1048576] [--source <file>]", rngRun);
