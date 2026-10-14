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

struct Der {
    const Bytes* bp = nullptr;
    size_t p = 0;
    Der() = default;
    explicit Der(const Bytes& x) : bp(&x), p(0) {}

    const Bytes& b() const { static const Bytes empty; return bp ? *bp : empty; }
    size_t size() const { return b().size(); }
    size_t remaining0() const { return b().size(); }
    bool eof() const { return p >= b().size(); }
    size_t remaining() const { return b().size() - p; }

    uint8_t u8() { return p < b().size() ? b()[p++] : 0; }
    uint16_t u16() {
        uint16_t v = 0;
        for (int i = 0; i < 2 && p < b().size(); ++i) v = (uint16_t)((v << 8) | b()[p++]);
        return v;
    }
    uint32_t u32() {
        uint32_t v = 0;
        for (int i = 0; i < 4 && p < b().size(); ++i) v = (v << 8) | b()[p++];
        return v;
    }

    Bytes take(size_t n) {
        Bytes out;
        while (n-- > 0 && p < b().size()) out.push_back(b()[p++]);
        return out;
    }

    struct Tlv {
        uint32_t tag = 0;
        Bytes val;
    };

    bool tlv(Tlv& out) {
        if (remaining() < 2) return false;
        out.tag = u8();
        size_t l = u8();
        if (l & 0x80) {
            int n = (int)(l & 0x7F);
            if (n == 0 || n > 4) return false;
            l = 0;
            for (int i = 0; i < n && remaining(); ++i) l = (l << 8) | u8();
        }
        if (l > remaining()) return false;
        out.val = take(l);
        return true;
    }
};

struct Rdn {
    std::string oid;
    std::string name;
    std::string value;
    bool printable = false;
};

std::map<std::string, std::string> buildOidMap() {
    return {
        {"2.5.4.3", "CN"}, {"2.5.4.4", "SN"}, {"2.5.4.5", "serialNumber"},
        {"2.5.4.6", "C"}, {"2.5.4.7", "L"}, {"2.5.4.8", "ST"},
        {"2.5.4.9", "street"}, {"2.5.4.10", "O"}, {"2.5.4.11", "OU"},
        {"2.5.4.12", "title"}, {"2.5.4.42", "GN"},
        {"0.9.2342.19200300.100.1.1", "UID"},
        {"0.9.2342.19200300.100.1.25", "DC"},
        {"1.2.840.113549.1.9.1", "emailAddress"},
        {"1.3.6.1.4.1.311.60.2.1.1", "jurisdictionL"},
        {"1.3.6.1.4.1.311.60.2.1.2", "jurisdictionST"},
        {"1.3.6.1.4.1.311.60.2.1.3", "jurisdictionC"},
    };
}

std::string oidToStr(const Bytes& raw) {
    std::string out;
    if (raw.empty()) return out;
    size_t i = 0;
    uint64_t v = 0;
    while (i < raw.size()) {
        v = v * 128 + (raw[i] & 0x7F);
        if (!(raw[i] & 0x80)) {
            if (out.empty()) {
                uint64_t a = std::min<uint64_t>(2, v / 40);
                out += std::to_string(a) + "." + std::to_string(v - a * 40);
            } else {
                out += "." + std::to_string(v);
            }
            v = 0;
        }
        ++i;
    }
    return out;
}

std::string utf16ToUtf8(const Bytes& b, size_t start) {
    std::string out;
    for (size_t i = start; i + 1 < b.size(); i += 2) {
        uint16_t cp = (uint16_t)((b[i] << 8) | b[i + 1]);
        if (cp < 0x80) out += (char)cp;
        else if (cp < 0x800) {
            out += (char)(0xC0 | (cp >> 6));
            out += (char)(0x80 | (cp & 0x3F));
        } else {
            out += (char)(0xE0 | (cp >> 12));
            out += (char)(0x80 | ((cp >> 6) & 0x3F));
            out += (char)(0x80 | (cp & 0x3F));
        }
    }
    return out;
}

std::vector<Rdn> parseName(const Bytes& raw) {
    std::vector<Rdn> out;
    static const std::map<std::string, std::string> names = buildOidMap();
    Der d(raw);
    while (d.remaining() >= 2) {
        Der::Tlv set;
        if (!d.tlv(set)) break;
        Der s(set.val);
        while (s.remaining() >= 2) {
            Der::Tlv rdn;
            if (!s.tlv(rdn)) break;
            Der r(rdn.val);
            Der::Tlv oidT;
            if (!r.tlv(oidT)) break;
            std::string oid = oidToStr(oidT.val);
            Der::Tlv valT;
            if (!r.tlv(valT)) break;
            Rdn x;
            x.oid = oid;
            x.name = names.count(oid) ? names.at(oid) : oid;
            x.value = (valT.tag == 0x1E || valT.tag == 0x0C) ? utf16ToUtf8(valT.val, 0)
                                                               : std::string(valT.val.begin(), valT.val.end());
            x.printable = true;
            out.push_back(x);
        }
    }
    return out;
}

std::string toHexStr(const Bytes& b, size_t from) {
    Bytes t(b.begin() + std::min(from, b.size()), b.end());
    return hexEncode(t.data(), t.size());
}

struct Cert {
    std::vector<Rdn> subject, issuer;
    std::string serial;
    std::string notBefore, notAfter;
    std::string sigAlg;
    std::string tbsSigAlg;
    std::string pubAlg, pubBits;
    std::vector<std::string> san;
    std::vector<std::string> keyUsage;
    std::string version = "v1";
    bool basicConstraintsCA = false;
    int pathLen = -1;
};

std::string toHexStr(const Bytes& b, size_t from);
std::string utf16ToUtf8(const Bytes& b, size_t start);

std::string algOid(const Bytes& oidVal) {
    static const std::map<std::string, std::string> table = {
        {"2a864886f70d010101", "rsaEncryption"},
        {"2a864886f70d01010b", "sha256WithRSAEncryption"},
        {"2a864886f70d01010c", "sha384WithRSAEncryption"},
        {"2a864886f70d01010d", "sha512WithRSAEncryption"},
        {"2a864886f70d010105", "sha1WithRSAEncryption"},
        {"2a864886f70d010104", "md5WithRSAEncryption"},
        {"2a864886f70d010102", "md2WithRSAEncryption"},
        {"2a864886f70d01010a", "rsassaPss"},
        {"2a8648ce38040", "id-ecPublicKey"},
        {"2a8648ce3d0201", "prime256v1 (P-256)"},
        {"2a8648ce3d030107", "secp256r1 (P-256)"},
        {"2a8648ce3d030108", "secp384r1 (P-384)"},
        {"2a8648ce3d030109", "secp521r1 (P-521)"},
        {"2b81040022", "secp384r1 (P-384)"},
        {"2b81040023", "secp521r1 (P-521)"},
        {"2b06010401da470f01", "Ed25519"},
        {"2a8648ce380401", "dsa"},
        {"2a8648ce380102", "dh"},
        {"06082a8648ce3d0401", "ecdsa-with-SHA1"},
        {"06082a8648ce3d040301", "ecdsa-with-SHA256"},
        {"06082a8648ce3d040302", "ecdsa-with-SHA384"},
        {"06082a8648ce3d040303", "ecdsa-with-SHA512"},
        {"06082a8648ce3d0402", "dsa-with-SHA256"},
        {"2a8648ce3d0401", "prime256v1 curve"},
        {"551d13", "basicConstraints"},
        {"551d0f", "keyUsage"},
        {"551d11", "subjectAltName"},
        {"551d25", "extendedKeyUsage"},
        {"2b0601055d0301", "S/MIME email protection"},
        {"2b0601040182370204", "clientAuth"},
        {"2b0601040182370205", "emailProtection"},
    };
    std::string key = toLower(hexEncode(oidVal.data(), oidVal.size()));
    auto it = table.find(key);
    if (it != table.end()) return it->second;
    return "OID 0x" + hexEncode(oidVal.data(), oidVal.size());
}

std::string utcToStr(uint8_t tag, const Bytes& v) {
    if (v.size() < 11) return "(malformed)";
    int y, mo, d, h, mi, se;
    if (tag == 0x17) {
        y = (v[0] - '0') * 10 + (v[1] - '0');
        y += (y < 50) ? 2000 : 1900;
        size_t o = 2;
        mo = (v[o] - '0') * 10 + (v[o + 1] - '0');
        d = (v[o + 2] - '0') * 10 + (v[o + 3] - '0');
        h = (v[o + 4] - '0') * 10 + (v[o + 5] - '0');
        mi = (v[o + 6] - '0') * 10 + (v[o + 7] - '0');
        se = (v[o + 8] - '0') * 10 + (v[o + 9] - '0');
    } else {
        y = (v[0] - '0') * 1000 + (v[1] - '0') * 100 + (v[2] - '0') * 10 + (v[3] - '0');
        size_t o = 4;
        mo = (v[o] - '0') * 10 + (v[o + 1] - '0');
        d = (v[o + 2] - '0') * 10 + (v[o + 3] - '0');
        h = (v[o + 4] - '0') * 10 + (v[o + 5] - '0');
        mi = (v[o + 6] - '0') * 10 + (v[o + 7] - '0');
        se = (v[o + 8] - '0') * 10 + (v[o + 9] - '0');
    }
    if (mo < 1 || mo > 12 || d < 1 || d > 31) return "(malformed)";
    char buf[64];
    snprintf(buf, sizeof(buf), "%04d-%02d-%02d %02d:%02d:%02d UTC", y, mo, d, h, mi, se);
    return buf;
}

std::string algIdToOid(const Bytes& algId) {
    Der d(algId);
    Der::Tlv oid;
    if (d.tlv(oid) && oid.tag == 0x06) return algOid(oid.val);
    return algOid(algId);
}

void parseExtensions(const Bytes& raw, Cert& c) {
    Der top(raw);
    Der::Tlv t;
    while (top.tlv(t)) {
        if (t.tag == 0x30) {
            Der inner(t.val);
            Der::Tlv head;
            if (!inner.tlv(head)) continue;
            if (head.tag == 0x30) {
                Bytes deeper = t.val;
                parseExtensions(deeper, c);
                continue;
            }
            Bytes extBytes = t.val;
            Der ext(extBytes);
            Der::Tlv oid, next;
            if (!ext.tlv(oid)) continue;
            std::string key = toLower(hexEncode(oid.val.data(), oid.val.size()));
            if (!ext.tlv(next)) continue;
            if (next.tag == 0x01 && !ext.tlv(next)) continue;
            if (next.tag != 0x04) continue;
            const Bytes& val = next.val;

            if (key == "551d11") {
                Der vd(val);
                Der::Tlv gn;
                while (vd.tlv(gn)) {
                    if (gn.tag == 0x82) c.san.push_back(utf16ToUtf8(gn.val, 0));
                    else if (gn.tag == 0x81 || gn.tag == 0x86)
                        c.san.push_back(std::string(gn.val.begin(), gn.val.end()));
                    else if (gn.tag == 0x87) {
                        std::string ip;
                        for (size_t i = 0; i < gn.val.size(); ++i) {
                            if (i) ip += ".";
                            ip += std::to_string((int)gn.val[i]);
                        }
                        c.san.push_back(ip);
                    }
                }
            } else if (key == "551d13") {
                Der vd(val);
                Der::Tlv inner2;
                if (vd.tlv(inner2) && inner2.tag == 0x30) {
                    Der bs(inner2.val);
                    c.basicConstraintsCA = bs.remaining() > 0 && bs.u8() != 0;
                    if (c.basicConstraintsCA && bs.remaining() > 0) c.pathLen = bs.u8();
                }
            } else if (key == "551d0f") {
                if (val.size() >= 3) {
                    uint16_t bits = (uint16_t)((val[1] << 8) | val[2]);
                    static const char* names[] = {"digitalSignature", "nonRepudiation",
                        "keyEncipherment", "dataEncipherment", "keyAgreement", "keyCertSign",
                        "cRLSign", "encipherOnly", "decipherOnly"};
                    for (int i = 0; i < 9; ++i)
                        if (bits & (1 << (15 - i))) c.keyUsage.push_back(names[i]);
                }
            }
        }
    }
}

bool parseCert(const Bytes& der, Cert& c) {
    Der root(der);
    Der::Tlv seq;
    if (!root.tlv(seq) || seq.tag != 0x30) return false;

    Der d(seq.val);
    Der::Tlv t;
    Der::Tlv tbsT;
    if (!d.tlv(tbsT)) return false;
    if (!d.tlv(t)) return false;
    c.sigAlg = algIdToOid(t.val);
if (!d.tlv(t)) return false;

Bytes tbsStore = tbsT.val;
Der tbs(tbsStore);
Der::Tlv verT;
if (!tbs.tlv(verT)) return false;
{
    uint32_t ver = 0;
    if (verT.tag == 0xA0 && verT.val.size() >= 3)
        ver = (uint32_t)(verT.val[2] & 0x7F) + 1;
    c.version = ver == 3 ? "v3" : ver == 2 ? "v2" : "v1";
}

    if (!tbs.tlv(t)) return false;
    c.serial = hexEncode(t.val.data(), t.val.size(), ":");

    if (!tbs.tlv(t)) return false;
    c.tbsSigAlg = algIdToOid(t.val);

    if (!tbs.tlv(t)) return false;
    c.issuer = parseName(t.val);

    if (!tbs.tlv(t)) return false;
    {
        Der vt(t.val);
        Der::Tlv nb, na;
        if (vt.tlv(nb)) c.notBefore = utcToStr(nb.tag, nb.val);
        if (vt.tlv(na)) c.notAfter = utcToStr(na.tag, na.val);
    }

    if (!tbs.tlv(t)) return false;
    c.subject = parseName(t.val);

    if (!tbs.tlv(t)) return false;
    {
        Der spki(t.val);
        Der::Tlv alg, bits;
        if (spki.tlv(alg)) c.pubAlg = algIdToOid(alg.val);
        if (spki.tlv(bits)) {
            if (c.pubAlg.find("rsa") != std::string::npos) {
                if (bits.val.size() > 1) {
                    Bytes inner(bits.val.begin() + 1, bits.val.end());
                    Der bk(inner);
                    Der::Tlv keySeq;
                    if (bk.tlv(keySeq)) {
                        Der kk(keySeq.val);
                        Der::Tlv mod;
                        if (kk.tlv(mod)) {
                            size_t z = 0;
                            while (z < mod.val.size() && mod.val[z] == 0) ++z;
                            c.pubBits = std::to_string((mod.val.size() - z) * 8) + " bits";
                        }
                    }
                }
            } else if (c.pubAlg.find("ec") != std::string::npos ||
                       c.pubAlg.find("P-") != std::string::npos ||
                       c.pubAlg.find("Ed25519") != std::string::npos) {
                c.pubBits = "elliptic curve";
            } else {
                c.pubBits = std::to_string(bits.val.size() * 8) + " bits";
            }
        }
    }

    while (tbs.tlv(t)) {
        if (t.tag != 0xA3) continue;
        parseExtensions(t.val, c);
    }
    return true;
}

Bytes pemToDer(const std::string& pem) {
    std::string all;
    for (auto& line : splitLines(pem)) {
        std::string t = trim(line);
        if (t.empty() || startsWith(t, "-----")) continue;
        for (char c : t)
            if (isalnum((unsigned char)c) || c == '+' || c == '/' || c == '=') all += c;
    }
    return base64Decode(all);
}

int runX509(const Args& a) {
    ui::section("X.509 CERTIFICATE PARSER");

    std::string file = a.opt("file");
    if (file.empty() && !a.first().empty()) file = a.first();
    if (file.empty()) {
        ui::fail("pass a PEM/DER certificate: argus x509 --file cert.pem");
        ui::info("openssl x509 -in cert.pem -outform der > cert.der   then: argus x509 --file cert.der");
        return 1;
    }

    std::string content;
    std::string err;
    if (!readTextFile(file, content, &err)) { ui::fail(err); return 1; }

    std::vector<Bytes> derList;
    std::vector<std::string> blocks;
    size_t pos = 0;
    while (true) {
        size_t s = content.find("-----BEGIN CERTIFICATE-----", pos);
        if (s == std::string::npos) break;
        size_t e = content.find("-----END CERTIFICATE-----", s);
        if (e == std::string::npos) break;
        derList.push_back(pemToDer(content.substr(s, e - s)));
        blocks.push_back("block " + std::to_string(derList.size()));
        pos = e + 10;
    }
    if (derList.empty()) derList.push_back(textToBytes(content));

    ui::kv("file", file);
    ui::kv("certificates", std::to_string(derList.size()));
    ui::line("");

    std::vector<Finding> allFs;
    time_t now = time(nullptr);

    for (size_t ci = 0; ci < derList.size(); ++ci) {
        Cert c;
        if (!parseCert(derList[ci], c)) {
            ui::fail("could not parse certificate #" + std::to_string(ci + 1));
            allFs.push_back({"X-PARSE", "DER structure invalid at certificate #" + std::to_string(ci + 1), 2});
            continue;
        }
        if (derList.size() > 1)
            ui::section("CERTIFICATE #" + std::to_string(ci + 1));

        std::string subj = c.subject.empty() ? "(empty)" : "";
        for (size_t i = 0; i < c.subject.size(); ++i) {
            subj += (i ? ", " : "");
            subj += c.subject[i].name + "=" + c.subject[i].value;
        }
        std::string iss = c.issuer.empty() ? "(empty)" : "";
        for (size_t i = 0; i < c.issuer.size(); ++i) {
            iss += (i ? ", " : "");
            iss += c.issuer[i].name + "=" + c.issuer[i].value;
        }

        ui::kv("version", c.version);
        ui::kv("subject", ui::truncateTo(subj, 56));
        ui::kv("issuer", ui::truncateTo(iss, 56));
        ui::kv("serial", ui::truncateTo(c.serial, 56));
        ui::kv("valid from", c.notBefore);
        ui::kv("valid to", c.notAfter);
        ui::kv("public key", c.pubAlg + (c.pubBits.empty() ? "" : "  " + c.pubBits));
        ui::kv("signature alg", c.sigAlg);
        ui::kv("basic constraints", c.basicConstraintsCA
                                         ? ("CA=true" + (c.pathLen >= 0 ? "  pathlen=" + std::to_string(c.pathLen) : "  pathlen=unlimited"))
                                         : "CA=false");
        ui::kv("key usage", c.keyUsage.empty() ? "(absent)" : join(c.keyUsage, ", "));
        if (!c.san.empty()) ui::kv("subject alt names", ui::truncateTo(join(c.san, ", "), 56));
        ui::line("");

        std::vector<Finding> fs;
        std::string sig = toLower(c.sigAlg);
        if (sig.find("md5") != std::string::npos || sig.find("md2") != std::string::npos)
            fs.push_back({"X-SIG-MD", "MD2/MD5 signature: practically forgeable", 3});
        else if (sig.find("sha1") != std::string::npos)
            fs.push_back({"X-SIG-SHA1", "SHA-1 signature: deprecated since 2016", 3});
        else if (sig.find("sha256") != std::string::npos)
            fs.push_back({"X-SIG-OK", "SHA-256 signature: acceptable", 0});

        if (c.pubAlg.find("rsa") != std::string::npos && c.pubBits.find("bits") != std::string::npos) {
            size_t ul = 0;
            std::string bits = regexFind(c.pubBits, "(\\d+)", 1, &ul);
            int b = bits.empty() ? 0 : std::atoi(bits.c_str());
            if (b > 0 && b < 2048) fs.push_back({"X-KEY-SMALL", "RSA key " + std::to_string(b) + " bits: too weak", 3});
            else if (b > 0 && b < 3072) fs.push_back({"X-KEY-MID", "RSA key " + std::to_string(b) + " bits: acceptable", 1});
        }
        if (c.pubAlg.find("P-256") != std::string::npos || c.pubAlg.find("ecdsa-with-SHA256") != std::string::npos)
            fs.push_back({"X-KEY-EC", "P-256 / ECDSA: acceptable", 0});
        if (c.pubAlg.find("Ed25519") != std::string::npos)
            fs.push_back({"X-KEY-ED", "Ed25519: modern and strong", 0});

        size_t ul2 = 0;
        std::string expYear = regexFind(c.notAfter, "(\\d{4})", 1, &ul2);
        std::string nbYear = regexFind(c.notBefore, "(\\d{4})", 1, &ul2);
        if (!expYear.empty()) {
            int ey = std::atoi(expYear.c_str());
            int ny = nbYear.empty() ? ey : std::atoi(nbYear.c_str());
            if (ey < now - 31536000)
                fs.push_back({"X-EXPIRED", "certificate expired in " + expYear, 3});
            else if (ey >= now)
                fs.push_back({"X-VALID", "currently valid (expires " + expYear + ")", 0});
            int life = ey - ny;
            if (life > 39)
                fs.push_back({"X-LIFETIME", "validity period of " + std::to_string(life) +
                                            " years exceeds the CABF maximum of 398 days", 2});
            else if (life > 1)
                fs.push_back({"X-LIFETIME", "validity period of " + std::to_string(life) + " years", 1});
        }
        if (subj == "(empty)")
            fs.push_back({"X-NOSUBJ", "empty subject: violates CABF BR 7.1.4.2.2", 2});
        for (auto& s : c.san)
            if (toLower(s).find(".internal") != std::string::npos ||
                toLower(s).find(".local") != std::string::npos)
                fs.push_back({"X-INTERNAL-SAN", "internal name in a publicly trusted certificate: " + s, 1});
        for (auto& s : c.subject) {
            if (s.name == "CN" && s.value.find(' ') != std::string::npos && s.value.size() > 20)
                fs.push_back({"X-CN-LONG", "CN '" + ui::truncateTo(s.value, 28) +
                                            "' is long: could hide the real identity", 1});
        }
        if (!iss.empty() && subj != iss && c.basicConstraintsCA && c.pathLen == 0)
            fs.push_back({"X-LEAF-CA", "leaf certificate has CA=true but pathlen=0", 2});
        if (c.keyUsage.empty())
            fs.push_back({"X-NOKU", "keyUsage extension absent: all uses implicitly allowed", 2});
        else {
            bool hasDigital = false, hasKeyEnc = false;
            for (auto& k : c.keyUsage) {
                if (k == "digitalSignature") hasDigital = true;
                if (k == "keyEncipherment") hasKeyEnc = true;
            }
            if (!hasDigital && !hasKeyEnc)
                fs.push_back({"X-KU-ODD", "unusual key usage set for an end-entity certificate", 1});
        }
        if (!c.san.empty()) {
            bool hasCn = false;
            for (auto& s : c.subject) if (s.name == "CN") hasCn = true;
            if (!hasCn) fs.push_back({"X-CN-NOTIN-SAN", "subject CN is absent from SAN: modern clients ignore CN", 2});
        }
        for (auto& f : fs) allFs.push_back(f);
        if (fs.size() > 1 || derList.size() > 1) renderFindings(fs);
        else if (fs.size() == 1) reportFinding(fs[0]);
    }

    ui::line("");
    if (allFs.empty()) {
        ui::ok("no certificate issues detected");
        ui::line("");
    } else {
        ui::line("");
        ui::info("verify chain and revocation with openssl s_client -connect host:443 -showcerts");
        ui::line("");
    }
    int bad = 0;
    for (auto& f : allFs) if (f.sev >= 2) ++bad;
    return bad ? 1 : 0;
}

}  // namespace

CK_TOOL("x509", "forensics", "Parse PEM/DER X.509 certificates and flag weak signatures, keys and SAN policy",
        "argus x509 --file cert.pem  |  argus x509 ./chain.pem", runX509);
