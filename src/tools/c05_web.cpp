#include "common.h"

#include <cstring>
#include <set>
#include <map>
#include <algorithm>

using namespace ck;
using namespace ck::tools;

namespace {

const std::string V_GREEN = "\033[38;5;46m";
const std::string V_YEL = "\033[38;5;214m";
const std::string V_RED = "\033[38;5;196m";
const std::string V_DIM = "\033[2;37m";
const std::string V_RESET = "\033[0m";

struct TlsProbe {
    std::string protocol;
    int code = 0;
    std::string cipher = "";
    std::string peer = "";
    std::string verification = "";
};

TlsProbe opensslProbe(const std::string& host, uint16_t port, const std::string& proto) {
    TlsProbe p;
    p.protocol = proto;
    std::string cmd = "echo | openssl s_client -connect " + host + ":" + std::to_string(port) +
                      " -" + proto + " -brief 2>&1";
    bool ok = false;
    std::string out = runCapture(cmd, 12000, &ok);
    if (out.find("no protocols available") != std::string::npos ||
        out.find("unsupported protocol") != std::string::npos ||
        out.find("wrong version number") != std::string::npos ||
        out.find("alert protocol version") != std::string::npos) {
        p.code = -2;
        return p;
    }
    if (out.find("Protocol version") == std::string::npos && out.find("CONNECTED") == std::string::npos &&
        out.empty()) {
        p.code = -1;
        return p;
    }
    p.code = 0;
    size_t l = 0;
    p.cipher = trim(regexFind(out, "Ciphersuite:\\s*(.+)", 1, &l));
    p.peer = trim(regexFind(out, "Peer certificate:\\s*(.+)", 1, &l));
    p.verification = trim(regexFind(out, "Verification:\\s*(.+)", 1, &l));
    if (p.cipher.empty()) p.cipher = trim(regexFind(out, "Cipher\\s*:\\s*(.+)", 1, &l));
    if (p.verification.empty()) p.verification = trim(regexFind(out, "Verify return code:.*\\((.+)\\)", 1, &l));
    return p;
}

int tlsAgainstHost(const Args& a, const std::string& host, uint16_t port) {
    if (!requireAuthorization(a, host)) return 2;

    ui::section("LIVE PROBE  " + host + ":" + std::to_string(port));
    if (which("openssl").empty()) {
        ui::fail("openssl not found on PATH; cannot perform a live TLS handshake probe");
        ui::info("run: argus tls-audit --file nginx.conf   (offline config analysis works without openssl)");
        return 3;
    }

    static const char* protos[] = {"tls1", "tls1_1", "tls1_2", "tls1_3"};
    static const char* labels[] = {"TLS 1.0", "TLS 1.1", "TLS 1.2", "TLS 1.3"};
    std::vector<TlsProbe> results;
    for (int i = 0; i < 4; ++i) results.push_back(opensslProbe(host, port, protos[i]));

    std::vector<std::vector<std::string>> rows;
    for (size_t i = 0; i < results.size(); ++i) {
        auto& r = results[i];
        std::string state = r.code == 0 ? std::string(V_GREEN) + "ACCEPTED" + V_RESET
                          : r.code == -2 ? std::string(V_DIM) + "REJECTED" + V_RESET
                                         : std::string(V_RED) + "ERROR" + V_RESET;
        rows.push_back({labels[i], state, r.cipher.empty() ? "-" : r.cipher,
                        r.verification.empty() ? "-" : r.verification});
    }
    ui::table({"VERSION", "NEGOTIATION", "CIPHER", "CERT VERIFY"}, rows);
    ui::line("");

    std::vector<Finding> fs;
    if (results[0].code == 0) fs.push_back({"T-TLS10", "server accepts TLS 1.0 (RFC 8996 deprecates it)", 3});
    if (results[1].code == 0) fs.push_back({"T-TLS11", "server accepts TLS 1.1 (deprecated, no AEAD)", 3});
    if (results[2].code == 0) fs.push_back({"T-TLS12", "server accepts TLS 1.2: acceptable", 0});
    if (results[3].code == 0) fs.push_back({"T-TLS13", "server accepts TLS 1.3: preferred", 0});
    if (results[0].code != 0 && results[1].code != 0 && results[2].code != 0 && results[3].code != 0)
        fs.push_back({"T-NOHANDSHAKE", "no TLS version negotiated: wrong port, blocking middlebox, or openssl failed", 2});
    if (results[3].code != 0 && results[2].code == 0)
        fs.push_back({"T-NO13", "TLS 1.3 not offered while 1.2 is: downgrade risk and lost modern AEADs", 2});
    for (auto& r : results) {
        if (r.code == 0 && r.verification.empty())
            fs.push_back({"T-NOVERIFY", "no certificate verification reported: likely a self-signed or untrusted chain", 2});
        if (r.code == 0 && !r.verification.empty() &&
            !icontains(r.verification, "OK"))
            fs.push_back({"T-CHAIN", "certificate verification says: " + r.verification, 2});
        if (r.code == 0 && !r.cipher.empty()) {
            std::string c = toUpper(r.cipher);
            if (c.find("RC4") != std::string::npos || c.find("DES") != std::string::npos ||
                c.find("3DES") != std::string::npos || c.find("NULL") != std::string::npos ||
                c.find("EXPORT") != std::string::npos)
                fs.push_back({"T-WEAK-CIPHER", "broken cipher negotiated: " + r.cipher, 3});
            else if (c.find("CBC") != std::string::npos && results[2].code == 0)
                fs.push_back({"T-CBC", "CBC mode cipher negotiated (" + r.cipher + "): prefer AEAD suites", 1});
        }
    }
    renderFindings(fs);
    return 0;
}

int tlsFromConfig(const Args& a, const std::string& file) {
    std::string cfg;
    std::string err;
    if (!readTextFile(file, cfg, &err)) { ui::fail(err); return 1; }

    std::vector<std::vector<std::string>> rows;
    int lineNo = 0;
    for (auto& rawLine : splitLines(cfg)) {
        std::string l = trim(rawLine);
        if (l.empty() || l[0] == '#') continue;
        ++lineNo;
        rows.push_back({std::to_string(lineNo), ui::truncateTo(l, 66)});
    }
    ui::section("CONFIG  " + file);
    ui::table({"LINE", "DIRECTIVE"}, rows);

    std::string low = toLower(cfg);
    std::vector<Finding> fs;

    auto hasDirective = [&](const std::string& d) { return icontains(low, d); };

    if (hasDirective("ssl_protocols") || hasDirective("tlsversions") || hasDirective("protocols")) {
        fs.push_back({"C-PROTO-SET", "TLS protocol list is configured; verify TLS 1.0/1.1 are absent", 0});
    } else {
        fs.push_back({"C-PROTO-DEFAULT", "no explicit protocol directive: server default may still allow TLS 1.0", 1});
    }
    if (icontains(low, "ssl_protocols") &&
        (icontains(low, "tlsv1 ") || icontains(low, "tlsv1_1") || endsWith(trim(low), "tlsv1"))) {
        fs.push_back({"C-TLS10", "TLS 1.0 appears in the protocol list", 3});
    }
    if (icontains(low, "ssl_ciphers") && icontains(low, "rc4"))
        fs.push_back({"C-RC4", "RC4 in the cipher list", 3});
    if (icontains(low, "ssl_ciphers") && (icontains(low, "3des") || icontains(low, "des-cbc")))
        fs.push_back({"C-3DES", "3DES in the cipher list: Sweet32 and birthday-bound", 3});
    if (icontains(low, "ssl_ciphers") && icontains(low, "null"))
        fs.push_back({"C-NULL", "NULL cipher in the list: no encryption at all", 3});
    if (icontains(low, "ssl_ciphers") && icontains(low, "cbc") && !icontains(low, "gcm"))
        fs.push_back({"C-CBC-ONLY", "cipher list has CBC but no GCM or ChaCha20-Poly1305", 2});
    if (hasDirective("ssl_prefer_server_ciphers") || hasDirective("ciphersuites") ||
        hasDirective("ssl_ecdh_curve"))
        fs.push_back({"C-MODERN", "modern directives present (cipher preference / ECDH curves)", 0});
    if (!hasDirective("ssl_prefer_server_ciphers") && icontains(low, "ssl_ciphers"))
        fs.push_back({"C-CIPHERORDER", "client cipher order decides; prefer_server_ciphers off can select weak suites", 1});
    if (icontains(low, "ssl_session_cache") || icontains(low, "sessiontickets"))
        fs.push_back({"C-SESSIONS", "session tickets or cache configured: verify keys rotate and forward secrecy holds", 1});
    if (!icontains(low, "hsts") && (icontains(low, "server_name") || icontains(low, "listen 443")))
        fs.push_back({"C-NOHSTS", "no HSTS directive in an HTTPS config", 1});
    else if (icontains(low, "hsts") &&
             (icontains(low, "max-age=0;") || icontains(low, "max-age=0\"") ||
              icontains(low, "max-age=0 ")))
        fs.push_back({"C-HSTS-OFF", "HSTS is configured with max-age=0, which disables it entirely", 2});
    if (icontains(low, "ssl_certificate") && !icontains(low, "ssl_dhparam") && !icontains(low, "ffdhe"))
        fs.push_back({"C-DHPARAM", "no ssl_dhparam / ffdhe directive: DHE ciphers may fall back to unsafe defaults", 1});
    if (icontains(low, "ssl_stapling") && icontains(low, "off"))
        fs.push_back({"C-NOSTAPLE", "OCSP stapling disabled", 1});
    if (icontains(low, "ssl_ecdh_curve") && icontains(low, "secp256r1") && !icontains(low, "x25519"))
        fs.push_back({"C-CURVE", "curve list lacks x25519", 2});

    renderFindings(fs);
    int cfgBad = 0;
    for (auto& f : fs)
        if (f.sev >= 2) ++cfgBad;
    return cfgBad ? 1 : 0;
}

int runTlsAudit(const Args& a) {
    ui::section("TLS / SSL CONFIGURATION AUDIT");

    std::string host = a.opt("host");
    std::string file = a.opt("file");
    if (file.empty() && !a.first().empty()) {
        IpAddr probe;
        bool isIp = parseIp(a.first(), probe);
        if (!isIp && (std::find(a.first().begin(), a.first().end(), '.') == a.first().end() || fileExists(a.first())))
            file = a.first();
        else
            host = a.first();
    }

    if (!file.empty()) return tlsFromConfig(a, file);
    if (host.empty()) {
        ui::fail("pass --host <name> to probe or --file <nginx.conf|apache.conf> to analyse offline");
        ui::info("argus tls-audit --host lab.internal        (needs --i-own-this or an allowlist entry)");
        ui::info("argus tls-audit --file /etc/nginx/ssl.conf");
        return 1;
    }
    uint16_t port = (uint16_t)std::atoi(a.opt("port", "443").c_str());
    return tlsAgainstHost(a, host, port);
}

// ------------------------------------------------------------ http audit
struct HttpResp {
    bool ok = false;
    int status = 0;
    std::string headers;
    std::string body;
    std::string url;
};

HttpResp httpGet(const std::string& url, int timeoutMs, bool followRedirect = true) {
    HttpResp r;
    r.url = url;
    std::string cur = url;
    for (int hop = 0; hop < 5; ++hop) {
        bool ok = false;
        std::string out = runCapture(
            "curl -s -i --max-time " + std::to_string(timeoutMs / 1000) +
            (followRedirect ? "" : " --max-redirs 0") + " -D - -o - \"" + cur + "\" 2>/dev/null",
            timeoutMs + 4000, &ok);
        if (out.empty()) return r;
        size_t hdrEnd = out.find("\r\n\r\n");
        size_t sep = 4;
        if (hdrEnd == std::string::npos) {
            hdrEnd = out.find("\n\n");
            sep = 2;
        }
        if (hdrEnd == std::string::npos) {
            r.headers = out;
            r.ok = true;
            break;
        }
        std::string head = out.substr(0, hdrEnd);
        std::string body = out.substr(hdrEnd + sep);
        if (r.headers.empty()) {
            r.headers = head;
            r.body = body;
        }
        r.ok = true;
        std::string statusLine = splitLines(head)[0];
        std::vector<std::string> stParts = split(statusLine, ' ');
        r.status = std::atoi(stParts.size() > 1 ? stParts[1].c_str() : "0");
        if (!followRedirect || (r.status < 300 || r.status >= 400)) break;
        size_t l = 0;
        std::string loc = trim(regexFind(head, "(?im)^location:\\s*(.+)$", 1, &l));
        if (loc.empty()) break;
        if (loc.rfind("http", 0) != 0) {
            size_t schemeEnd = cur.find("://");
            size_t slash = cur.find('/', schemeEnd == std::string::npos ? 0 : schemeEnd + 3);
            std::string base = slash == std::string::npos ? cur : cur.substr(0, slash);
            loc = startsWith(loc, "/") ? base + loc : base + "/" + loc;
        }
        cur = loc;
        if (hop == 0) { r.body = body; r.headers = head; }
    }
    return r;
}

int runHttpAudit(const Args& a) {
    ui::section("HTTP SECURITY AUDIT");

    std::string url = a.opt("url");
    std::string host = a.opt("host");
    std::string file = a.opt("file");
    std::string source;
    std::string headers;

    if (!file.empty()) {
        std::string err;
        if (!readTextFile(file, headers, &err)) { ui::fail(err); return 1; }
        source = file;
    } else if (!url.empty() || !host.empty()) {
        if (url.empty()) {
            host = host.empty() && !a.first().empty() ? a.first() : host;
            if (host.empty()) {
                ui::fail("pass --url <url> or --host <host>");
                return 1;
            }
            std::string scheme = toLower(a.opt("scheme", "https"));
            if (scheme != "http" && scheme != "https") {
                ui::fail("--scheme must be http or https");
                return 1;
            }
            std::string port = a.opt("port");
            if (!port.empty() &&
                (port == "80" || port == "443")) port.clear();
            url = scheme + "://" + host + (port.empty() ? "" : ":" + port);
        }
        if (!requireAuthorization(a, url)) return 2;
        if (which("curl").empty()) {
            ui::fail("curl not found on PATH");
            return 3;
        }
        ui::info("fetching " + url);
        HttpResp r = httpGet(url, std::atoi(a.opt("timeout", "10000").c_str()),
                             !a.flag("no-follow"));
        if (!r.ok) {
            ui::fail("no HTTP response from " + url);
            return 1;
        }
        headers = r.headers;
        source = r.url;
        ui::kv("status", std::to_string(r.status));
    } else {
        ui::fail("pass --url https://host, --host host, or --file headers.txt");
        return 1;
    }

    ui::section("RESPONSE HEADERS  " + source);
    std::map<std::string, std::string> H;
    for (auto& l : splitLines(headers)) {
        size_t c = l.find(':');
        if (c == std::string::npos) continue;
        H[toLower(trim(l.substr(0, c)))] = trim(l.substr(c + 1));
    }
    std::vector<std::vector<std::string>> rows;
    for (auto& kv : H) rows.push_back({kv.first, ui::truncateTo(kv.second, 54)});
    ui::table({"HEADER", "VALUE"}, rows);
    ui::line("");

    std::vector<Finding> fs;
    auto has = [&](const char* k) { return H.count(toLower(k)) > 0; };
    auto val = [&](const char* k) { return H.count(toLower(k)) ? H[toLower(k)] : std::string(); };

    ui::section("FINDINGS");
    if (!has("strict-transport-security"))
        fs.push_back({"H-NO-HSTS", "Strict-Transport-Security missing: downgrade to http is possible", 2});
    else {
        std::string v = val("strict-transport-security");
        size_t l = 0;
        std::string maxAge = regexFind(v, "max-age\\s*=\\s*(\\d+)", 1, &l);
        if (maxAge.empty()) fs.push_back({"H-HSTS-NOAGE", "HSTS without max-age is ignored by browsers", 3});
        else if (atoll(maxAge.c_str()) < 15552000)
            fs.push_back({"H-HSTS-SHORT", "HSTS max-age " + maxAge + "s is below the 180-day baseline", 2});
        if (!icontains(v, "includesubdomains"))
            fs.push_back({"H-HSTS-SUB", "HSTS lacks includeSubDomains", 2});
        if (icontains(v, "preload"))
            fs.push_back({"H-HSTS-PRELOAD", "preload directive present: confirm the domain is actually submitted", 0});
    }
    if (!has("content-security-policy"))
        fs.push_back({"H-NO-CSP", "Content-Security-Policy missing: no XSS mitigation layer", 2});
    else {
        std::string csp = val("content-security-policy");
        if (icontains(csp, "unsafe-inline")) fs.push_back({"H-CSP-INLINE", "CSP allows unsafe-inline", 2});
        if (icontains(csp, "unsafe-eval")) fs.push_back({"H-CSP-EVAL", "CSP allows unsafe-eval", 2});
        if (!icontains(csp, "default-src") && !icontains(csp, "script-src"))
            fs.push_back({"H-CSP-NOSRC", "CSP has no default-src or script-src", 2});
        if (csp.find(';') == std::string::npos && csp.find(' ') != std::string::npos)
            fs.push_back({"H-CSP-FORMAT", "CSP may be missing semicolons between directives", 2});
    }
    if (!has("x-frame-options") && !icontains(val("content-security-policy"), "frame-ancestors"))
        fs.push_back({"H-CLICKJACK", "no X-Frame-Options and no frame-ancestors: clickjacking possible", 2});
    if (!has("x-content-type-options"))
        fs.push_back({"H-NOCTO", "X-Content-Type-Options: nosniff missing", 1});
    else if (toLower(val("x-content-type-options")) != "nosniff")
        fs.push_back({"H-CTO-BAD", "X-Content-Type-Options is not nosniff", 2});
    if (!has("referrer-policy"))
        fs.push_back({"H-NOREF", "Referrer-Policy missing: URLs leak to third parties", 1});
    else {
        std::string rp = toLower(val("referrer-policy"));
        if (rp.find("strict-origin") == std::string::npos && rp.find("no-referrer") == std::string::npos)
            fs.push_back({"H-REF-WEAK", "Referrer-Policy '" + rp + "' leaks path information", 1});
    }
    if (!has("permissions-policy"))
        fs.push_back({"H-NOPERM", "Permissions-Policy missing", 0});

    std::string cookie = val("set-cookie");
    if (cookie.empty() && H.count("set-cookie2")) cookie = H["set-cookie2"];
    if (!cookie.empty()) {
        std::string cl = toLower(cookie);
        if (cl.find("secure") == std::string::npos)
            fs.push_back({"C-NOSECURE", "cookie without Secure: sent over plain http", 2});
        if (cl.find("httponly") == std::string::npos)
            fs.push_back({"C-NOHTTPONLY", "cookie without HttpOnly: readable by JavaScript", 2});
        if (cl.find("samesite") == std::string::npos)
            fs.push_back({"C-NOSAMESITE", "cookie without SameSite: CSRF exposure", 1});
        else if (cl.find("samesite=none") != std::string::npos && cl.find("secure") == std::string::npos)
            fs.push_back({"C-SAMESITE-NONE", "SameSite=None without Secure is rejected outright", 2});
    } else {
        fs.push_back({"C-NOCOOKIE", "no Set-Cookie observed in this response", 0});
    }

    if (!has("server")) fs.push_back({"H-NOSERVER", "Server header absent (good: reduced fingerprinting)", 0});
    else {
        std::string sv = toLower(val("server"));
        if (!sv.empty() && sv.find("apache") != std::string::npos)
            fs.push_back({"H-SERVER-INFO", "Server: " + val("server") + " discloses the stack and version", 1});
        else
            fs.push_back({"H-SERVER", "Server: " + val("server"), 1});
    }
    if (has("x-powered-by"))
        fs.push_back({"H-POWERED", "X-Powered-By discloses the framework", 1});
    if (has("access-control-allow-origin")) {
        std::string acao = trim(val("access-control-allow-origin"));
        if (acao == "*")
            fs.push_back({"H-CORS-WILD", "Access-Control-Allow-Origin: * on an authenticated endpoint", 2});
        std::string acac = toLower(val("access-control-allow-credentials"));
        if (acao != "*" && acac == "true" && !acao.empty())
            fs.push_back({"H-CORS-CRED", "CORS allows credentials from a reflected origin", 2});
    }
    if (has("strict-transport-security") && icontains(headers, "http://"))
        fs.push_back({"H-MIXED", "plaintext content served alongside HSTS", 2});

    ui::kv("headers parsed", std::to_string(H.size()));
    ui::line("");
    renderFindings(fs);
    int bad = 0;
    for (auto& f : fs) if (f.sev >= 2) ++bad;
    return bad ? 1 : 0;
}

}  // namespace

CK_TOOL("tls-audit", "network", "Probe TLS versions/ciphers and audit server config files",
        "argus tls-audit --host lab.internal [--port 443] [--i-own-this]  |  --file nginx.conf",
        runTlsAudit);
CK_TOOL("http-audit", "network", "Audit HTTP security headers, cookies and CORS policy",
        "argus http-audit --url https://host  |  --host host [--i-own-this]  |  --file headers.txt",
        runHttpAudit);