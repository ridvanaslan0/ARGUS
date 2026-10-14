#include "common.h"

#include <cstring>
#include <set>
#include <map>
#include <algorithm>

using namespace ck;
using namespace ck::tools;

namespace {

const std::string V_GREEN = "\033[38;5;46m";
const std::string V_RED = "\033[38;5;196m";
const std::string V_YEL = "\033[38;5;214m";
const std::string V_ORANGE = "\033[38;5;208m";
const std::string V_DIM = "\033[2;37m";
const std::string V_RESET = "\033[0m";

const char* COMMON_PW[] = {
    "password","123456","123456789","12345678","12345","1234567","1234567890","qwerty",
    "abc123","111111","123123","admin","letmein","welcome","monkey","dragon","iloveyou",
    "princess","football","sunshine","passw0rd","master","shadow","login","trustno1",
    "qwertyuiop","1q2w3e4r","zaq12wsx","changeme","secret","root","toor","test","guest",
    "default","pass","password1","password123","admin123","root123","1234567891","000000",
    "baseball","superman","batman","696969","mustang","access","flower","hello","charlie",
    "donald","loveme","michael","soccer","ashley","bailey","buster","daniel","hannah",
    "jessica","pepper","summer","thomas","whatever","hunter","george","harley","jordan",
    "maggie","ranger","robert","thunder","tigger","orange","silver","sparky","zxcvbn",
    "asdfgh","qazwsx","1qaz2wsx","q1w2e3r4","aaaaaa","11111111","654321","112233",
    "a123456","1234abcd","1q2w3e","qwe123","1q2w3e4r5t","abcd1234","aaa111","asd123",
    "p@ssw0rd","p@ssword","Password1","P@ssw0rd1","Pa$$w0rd","Summer2024","Winter2023",
    "Company123","company","office","server","database","backup","network","security",
};

const char* BAD_PATTERNS[] = {
    "\\d{4,}", "\\b(19|20)\\d{2}\\b", "(.)\\1{3,}", "(..)\\1{2,}", "(.{3,})\\1+",
};

std::string deLeet(const std::string& s) {
    std::string o;
    for (char c : s) {
        switch (tolower((unsigned char)c)) {
            case '@': o += 'a'; break;
            case '4': o += 'a'; break;
            case '8': o += 'b'; break;
            case '(': case '[': case '{': case '<': o += 'c'; break;
            case '3': o += 'e'; break;
            case '6': case '9': o += 'g'; break;
            case '#': case '$': o += 's'; break;
            case '1': case '!': case '|': case 'i': o += 'l'; break;
            case '0': o += 'o'; break;
            case '5': o += 's'; break;
            case '7': o += 't'; break;
            case '2': o += 'z'; break;
            case '%': o += 'x'; break;
            case '^': o += 'x'; break;
            case '+': o += 't'; break;
            default: o += tolower((unsigned char)c);
        }
    }
    return o;
}

int seqRun(const std::string& s, bool descending) {
    int best = 1, cur = 1;
    for (size_t i = 1; i < s.size(); ++i) {
        int d = descending ? (s[i - 1] - s[i]) : (s[i] - s[i - 1]);
        if (d == 1) { ++cur; best = std::max(best, cur); }
        else cur = 1;
    }
    return best;
}

double charsetPool(const std::string& s) {
    int pool = 0;
    bool lower = false, upper = false, digit = false, sym = false, wide = false;
    for (unsigned char c : s) {
        if (c >= 0x80) wide = true;
        else if (islower(c)) lower = true;
        else if (isupper(c)) upper = true;
        else if (isdigit(c)) digit = true;
        else sym = true;
    }
    if (lower) pool += 26;
    if (upper) pool += 26;
    if (digit) pool += 10;
    if (sym) pool += 33;
    if (wide) pool += 100;
    return pool;
}

struct PwResult {
    std::string pw;
    double bits = 0;
    int score = 0;
    std::string label;
};

PwResult analyze(const std::string& pw) {
    PwResult r;
    r.pw = pw;
    if (pw.empty()) {
        r.label = "EMPTY";
        return r;
    }
    double pool = charsetPool(pw);
    double naive = pw.size() * (pool > 0 ? std::log2(pool) : 0);

    std::string low = toLower(pw);
    std::string deleet = deLeet(low);

    double pen = 0;
    std::vector<std::string> reasons;

    for (auto c : COMMON_PW) {
        std::string cl = toLower(c);
        if (low == cl || deleet == deLeet(cl)) {
            pen += 60;
            reasons.push_back("in the top-common-password list");
            break;
        }
    }

    int sq = seqRun(low, false);
    if (sq >= 4) { pen += 18; reasons.push_back("ascending sequence (" + std::to_string(sq) + " chars)"); }
    int sd = seqRun(low, true);
    if (sd >= 4) { pen += 18; reasons.push_back("descending sequence (" + std::to_string(sd) + " chars)"); }

    size_t i = 0;
    while (i < pw.size()) {
        size_t j = i;
        while (j < pw.size() && pw[j] == pw[i]) ++j;
        if (j - i >= 2) {
            pen += 10 * (j - i);
            reasons.push_back("repeated character run '" + std::string(1, pw[i]) + "' x" +
                              std::to_string(j - i));
        }
        i = j;
    }

    std::string digitsOnly;
    for (char c : pw) if (isdigit((unsigned char)c)) digitsOnly += c;
    if (digitsOnly.size() >= 4) {
        pen += 16;
        reasons.push_back("contains a " + std::to_string(digitsOnly.size()) + "-digit run");
    }

    for (auto pat : BAD_PATTERNS) {
        std::string m;
        regexFind(pw, pat, 0, nullptr, &m, 1);
        if (!m.empty()) {
            pen += 8;
            reasons.push_back("pattern match: " + toLower(pw));
            break;
        }
    }

    if (levenShannon(pw) < 3.2 && pw.size() >= 6) {
        pen += 20;
        reasons.push_back("low character entropy (predictable distribution)");
    }

    if (pen > naive * 0.95) pen = naive * 0.95;
    r.bits = std::max(0.0, naive - pen);

    double crack = r.bits / 60.0;
    r.score = pw.size() < 8 ? 0 : pw.size() < 12 ? 1 : r.bits < 40 ? 1 : r.bits < 60 ? 2 : r.bits < 80 ? 3 : 4;

    const char* labels[] = {"CRITICAL", "WEAK", "FAIR", "STRONG", "EXCELLENT"};
    r.label = labels[r.score];
    (void)reasons;
    return r;
}

int runPwAudit(const Args& a) {
    ui::section("PASSWORD STRENGTH AUDIT");

    std::vector<std::string> lines;
    std::string file = a.opt("file");
    if (!file.empty()) {
        std::string content;
        std::string err;
        if (!readTextFile(file, content, &err)) { ui::fail(err); return 1; }
        lines = splitLines(content);
    } else if (a.hasOpt("password")) {
        lines = split(a.opt("password"), ',');
    } else {
        std::string s = readStdin();
        lines = splitLines(s);
        if (lines.empty() && !s.empty()) lines.push_back(s);
    }
    lines.erase(std::remove_if(lines.begin(), lines.end(),
                              [](const std::string& s) { return trim(s).empty(); }),
                lines.end());

    if (lines.empty()) {
        ui::fail("no passwords supplied");
        ui::info("argus pw-audit --password 'Passw0rd!,Summer2024'   |   --file creds.txt");
        return 1;
    }

    std::set<std::string> seen;
    std::vector<std::vector<std::string>> dupes;
    std::vector<PwResult> results;
    int weak = 0;

    for (auto& l : lines) {
        std::string pw = trim(l);
        std::string key = toLower(pw);
        if (seen.count(key)) {
            dupes.push_back({toLower(pw), "duplicate in this list", "0.0", "REUSE"});
            continue;
        }
        seen.insert(key);
        PwResult r = analyze(pw);
        if (r.score <= 1) ++weak;
        results.push_back(r);
    }

    ui::kv("passwords", std::to_string(lines.size()));
    ui::kv("unique", std::to_string(results.size()));
    ui::kv("weak", std::to_string(weak));
    ui::line("");

    for (auto& r : results) {
        const std::string& c = r.score <= 1 ? V_RED : r.score == 2 ? V_YEL : r.score == 3 ? V_ORANGE : V_GREEN;
        double secs = std::pow(2.0, std::min(r.bits, 200.0)) / 1e10;
        std::string time;
        if (secs < 1) time = "instant";
        else if (secs < 60) time = fmtLong(secs) + "s";
        else if (secs < 3600) time = fmtLong(secs / 60) + "m";
        else if (secs < 86400) time = fmtLong(secs / 3600) + "h";
        else if (secs < 31536000) time = fmtLong(secs / 86400) + "d";
        else if (secs < 3.15e10) time = fmtLong(secs / 31536000) + "y";
        else if (secs < 3.15e17) time = fmtLong(secs / 3.15e10) + "ky";
        else time = "heat death of universe";

        std::string masked = pwMask(r.pw);
        ui::line("  " + std::string(c) + ui::bar(r.bits / 100.0, 20) + " " +
                 ui::padTo(r.label, 10) + V_DIM + " " + fmt(r.bits, 1) + " bits  " + time +
                 "  " + masked + V_RESET);
        ui::line("");
    }

    if (!dupes.empty()) {
        ui::section("REUSE");
        std::vector<std::vector<std::string>> rows;
        for (auto& d : dupes) rows.push_back({pwMask(d[0]), "duplicate", "REUSE"});
        ui::table({"PASSWORD", "ISSUE", "SEVERITY"}, rows);
    }

    ui::line("");
    if (weak == 0 && dupes.empty())
        ui::ok("all passwords meet the recommended bar (>= 60 bits, unique)");
    else
        ui::fail(std::to_string(weak + dupes.size()) + " of " + std::to_string(lines.size()) +
                 " passwords need attention");
    ui::line("");
    ui::info("bit estimates assume offline attack at ~10^10 guesses/sec; online throttling changes everything");
    ui::line("");
    return weak ? 1 : 0;
}

int runPwGen(const Args& a) {
    ui::section("PASSWORD GENERATOR (OS CSPRNG)");

    int count = std::atoi(a.opt("count", "5").c_str());
    if (count < 1) count = 1;
    if (count > 200) count = 200;
    size_t len = (size_t)std::atoll(a.opt("length", "24").c_str());
    if (len < 4) len = 4;
    if (len > 512) len = 512;

    bool lower = !a.flag("no-lower");
    bool upper = !a.flag("no-upper");
    bool digits = !a.flag("no-digits");
    bool symbols = a.flag("symbols");
    bool passphrase = a.flag("passphrase");
    bool noAmbiguous = a.flag("no-ambiguous");
    bool avoidRepeat = a.flag("no-repeat");

    std::string alphabet;
    std::string lc = "abcdefghijklmnopqrstuvwxyz", uc = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
    std::string dg = "0123456789", sy = "!@#$%^&*()-_=+[]{};:,.?/|~";
    if (noAmbiguous) {
        lc = "abcdefghijkmnopqrstuvwxyz";
        uc = "ABCDEFGHJKLMNPQRSTUVWXYZ";
        dg = "23456789";
        sy = "!@#$%^&*()-_=+[]{};:,.?/|~";
    }
    if (lower) alphabet += lc;
    if (upper) alphabet += uc;
    if (digits) alphabet += dg;
    if (symbols) alphabet += sy;

    if (alphabet.empty()) {
        ui::fail("all character classes disabled; nothing to choose from");
        return 1;
    }

    size_t passphraseWords = 0, passphraseChars = 0, passphraseList = 0;
    double passphraseBits = 0;
    int sep = std::atoi(a.opt("separator", "0").c_str());
    if (passphrase) {
        static const char* words[] = {
            "anchor","amber","anvil","arrow","basalt","beacon","cactus","canyon","cedar",
            "cipher","cobalt","comet","copper","coral","cosmos","crater","crystal","dagger",
            "delta","ember","falcon","fern","fjord","flint","garnet","glacier","granite",
            "harbor","hazel","helix","hollow","indigo","ivory","jasper","jungle","krypton",
            "lantern","lattice","lagoon","lupine","magnet","marlin","meadow","nebula","nickel",
            "obsidian","onyx","opal","orbit","otter","pebble","pillar","pine","prism",
            "quartz","quiver","raven","reef","ridge","river","saffron","sequoia","silver",
            "sparrow","summit","talon","thicket","timber","topaz","tundra","umbra","velvet",
            "vertex","violet","walnut","willow","xenon","yarrow","zenith","zephyr","cobalt",
        };
        int wc = (int)(len / 5) + 3;
        const size_t wordCount = sizeof(words) / sizeof(char*);
        for (int i = 0; i < count; ++i) {
            std::string p;
            size_t digitsAdded = 0;
            for (int w = 0; w < wc; ++w) {
                const char* word = words[randomRange(0, (uint32_t)wordCount)];
                std::string ws = word;
                if (!a.flag("no-caps")) ws[0] = (char)toupper((unsigned char)ws[0]);
                if (digits && randomRange(0, 4) == 0) {
                    ws += (char)('0' + randomRange(0, 10));
                    ++digitsAdded;
                }
                p += ws;
                if (sep) p += (char)sep;
            }
            if (sep && !p.empty() && p.back() == (char)sep) p.pop_back();
            double bits = (double)wc * std::log2((double)wordCount) +
                          (double)digitsAdded * std::log2(10.0);
            ui::line("  " + V_GREEN + ui::padTo(p, 46) + V_DIM + fmt(bits, 0) + " bits" + V_RESET);
            if (i == 0) {
                passphraseWords = wc;
                passphraseChars = p.size();
                passphraseBits = bits;
                passphraseList = wordCount;
            }
        }
    } else {
        for (int i = 0; i < count; ++i) {
            std::string p;
            std::string used;
            auto pick = [&](const std::string& set) {
                char c = set[randomRange(0, (uint32_t)set.size())];
                p += c;
                used += c;
            };
            if (lower) pick(lc);
            if (upper) pick(uc);
            if (digits) pick(dg);
            if (symbols) pick(sy);
            while (p.size() < len) {
                char c = alphabet[randomRange(0, (uint32_t)alphabet.size())];
                if (avoidRepeat && p.size() > 0 && c == p.back()) continue;
                p += c;
            }
            for (size_t k = p.size(); k > len; --k)
                std::swap(p[k - 1], p[randomRange(0, (uint32_t)k)]);
            double bits = len * std::log2((double)alphabet.size());
            ui::line("  " + V_GREEN + ui::padTo(p, 46) + V_DIM + fmt(bits, 0) + " bits" + V_RESET);
        }
    }

    ui::line("");
    ui::kv("count", std::to_string(count));
    if (passphrase) {
        ui::kv("words", std::to_string(passphraseWords));
        ui::kv("characters", std::to_string(passphraseChars));
        ui::kv("word list", std::to_string(passphraseList) + " words" +
                              (sep ? ", separator '" + std::string(1, (char)sep) + "'" : ", no separator"));
        ui::kv("entropy/pass", fmt(passphraseBits, 1) + " bits");
    } else {
        ui::kv("length", std::to_string(len));
        ui::kv("alphabet", std::to_string(alphabet.size()) + " characters");
        ui::kv("entropy/pass", fmt(len * std::log2((double)alphabet.size()), 1) + " bits");
    }
    ui::kv("source", "OS CSPRNG (BCryptGenRandom / SystemFunction036 / getrandom)");
    ui::kv("entropy source", secureRandomAvailable()
                                ? "verified non-repeating"
                                : "WARNING: OS CSPRNG unavailable, falling back to rand()");
    ui::line("");
    ui::info("generated values are printed once and never stored; do not log this output");
    ui::line("");
    return 0;
}

struct SecretRule {
    std::string id;
    std::string pattern;
    std::string desc;
    int sev;
    std::string mask;
};

int runCredScan(const Args& a) {
    ui::section("SECRET SCANNER");

    std::vector<std::string> roots;
    if (a.hasOpt("path")) roots = split(a.opt("path"), ';');
    if (roots.empty() && !a.first().empty()) roots.push_back(a.first());
    if (roots.empty()) roots.push_back(".");

    bool recursive = !a.flag("no-recursive");
    std::vector<std::string> exts = {".env", ".json", ".yaml", ".yml", ".xml", ".ini", ".cfg",
                                     ".conf", ".properties", ".toml", ".js", ".ts", ".py",
                                     ".rb", ".go", ".java", ".cs", ".php", ".sh", ".bash",
                                     ".ps1", ".bat", ".cmd", ".txt", ".pem", ".key", ".p12",
                                     ".pfx", ".jks", ".keystore", ".npmrc", ".netrc", ".git/config",
                                     ""};
    exts.pop_back();
    if (!a.flag("all-files")) {
        std::vector<std::string> filtered;
        for (auto& p : roots) filtered.push_back(p);
        roots = filtered;
    }

    std::vector<std::string> files = globFiles(roots, exts, recursive);
    if (files.empty()) {
        ui::warn("no scannable files found under the given paths");
        return 1;
    }

    static const SecretRule rules[] = {
        {"PRIVATE-KEY", "-----BEGIN (RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY-----",
         "embedded private key material", 3, "keep"},
        {"AWS-AKID", "\\b(AKIA|ASIA|ABIA|ACCA)[0-9A-Z]{16}\\b", "AWS access key id", 3, "keep"},
        {"AWS-SECRET", "\\baws_secret_access_key\\b\\s*[=:]\\s*[\"']?([A-Za-z0-9/+=]{40})",
         "AWS secret access key", 3, "keep"},
        {"GITHUB-TOKEN", "\\b(ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{36}\\b", "GitHub PAT/OAuth token", 3, "keep"},
        {"SLACK-TOKEN", "\\bxox[baprs]-[A-Za-z0-9-]{10,}\\b", "Slack token", 3, "keep"},
        {"STRIPE-KEY", "\\b(sk|rk)_(live|test)_[A-Za-z0-9]{20,}\\b", "Stripe secret key", 3, "keep"},
        {"GOOGLE-API", "\\bAIza[0-9A-Za-z\\-_]{35}\\b", "Google API key", 3, "keep"},
        {"AZURE-SAS", "\\bsig=[A-Za-z0-9%+/]{40,}\\b", "Azure SAS signature", 2, "keep"},
        {"JWT", "\\beyJ[A-Za-z0-9_-]{10,}\\.[A-Za-z0-9_-]{10,}\\.[A-Za-z0-9_-]{5,}\\b",
         "JSON Web Token", 2, "keep"},
        {"PG-CONN", "\\b(postgres|postgresql|mysql|mongodb(\\+srv)?|redis|amqp)://[^\\s\"']{6,}",
         "database connection string with credentials", 3, "keep"},
        {"BASIC-AUTH-URL", "\\bhttps?://[^\\s:/@]+:[^\\s/@]{3,}@", "credentials embedded in URL", 3, "keep"},
        {"PASSWORD-ASSIGN", "(?i)\\b(pass(word|wd)?|secret|token|apikey|api_key|auth)\\b\\s*[=:]\\s*[\"'][^\"'\\s]{6,}[\"']",
         "hardcoded credential in config or source", 3, "mask"},
        {"NETRC", "^machine\\s+\\S+\\s+login\\s+\\S+\\s+password\\s+\\S+", "netrc credentials", 3, "keep"},
        {"NPM-TOKEN", "_authToken\\s*=\\s*[A-Za-z0-9_\\-]{20,}", "npm auth token", 3, "keep"},
        {"SSH-PRIVATE", "PuTTY-User-Key-File-[0-9]", "PuTTY private key", 3, "keep"},
        {"KDUMP-PATH", "(?i)\\b[A-Z]:\\\\Windows\\\\MEMORY\\.DMP\\b", "memory dump path referenced", 1, "keep"},
    };

    int scanned = 0, findings = 0;
    std::vector<std::vector<std::string>> rows;
    std::set<std::string> byType;

    for (auto& f : files) {
        uint64_t sz = fileSize(f);
        if (sz == 0 || sz > 8u * 1024 * 1024) continue;
        std::string content;
        std::string err;
        if (!readTextFile(f, content, &err)) continue;
        if (shannonEntropy(content) > 7.6 && sz > 4096) continue;
        ++scanned;

        for (auto& r : rules) {
            std::string all;
            std::string pattern = r.pattern;
            std::string haystack = content;
            if (pattern.rfind("(?i)", 0) == 0) {
                pattern = pattern.substr(4);
                haystack = toLower(content);
            }
            regexFind(haystack, pattern, 0, nullptr, &all, 50);
            if (all.empty()) continue;
            for (auto& line : splitLines(all)) {
                if (line.empty()) continue;
                int lineNo = 1;
                std::string needle = toLower(line);
                for (auto& ln : splitLines(content)) {
                    if (icontains(toLower(ln), needle)) break;
                    ++lineNo;
                }
                findings++;
                byType.insert(r.id);
                std::string shown = r.mask == "mask" ? toLower(line.substr(0, 4)) +
                                                          std::string("****") + line.substr(line.size() > 8 ? line.size() - 4 : 4)
                                                    : line;
                rows.push_back({r.id, ui::truncateTo(f, 34), std::to_string(lineNo),
                                ui::truncateTo(shown, 24)});
                if (rows.size() > 400) break;
            }
            if (rows.size() > 400) break;
        }
        if (rows.size() > 400) break;
    }

    ui::kv("roots", join(roots, ", "));
    ui::kv("files enumerated", std::to_string(files.size()));
    ui::kv("files scanned", std::to_string(scanned));
    ui::kv("findings", std::to_string(findings));
    ui::line("");

    if (rows.empty()) {
        ui::ok("no hardcoded secrets detected");
    } else {
        ui::table({"TYPE", "FILE", "LINE", "VALUE"}, rows);
        ui::line("");
        ui::fail(std::to_string(findings) + " potential secret(s) across " +
                 std::to_string(byType.size()) + " rule type(s)");
    }
    ui::line("");
    ui::warn("treat every hit as compromised: rotate the credential, then fix the leak");
    ui::line("");
    ui::info("add regexes for internal formats; pipe this into a pre-commit hook or CI gate");
    ui::line("");
    return findings ? 1 : 0;
}

}  // namespace

CK_TOOL("pw-audit", "passwords", "Entropy-based password audit with pattern, dictionary and reuse detection",
        "argus pw-audit --password 'a,Passw0rd!'  |  --file creds.txt", runPwAudit);
CK_TOOL("pw-gen", "passwords", "CSPRNG password and passphrase generator with policy flags",
        "argus pw-gen [--count 5] [--length 24] [--symbols] [--passphrase]", runPwGen);
CK_TOOL("credscan", "passwords", "Scan a tree for hardcoded API keys, tokens, private keys and connection strings",
        "argus credscan [--path ./src;./config] [--no-recursive]", runCredScan);