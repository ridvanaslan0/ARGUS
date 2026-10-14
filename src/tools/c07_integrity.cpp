#include "common.h"

#include <cstring>
#include <map>
#include <set>
#include <algorithm>

#if CK_WINDOWS
#  include <windows.h>
#  include <aclapi.h>
#endif

using namespace ck;
using namespace ck::tools;

namespace {

const std::string V_GREEN = "\033[38;5;46m";
const std::string V_YEL = "\033[38;5;214m";
const std::string V_RED = "\033[38;5;196m";
const std::string V_DIM = "\033[2;37m";
const std::string V_RESET = "\033[0m";

#if !CK_WINDOWS
std::string modeToString(uint32_t mode) {
    std::string s;
    char type = (mode & 0170000) == 0040000 ? 'd' : (mode & 0170000) == 0120000 ? 'l' : '-';
    s += type;
    const char* rwx = "rwx";
    for (int who = 2; who >= 0; --who) {
        int shift = who * 3;
        s += (mode & (1 << (shift + 2))) ? 'r' : '-';
        s += (mode & (1 << (shift + 1))) ? 'w' : '-';
        s += (mode & (1 << shift)) ? 'x' : '-';
    }
    (void)rwx;
    return s;
}
#endif

int runAclAudit(const Args& a) {
    ui::section("PERMISSION / ACL AUDIT");

    std::string target = a.opt("path");
    if (target.empty() && !a.first().empty()) target = a.first();
    if (target.empty()) {
        ui::fail("pass a path: argus acl-audit ./config");
        return 1;
    }

    bool recursive = !a.flag("no-recursive");
    size_t maxEntries = (size_t)std::atoll(a.opt("max", "400").c_str());

    std::vector<std::string> entries;
    if (listDir(target, entries, recursive, false)) {
        // ok
    } else {
        ui::fail("cannot read " + target);
        return 1;
    }
    if (entries.size() > maxEntries) entries.resize(maxEntries);

    ui::kv("target", target);
    ui::kv("entries examined", std::to_string(entries.size()));
    ui::kv("recursive", recursive ? "yes" : "no");
    ui::line("");

    std::vector<Finding> fs;
    std::vector<std::vector<std::string>> rows;

#if CK_WINDOWS
    std::map<std::string, int> permCount;
    std::map<std::string, std::string> permSample;
    int unauthEnum = 0, everyoneModify = 0, insecure = 0, checked = 0;

    for (auto& path : entries) {
        std::string out = trim(runCapture("icacls \"" + path + "\"", 8000));
        if (out.empty()) continue;
        ++checked;
        auto lines = splitLines(out);
        if (lines.empty()) continue;
        std::string acl = join(std::vector<std::string>(lines.begin() + 1, lines.end()), " ");
        permCount[acl]++;
        if (permSample.find(acl) == permSample.end()) permSample[acl] = path;

        std::string low = toLower(acl);
        if (low.find("everyone:(r)") != std::string::npos ||
            low.find("everyone:(rx)") != std::string::npos ||
            low.find("everyone: (r)") != std::string::npos) {
            unauthEnum++;
            fs.push_back({"A-READABLE", "readable by Everyone: " + ui::truncateTo(path, 46), 2});
        }
        if (low.find("everyone:(w)") != std::string::npos ||
            low.find("everyone:(m)") != std::string::npos ||
            low.find("everyone:(f)") != std::string::npos ||
            low.find("users:(m)") != std::string::npos ||
            low.find("users:(w)") != std::string::npos) {
            everyoneModify++;
            fs.push_back({"A-WRITABLE", "writable by non-admin principals: " + ui::truncateTo(path, 46), 3});
        }
        if (low.find("authenticated users") != std::string::npos) {
            fs.push_back({"A-AUTHUSERS", "granted to 'Authenticated Users': " + ui::truncateTo(path, 44), 2});
        }
        if (path.find("$Recycle.Bin") != std::string::npos) continue;
        if (low.find("(i)") != std::string::npos && (low.find("(m)") != std::string::npos ||
            low.find("(f)") != std::string::npos || low.find("(w)") != std::string::npos)) {
            fs.push_back({"A-INHERIT", "inheritable write ACE present: privilege escalation via child objects", 2});
        }
        if (path.find("\\Program Files") != std::string::npos ||
            path.find("\\Windows\\System32") != std::string::npos) {
            if (low.find("(w)") != std::string::npos || low.find("(m)") != std::string::npos) {
                insecure++;
                fs.push_back({"A-SYSTEM-W", "WRITE access inside a protected system directory: " +
                                           ui::truncateTo(path, 44), 3});
            }
        }
    }

    if (permCount.size() > 1)
        fs.push_back({"A-INCONSISTENT", std::to_string(permCount.size()) +
                                        " distinct ACLs across " + std::to_string(checked) +
                                        " files: configuration drift", 1});
    if (checked == 0) fs.push_back({"A-NOACL", "could not read any ACLs (needs elevation?)", 2});

    ui::section("ACL PROFILE DISTRIBUTION");
    std::vector<std::pair<std::string, int>> prof(permCount.begin(), permCount.end());
    std::sort(prof.begin(), prof.end(), [](auto& x, auto& y) { return x.second > y.second; });
    rows.clear();
    int shown = 0;
    for (auto& p : prof) {
        if (shown++ >= 6) break;
        rows.push_back({std::to_string(p.second), ui::truncateTo(p.first, 52)});
    }
    ui::table({"COUNT", "ACE SUMMARY"}, rows);
    ui::line("");
    ui::kv("world-readable", std::to_string(unauthEnum));
    ui::kv("group-writable", std::to_string(everyoneModify));
#else
    int worldWritable = 0, worldReadable = 0, setuid = 0, setgid = 0, stickyMissing = 0, checked = 0;
    std::map<std::string, int> modeDist;
    std::vector<std::vector<std::string>> listing;

    for (auto& p : entries) {
        std::string out = trim(runCapture("ls -ld \"" + p + "\" 2>/dev/null", 6000));
        if (out.empty()) continue;
        ++checked;
        size_t ul = 0;
        std::string mode = regexFind(out, "^(.{10})", 1, &ul);
        if (mode.empty()) continue;
        modeDist[mode]++;
        if (mode.size() >= 10) {
            char other = mode[8];
            if (other == 'w' || (other == 'x' && mode[0] != 'l')) {
                if (other == 'w') {
                    ++worldWritable;
                    fs.push_back({"A-WORLD-W", "world-writable: " + ui::truncateTo(p, 48), 3});
                } else {
                    ++worldReadable;
                    if (listing.size() < 12)
                        fs.push_back({"A-WORLD-R", "world-executable/readable: " + ui::truncateTo(p, 44), 1});
                }
            }
            if (mode[3] == 's' || mode[6] == 's') {
                ++setuid;
                fs.push_back({"A-SETUID", "setuid/setgid bit: " + ui::truncateTo(p, 48), 3});
            }
            if (mode[0] == 'd' && mode[9] != 't') {
                ++stickyMissing;
                fs.push_back({"A-NOSTICKY", "world-writable directory without sticky bit: " +
                                            ui::truncateTo(p, 40), 2});
            }
            if (mode.size() >= 10 && mode[0] != 'l') {
                listing.push_back({mode, ui::truncateTo(p, 56)});
            }
        }
    }

    ui::section("PERMISSION PROFILE");
    rows.clear();
    std::vector<std::pair<std::string, int>> md(modeDist.begin(), modeDist.end());
    std::sort(md.begin(), md.end(), [](auto& x, auto& y) { return x.second > y.second; });
    int shown = 0;
    for (auto& m : md) {
        if (shown++ >= 12) break;
        rows.push_back({m.first, std::to_string(m.second)});
    }
    ui::table({"MODE", "COUNT"}, rows);
    ui::line("");
    ui::kv("world-writable", std::to_string(worldWritable));
    ui::kv("world-executable", std::to_string(worldReadable));
    ui::kv("setuid/setgid", std::to_string(setuid));
    ui::kv("sticky-bit gaps", std::to_string(stickyMissing));
#endif

    ui::line("");
    renderFindings(fs);
    ui::info("hardening: remove write for non-admins, replace 'Everyone' with explicit service identities");
    ui::line("");
    return 0;
}

// ------------------------------------------------------------ integrity
struct ManifestEntry {
    std::string path;
    std::string sha256;
    uint64_t size = 0;
};

std::string manifestLine(const ManifestEntry& e) {
    char buf[32];
    snprintf(buf, sizeof(buf), "%llu", (unsigned long long)e.size);
    return e.sha256 + "  " + std::string(buf) + "  " + e.path;
}

int runIntegrity(const Args& a) {
    std::string mode = toLower(a.opt("mode", "verify"));
    std::string root = a.opt("path");
    if (root.empty() && !a.first().empty()) root = a.first();

    if (mode == "create" || mode == "init") {
        std::string out = a.opt("out", "integrity.manifest");
        std::vector<std::string> roots;
        if (!root.empty()) roots = split(root, ';');
        else roots.push_back(".");
        std::vector<std::string> files = globFiles(roots, {}, true);
        ui::section("BASELINE CREATION");
        ui::kv("roots", join(roots, ", "));
        ui::kv("files", std::to_string(files.size()));
        ui::line("");

        std::string body = "# argus integrity manifest v1\n# created " +
                           std::string(__DATE__) + " " + __TIME__ + "\n";
        int n = 0;
        for (auto& f : files) {
            uint64_t sz = fileSize(f);
            if (sz == 0 || sz > 64ull * 1024 * 1024) continue;
            std::string err;
            Digest d = hashFile("sha256", f, &err);
            if (d.bytes.empty()) continue;
            ManifestEntry e;
            e.path = f;
            e.sha256 = d.hex();
            e.size = sz;
            body += manifestLine(e) + "\n";
            ++n;
            if (n % 50 == 0) progressBar("hashing", (size_t)n, files.size());
        }
        fputs("\r\033[K", stdout);
        body += "# files: " + std::to_string(n) + "\n";
        std::string err;
        if (!writeTextFile(out, body, &err)) { ui::fail(err); return 1; }
        ui::ok("wrote " + std::to_string(n) + " entries to " + out);
        ui::line("");
        return 0;
    }

    std::string manifest = a.opt("manifest");
    if (manifest.empty() && fileExists("integrity.manifest")) manifest = "integrity.manifest";
    if (manifest.empty()) {
        ui::fail("pass --manifest <file> (create one with --mode create)");
        return 1;
    }

    std::string content;
    std::string err;
    if (!readTextFile(manifest, content, &err)) { ui::fail(err); return 1; }

    ui::section("INTEGRITY VERIFICATION");
    ui::kv("manifest", manifest);
    ui::line("");

    int checked = 0, ok = 0, modified = 0, missing = 0;
    std::vector<std::vector<std::string>> rows;
    std::vector<Finding> fs;

    for (auto& line : splitLines(content)) {
        std::string l = line;
        if (l.empty() || l[0] == '#') continue;
        size_t p1 = l.find("  ");
        if (p1 == std::string::npos) continue;
        size_t p2 = l.find("  ", p1 + 2);
        if (p2 == std::string::npos) continue;
        std::string want = l.substr(0, p1);
        std::string sizeS = l.substr(p1 + 2, p2 - p1 - 2);
        std::string path = l.substr(p2 + 2);
        ++checked;

        if (!fileExists(path)) {
            ++missing;
            rows.push_back({"MISSING", ui::truncateTo(path, 40), ""});
            fs.push_back({"I-MISSING", "file deleted since baseline: " + ui::truncateTo(path, 46), 3});
            continue;
        }
        std::string e2;
        Digest d = hashFile("sha256", path, &e2);
        if (d.hex() != want) {
            ++modified;
            rows.push_back({"CHANGED", ui::truncateTo(path, 40), ui::truncateTo(d.hex(), 24)});
            fs.push_back({"I-MODIFIED", "content changed: " + ui::truncateTo(path, 48), 3});
        } else if (std::to_string(fileSize(path)) != sizeS) {
            rows.push_back({"RESIZED", ui::truncateTo(path, 40), ""});
            fs.push_back({"I-RESIZED", "size changed: " + ui::truncateTo(path, 48), 2});
            ++modified;
        } else {
            ++ok;
            rows.push_back({"OK", ui::truncateTo(path, 40), ui::truncateTo(d.hex(), 24)});
        }
    }

    ui::table({"STATE", "PATH", "ACTUAL SHA256"}, rows);
    ui::line("");
    ui::kv("checked", std::to_string(checked));
    ui::kv("unchanged", std::to_string(ok));
    ui::kv("changed", std::to_string(modified));
    ui::kv("missing", std::to_string(missing));
    ui::line("");
    if (modified == 0 && missing == 0) {
        ui::ok("every file matches the baseline");
        return 0;
    }
    renderFindings(fs);
    return 1;
}

}  // namespace

CK_TOOL("acl-audit", "defense", "Audit file and directory permissions for world-writable, setuid and Everyone-grant issues",
        "argus acl-audit ./config [--no-recursive] [--max 400]", runAclAudit);
CK_TOOL("integrity", "defense", "Create and verify a SHA-256 baseline manifest to detect tampering",
        "argus integrity --mode create --path ./bin --out baseline.manifest  |  --manifest baseline.manifest",
        runIntegrity);