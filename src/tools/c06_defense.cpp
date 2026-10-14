#include "common.h"

#include <cstring>
#include <map>
#include <set>
#include <algorithm>

#if CK_WINDOWS
#  include <windows.h>
#else
#  include <unistd.h>
#endif

using namespace ck;
using namespace ck::tools;

namespace {

const std::string V_GREEN = "\033[38;5;46m";
const std::string V_YEL = "\033[38;5;214m";
const std::string V_RED = "\033[38;5;196m";
const std::string V_DIM = "\033[2;37m";
const std::string V_RESET = "\033[0m";

std::string ps(const std::string& script, int ms = 30000) {
    return trim(runCapture("powershell -NoProfile -NonInteractive -ExecutionPolicy Bypass -Command \"" +
                           script + "\"", ms));
}

bool isAdmin() {
#if CK_WINDOWS
    BOOL r = FALSE;
    HANDLE tok = NULL;
    if (OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &tok)) {
        GetTokenInformation(tok, TokenElevation, (LPVOID)&r, sizeof(r), NULL);
        CloseHandle(tok);
    }
    return r != 0;
#else
    return geteuid() == 0;
#endif
}

int runWinAudit(const Args& a) {
    ui::section("WINDOWS SECURITY POSTURE AUDIT");

    std::vector<std::vector<std::string>> rows;
    std::vector<Finding> fs;

    ui::kv("host", localHostName());
    ui::kv("privilege", isAdmin() ? std::string(V_YEL) + "elevated (full checks)" + V_RESET
                                  : std::string(V_DIM) + "standard (some checks need admin)" + V_RESET);
    ui::line("");

    bool linux = !CK_WINDOWS;
    if (linux) {
        ui::warn("win-audit targets Windows; running generic POSIX checks instead");
        ui::section("POSIX BASELINE");
        fs.push_back({"POSIX-SELINUX", "SELinux/AppArmor state not inspected by this tool", 1});
        fs.push_back({"POSIX-SSH", "run: argus log-hunt / sshd -t  and  grep -R PermitRootLogin /etc/ssh", 0});
        renderFindings(fs);
        return 1;
    }

    // ---- SMBv1
    {
        std::string v = ps("$k='HKLM:\\SYSTEM\\CurrentControlSet\\Services\\LanmanServer\\Parameters';"
                           "(Get-ItemProperty $k -Name SMB1Protocol -EA SilentlyContinue).SMB1Protocol");
        std::string driver = ps("(Get-ItemProperty 'HKLM:\\SYSTEM\\CurrentControlSet\\Services\\LanmanWorkstation\\Parameters' "
                               "-Name EnableSMB1Protocol -EA SilentlyContinue).EnableSMB1Protocol");
        if (v == "0" && driver == "0") fs.push_back({"W-SMB1-OFF", "SMBv1 disabled on server and client", 0});
        else fs.push_back({"W-SMB1", "SMBv1 is ENABLED (server=" + (v.empty() ? "default" : v) +
                                     ", client=" + (driver.empty() ? "default" : driver) +
                                     "): remove with Set-SmbServerConfiguration -EnableSMB1Protocol $false", 3});
    }

    // ---- Guest accounts
    {
        std::string g = ps("(Get-LocalUser | Where-Object {$_.Enabled -and $_.PasswordRequired -eq $false} | "
                           "Select-Object -ExpandProperty Name) -join ','");
        std::string g2 = ps("(Get-LocalUser | Where-Object {$_.Name -match '^(Guest|DefaultAccount|ANONYMOUS)'} | "
                            "Select-Object -ExpandProperty Name) -join ','");
        if (!trim(g).empty()) fs.push_back({"W-GUEST", "account(s) with passwordless access: " + g, 3});
        if (!trim(g2).empty()) fs.push_back({"W-BUILTIN", "guest-style builtin account(s) present: " + g2 + " (verify they are disabled)", 2});
        if (trim(g).empty() && trim(g2).empty()) fs.push_back({"W-NOGUEST", "no passwordless or guest accounts enabled", 0});
    }

    // ---- Defender
    {
        std::string status = ps("(Get-MpComputerStatus | Select-Object -ExpandProperty AMServiceEnabled) -join ','");
        std::string re = ps("(Get-MpPreference | Select-Object -ExpandProperty DisableRealtimeMonitoring) -join ','");
        if (status == "True") {
            if (re == "True") fs.push_back({"W-MPDISABLED", "Defender real-time monitoring is DISABLED", 3});
            else fs.push_back({"W-MP", "Microsoft Defender real-time protection active", 0});
        } else {
            fs.push_back({"W-MP-OFF", "Defider/AV real-time protection not reporting as enabled (status=" +
                                       (status.empty() ? "unknown" : status) + ")", 3});
        }
        std::string sigAge = ps("$v=Get-MpComputerStatus; if($v){[int]((Get-Date)-$v.AntivirusSignatureLastUpdated).TotalHours}");
        if (!sigAge.empty()) {
            int age = std::atoi(sigAge.c_str());
            if (age > 48) fs.push_back({"W-SIGAGE", "antivirus signatures are " + std::to_string(age) + " hours old", 3});
            else if (age > 4) fs.push_back({"W-SIGAGE", "antivirus signatures " + std::to_string(age) + " hours old", 1});
        }
        std::string tf = ps("(Get-MpPreference | Select-Object -ExpandProperty DisableRealtimeMonitoring)");
        (void)tf;
    }

    // ---- UAC
    {
        std::string uac = ps("(Get-ItemProperty 'HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System' "
                             "-Name EnableLUA,ConsentPromptBehaviorAdmin,PromptOnSecureDesktop | "
                             "ForEach-Object { \"$($_.EnableLUA)/$($_.ConsentPromptBehaviorAdmin)/$($_.PromptOnSecureDesktop)\" })");
        std::vector<std::string> parts = split(trim(uac), '/');
        if (parts.size() >= 3) {
            if (parts[0] == "0") fs.push_back({"W-UAC-OFF", "UAC is disabled entirely", 3});
            else if (parts[1] == "0") fs.push_back({"W-UAC-SILENT", "admin elevation never prompts (ConsentPromptBehaviorAdmin=0)", 3});
            else if (parts[2] == "0") fs.push_back({"W-UAC-DESKTOP", "admin elevation does not prompt on the secure desktop", 2});
            else fs.push_back({"W-UAC", "UAC enabled with prompting enabled", 0});
        } else {
            fs.push_back({"W-UAC-UNKNOWN", "could not read UAC policy", 1});
        }
    }

    // ---- Firewall profiles
    {
        std::string fw = ps("Get-NetFirewallProfile | ForEach-Object { \"$($_.Name)=$($_.Enabled)/$($_.DefaultInboundAction)\" }");
        for (auto& p : split(fw, ' ')) {
            std::vector<std::string> kv2 = split(p, '=');
            if (kv2.size() != 2) continue;
            std::string name = kv2[0];
            std::string state = kv2[1];
            std::vector<std::string> st = split(state, '/');
            if (!st.empty() && st[0] == "False")
                fs.push_back({"W-FW-OFF", "firewall profile '" + name + "' is DISABLED", 3});
            else if (st.size() > 1 && (st[1] == "Allow" || st[1] == "0"))
                fs.push_back({"W-FW-IN", "firewall profile '" + name + "' default inbound action is Allow", 2});
        }
        if (trim(fw).empty()) fs.push_back({"W-FW-UNKNOWN", "could not enumerate firewall profiles", 2});
    }

    // ---- RDP
    {
        std::string rdp = ps("(Get-ItemProperty 'HKLM:\\System\\CurrentControlSet\\Control\\Terminal Server' "
                             "-Name fDenyTSConnections -EA SilentlyContinue).fDenyTSConnections");
        std::string nla = ps("(Get-ItemProperty 'HKLM:\\System\\CurrentControlSet\\Control\\Terminal Server\\WinStations\\RDP-Tcp' "
                             "-Name UserAuthentication -EA SilentlyContinue).UserAuthentication");
        if (rdp == "0") {
            fs.push_back({"W-RDP", "RDP is ENABLED", 2});
            if (nla != "1") fs.push_back({"W-RDP-NONLA", "RDP without Network Level Authentication: credential relay risk", 3});
            else fs.push_back({"W-RDP-NLA", "RDP enabled with NLA enforced", 0});
        } else {
            fs.push_back({"W-RDP-OFF", "RDP disabled", 0});
        }
    }

    // ---- BitLocker
    {
        std::string bl = ps("(Get-BitLockerVolume -EA SilentlyContinue | Where-Object {$_.VolumeStatus -ne 'FullyEncrypted' -and "
                            "$_.ProtectionStatus -ne 'Off'} | Select-Object -ExpandProperty MountPoint) -join ','");
        std::string allOff = ps("(Get-BitLockerVolume -EA SilentlyContinue | Where-Object {$_.ProtectionStatus -eq 'Off'} "
                                "| Select-Object -ExpandProperty MountPoint) -join ','");
        if (!trim(allOff).empty())
            fs.push_back({"W-BITLOCKER-OFF", "BitLocker OFF for: " + allOff + " - data recoverable from a stolen disk", 2});
        else if (trim(bl).empty())
            fs.push_back({"W-BITLOCKER", "no unencrypted volumes reported", 0});
        else
            fs.push_back({"W-BITLOCKER-PARTIAL", "not-fully-encrypted volumes: " + bl, 2});
    }

    // ---- SMB signing
    {
        std::string sign = ps("(Get-SmbServerConfiguration | Select-Object -ExpandProperty EnableSMB2Encryption)");
        std::string req = ps("$k='HKLM:\\SYSTEM\\CurrentControlSet\\Services\\LanmanServer\\Parameters';"
                             "(Get-ItemProperty $k -Name RequireSecurityModeShare -EA SilentlyContinue).RequireSecurityModeShare");
        if (req == "1") fs.push_back({"W-SMBSIGN", "SMB signing required (good)", 0});
        else fs.push_back({"W-SMBSIGN", "SMB signing is not required: relay attacks are possible", 2});
        (void)sign;
    }

    // ---- Lockout policy
    {
        std::string pol = ps("(net accounts) | Select-String 'Lockout threshold'");
        size_t l = 0;
        std::string thr = regexFind(pol, "(\\d+)", 1, &l);
        if (thr.empty()) fs.push_back({"W-LOCKOUT", "could not read lockout threshold", 2});
        else if (std::atoi(thr.c_str()) == 0)
            fs.push_back({"W-LOCKOUT-OFF", "account lockout threshold is 'Never': unlimited password guessing", 3});
        else
            fs.push_back({"W-LOCKOUT", "lockout threshold " + thr + " attempts", 0});
    }

    // ---- Audit policy
    {
        std::string audit = ps("auditpol /get /subcategory:\"Logon/Logoff\"");
        if (icontains(audit, "No Auditing"))
            fs.push_back({"W-AUDITLOGON", "logon/logoff auditing is disabled: brute-force is invisible", 3});
        else
            fs.push_back({"W-AUDITLOGON", "logon auditing enabled", 0});
        std::string obj = ps("auditpol /get /subcategory:\"Object Access\"");
        if (icontains(obj, "No Auditing"))
            fs.push_back({"W-AUDITOBJ", "object access auditing disabled", 1});
    }

    // ---- Windows Defender Firewall inbound allow rules (informational)
    {
        std::string rules = ps("(Get-NetFirewallRule -Direction Inbound -Action Allow -EA SilentlyContinue | "
                               "Where-Object {$_.Enabled -eq 'True'} | Select-Object -First 8 -ExpandProperty DisplayName) -join ' | '");
        if (!trim(rules).empty()) {
            ui::section("ENABLED INBOUND ALLOW RULES (first 8)");
            ui::line("    " + ui::truncateTo(trim(rules), 66));
            ui::line("");
        }
    }

    // ---- Windows Update policy
    {
        std::string wu = ps("(Get-ItemProperty 'HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows\\WindowsUpdate\\AU' "
                            "-Name NoAutoUpdate -EA SilentlyContinue).NoAutoUpdate");
        if (wu == "1") fs.push_back({"W-WU-OFF", "Windows Update is disabled by policy", 2});
        else fs.push_back({"W-WU", "Windows Update is not blocked by policy", 0});
    }

    // ---- Local admin members
    {
        std::string admins = ps("(Get-LocalGroupMember -Group 'Administrators' -EA SilentlyContinue | "
                                "Where-Object {$_.ObjectClass -eq 'User'} | Select-Object -ExpandProperty Name) -join ','");
        size_t count = 1;
        for (char c : admins) if (c == ',') ++count;
        if (count > 4)
            fs.push_back({"W-ADMINS", std::to_string(count) + " accounts in the Administrators group: " +
                                          ui::truncateTo(admins, 46), 2});
        else
            fs.push_back({"W-ADMINS-OK", "administrators group is limited (" + std::to_string(count) + " users)", 0});
    }

    ui::section("CHECKS PERFORMED");
    ui::line("    SMBv1, guest/passwordless accounts, Defender, AV signature age, UAC, firewall profiles,");
    ui::line("    RDP + NLA, BitLocker, SMB signing, lockout policy, audit policy, Windows Update, local admins");
    ui::line("");
    int bad = 0;
    for (auto& f : fs) if (f.sev >= 2) ++bad;
    return bad ? 1 : 0;
}

// ---------------------------------------------------------------- loghunt
struct AuthEvent {
    std::string time;
    std::string user;
    std::string src;
    std::string eventId;
    std::string type;
};

int runLogHunt(const Args& a) {
    ui::section("AUTHENTICATION LOG ANALYSIS");

    std::string file = a.opt("file");
    std::string content;

    if (!file.empty()) {
        std::string err;
        if (!readTextFile(file, content, &err)) {
            ui::fail(err);
            return 1;
        }
        ui::info("analysing " + file + " (" + std::to_string(content.size()) + " bytes)");
    } else if (fileExists("C:/Windows/System32/winevt/Logs/Security.evtx")) {
        ui::fail("Security.evtx is binary; export it first:");
        ui::line("    wevtutil epl Security C:\\Temp\\Security.xml");
        ui::line("    argus log-hunt --file C:\\Temp\\Security.xml");
        return 1;
    } else {
        ui::fail("pass --file <auth.log|Security.xml|any auth log>");
        ui::info("argus log-hunt --file /var/log/auth.log --threshold 5 --window 10m");
        return 1;
    }

    std::vector<std::string> lines = splitLines(content);
    ui::kv("lines", std::to_string(lines.size()));
    ui::line("");

    std::map<std::string, std::vector<std::string>> failures;
    std::map<std::string, std::vector<std::string>> successes;
    std::map<std::string, size_t> failCount;
    std::map<std::string, size_t> succCount;
    std::vector<std::string> failedEvents, successEvents, specialEvents;
    std::set<std::string> users, srcIPs;
    int failedTotal = 0, successTotal = 0;

    auto pushUnique = [](std::map<std::string, std::vector<std::string>>& m,
                         const std::string& k, const std::string& v) {
        auto& vec = m[k];
        for (auto& s : vec) if (s == v) return;
        vec.push_back(v);
    };

    for (size_t i = 0; i < lines.size(); ++i) {
        std::string l = lines[i];
        std::string low = toLower(l);

        bool isFail = icontains(low, "failure") || icontains(low, "failed password") ||
                      icontains(low, "invalid user") || icontains(low, "authentication failure") ||
                      icontains(low, "failed login") || icontains(low, "eventid>4625") ||
                      icontains(low, "eventid=\"4625\"") || icontains(low, "bad password");
        bool isSuccess = icontains(low, "accepted password") || icontains(low, "session opened") ||
                         icontains(low, "login successful") || icontains(low, "eventid>4624") ||
                         icontains(low, "eventid=\"4624\"") || icontains(low, "successfully authenticated");

        std::string user, src;
        size_t ul = 0;
        user = regexFind(low, "(?:failed password for|accepted password for|invalid user|"
                              "authentication failure for|login failed for|failed login for)"
                              "\\s+([a-z0-9._\\\\$-]{1,64})", 1, &ul);
        if (user.empty()) user = regexFind(low, "(?:targetusername|ruser|user(name)?|account|login)"
                                            "\\s*[=:]\\s*[\"']?([^\"'<\\s,;]{1,64})", 1, &ul);
        if (user.empty()) user = regexFind(low, "user\\s+([a-z0-9._-]{1,64})\\s*;", 1, &ul);

        src = regexFind(low, "\\bfrom\\s+([0-9a-f:.]{3,45})\\b", 1, &ul);
        if (src.empty()) src = regexFind(low, "\\brhost[=: ]\\s*([0-9a-f:.]{3,45})", 1, &ul);
        if (src.empty()) src = regexFind(low, "\\bsrcip[=: ]\\s*([0-9a-f:.]{3,45})", 1, &ul);
        if (src.empty()) src = regexFind(low, "ipaddress[\"'>:= ]+([0-9a-f:.]{3,45})", 1, &ul);
        if (src.empty()) src = regexFind(low, "clientaddress[\"'>:= ]+([0-9a-f:.]{3,45})", 1, &ul);
        if (src.empty()) src = regexFind(low, "\\b(\\d{1,3}(?:\\.\\d{1,3}){3})\\b", 1, &ul);

        if (isFail) {
            ++failedTotal;
            failedEvents.push_back(l);
            std::string u = user.empty() ? "(unknown)" : user;
            pushUnique(failures, u, src.empty() ? "(local)" : src);
            ++failCount[u];
            if (!user.empty()) users.insert(user);
            if (!src.empty()) srcIPs.insert(src);
        } else if (isSuccess) {
            ++successTotal;
            if (successEvents.size() < 4000) successEvents.push_back(l);
            std::string u = user.empty() ? "(unknown)" : user;
            pushUnique(successes, u, src.empty() ? "(local)" : src);
            ++succCount[u];
            if (!user.empty()) users.insert(user);
            if (!src.empty()) srcIPs.insert(src);
        }

        if (icontains(low, "4620") || icontains(low, "4720") || icontains(low, "user account was created"))
            specialEvents.push_back("account created: " + l);
        if (icontains(low, "4726") || icontains(low, "user account deleted"))
            specialEvents.push_back("account deleted: " + l);
        if (icontains(low, "4728") || icontains(low, "member added") || icontains(low, "added to the administrators"))
            specialEvents.push_back("privileged group add: " + l);
        if (icontains(low, "4732") || icontains(low, "added to a group"))
            specialEvents.push_back("group add: " + l);
        if (icontains(low, "1102") || icontains(low, "audit log cleared"))
            specialEvents.push_back("AUDIT LOG CLEARED: " + l);
        if (icontains(low, "4624") && (icontains(low, "type 3") || icontains(low, "logon type: 3")))
            specialEvents.push_back("network logon (type 3): " + l);
        if (icontains(low, "4625") && icontains(low, "4771") )
            specialEvents.push_back("pre-auth failure: " + l);
    }

    ui::section("SUMMARY");
    ui::kv("failed auth events", std::to_string(failedTotal));
    ui::kv("successful events", std::to_string(successTotal));
    ui::kv("distinct users", std::to_string(users.size()));
    ui::kv("distinct sources", std::to_string(srcIPs.size()));
    ui::line("");

    int threshold = std::atoi(a.opt("threshold", "5").c_str());
    std::vector<Finding> fs;

    ui::section("FAILURES BY USER");
    std::vector<std::vector<std::string>> rows;
    int sprayUsers = 0, bruteUsers = 0;
    for (auto& kv : failures) {
        size_t count = failCount.count(kv.first) ? failCount[kv.first] : 0;
        bool isSpray = kv.second.size() >= 3;
        rows.push_back({kv.first, std::to_string(count), std::to_string(kv.second.size()),
                        ui::truncateTo(join(kv.second, ", "), 30)});
        if (count >= threshold * 5) { bruteUsers++; fs.push_back({"L-BRUTE", "user '" + kv.first + "' had " + std::to_string(count) + " failed attempts", 3}); }
        else if (isSpray) { sprayUsers++; fs.push_back({"L-SPRAY", "user '" + kv.first + "' attacked from " + std::to_string(kv.second.size()) + " distinct sources (password spraying)", 3}); }
    }
    ui::table({"USER", "TOTAL FAILS", "SOURCES", "SOURCE IPS"}, rows);
    ui::line("");

    ui::section("FAILURES BY SOURCE");
    std::map<std::string, size_t> bySrc;
    for (auto& kv : failures)
        for (auto& s : kv.second) bySrc[s] += failCount.count(kv.first) ? failCount[kv.first] : 0;
    rows.clear();
    for (auto& kv : bySrc)
        rows.push_back({kv.first, std::to_string(kv.second), "", ""});
    ui::table({"SOURCE", "FAILS", "", ""}, rows);
    ui::line("");

    ui::section("SUCCESSFUL LOGINS BY USER");
    rows.clear();
    for (auto& kv : successes) {
        size_t count = succCount.count(kv.first) ? succCount[kv.first] : 0;
        rows.push_back({kv.first, std::to_string(count), ui::truncateTo(join(kv.second, ", "), 40), ""});
    }
    ui::table({"USER", "SUCCESSES", "SOURCES", ""}, rows);
    ui::line("");

    for (auto& s : srcIPs) {
        IpAddr ip;
        if (parseIp(s, ip) && !isPrivateIp(ip) && !isLoopbackIp(ip))
            fs.push_back({"L-EXTERNAL", "failures originating from public IP " + s, 2});
    }

    bool cleared = false;
    for (auto& s : specialEvents) {
        if (icontains(s, "AUDIT LOG CLEARED")) { cleared = true; break; }
    }
    if (cleared) fs.push_back({"L-CLEARED", "the audit log was cleared during this window: anti-forensics", 3});

    if (!specialEvents.empty()) {
        ui::section("PRIVILEGED / NOTABLE EVENTS");
        for (auto& s : specialEvents) ui::bullet(ui::truncateTo(s, 66));
        ui::line("");
    }

    if (failedTotal > 0 && successTotal > 0) {
        double ratio = (double)failedTotal / (double)(failedTotal + successTotal);
        if (ratio > 0.95 && failedTotal > 50)
            fs.push_back({"L-ALLFAIL", std::to_string(failedTotal) + " failures vs " + std::to_string(successTotal) +
                                          " successes: near-total credential attack", 3});
    }
    if (sprayUsers + bruteUsers == 0 && failedTotal == 0)
        fs.push_back({"L-CLEAN", "no failed authentication events found", 0});
    if (bruteUsers + sprayUsers > 0)
        fs.push_back({"L-THRESH", "threshold in use: " + std::to_string(threshold) + " failures/user", 1});

    renderFindings(fs);
    return fs.empty() ? 0 : 1;
}

}  // namespace

CK_TOOL("win-audit", "defense", "Windows posture audit: SMBv1, guest access, Defender, UAC, firewall, RDP, BitLocker",
        "argus win-audit        (run elevated for full coverage)", runWinAudit);
CK_TOOL("log-hunt", "defense", "Brute-force, spraying and notable-account-event detection in auth logs",
        "argus log-hunt --file /var/log/auth.log [--threshold 5]", runLogHunt);
