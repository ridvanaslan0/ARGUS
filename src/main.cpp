#include "ck/tool.h"
#include "ck/kit.h"

#include <cstdio>
#include <cstring>
#include <cstdlib>
#include <iostream>
#include <string>
#include <vector>

#if CK_WINDOWS
#  include <io.h>
#  define isatty _isatty
#else
#  include <unistd.h>
#endif

namespace {

const char* C_RESET = "\033[0m";
const char* C_DIM = "\033[2;37m";
const char* C_BOLD = "\033[1m";
const char* C_A = "\033[38;5;44m";
const char* C_B = "\033[38;5;205m";
const char* C_C = "\033[38;5;214m";
const char* C_D = "\033[38;5;51m";
const char* C_E = "\033[38;5;99m";
const char* C_BORDER = "\033[38;5;60m";
const char* C_KEY = "\033[38;5;250m";
const char* C_OK = "\033[38;5;46m";
const char* C_WARN = "\033[38;5;214m";
const char* C_CRIT = "\033[38;5;196m";

const char* BANNER_ART[] = {
    " ##    ###     ###    #  #   ###",
    "#  #   #  #   #       #  #   #",
    "####   ###    #  ##   #  #   ###",
    "#  #   # #    #   #   #  #     #",
    "#  #   #  #    ###     ##    ###",
};

const std::string S_RESET = "\033[0m";
const std::string S_BOLD = "\033[1m";
const std::string S_DIM = "\033[2;37m";
const std::string S_KEY = "\033[38;5;250m";
const std::string S_A = "\033[38;5;44m";
const std::string S_B = "\033[38;5;205m";
const std::string S_CRIT = "\033[38;5;196m";
const std::string S_BORDER = "\033[38;5;60m";
const std::string S_NAME = "\033[1;38;5;51m";
const std::string S_PURPLE = "\033[1;38;5;141m";

std::string rule(int w) {
    std::string r = S_BORDER;
    for (int i = 0; i < w; ++i) r += "\u2500";
    return r + S_RESET;
}

void banner() {
    for (int i = 0; i < 5; ++i)
   ck::ui::emit(S_NAME + BANNER_ART[i] + S_RESET + "\n");
    ck::ui::emit("  " + S_BOLD + "v2.0" + S_RESET + " " + S_DIM + "\u2022 25 tools" +
                S_RESET + " " + S_DIM + "\u2022 made by " + S_RESET + S_PURPLE + "Rio" +
                S_RESET + "\n\n");
}

void signOff(int runs) {
    ck::ui::line("");
    ck::ui::line("  " + rule(74));
    ck::ui::line("  " + S_DIM + "made by " + S_RESET + S_PURPLE + "Rio" + S_RESET + S_DIM +
                 "  \u2014  25 tools, one binary, no dependencies." + S_RESET);
    if (runs > 0)
        ck::ui::line("  " + S_DIM + std::to_string(runs) + " tool run" +
                     (runs == 1 ? "" : "s") + " this session." + S_RESET);
    ck::ui::line("  " + rule(74));
    ck::ui::line("");
}

void topRule() { ck::ui::emit(rule(78) + "\n"); }

void catColor(int idx) {
    static const std::string cols[] = {C_A, C_B, C_C, C_D, C_E,
                                       "\033[38;5;215m", "\033[38;5;79m"};
    ck::ui::emit(cols[idx % 7]);
}

void cmdHelp() {
    banner();
    topRule();
    ck::ui::emitf("  %sUSAGE%s\n", C_BOLD, C_RESET);
    ck::ui::emitf("    argus <tool> [arguments]\n");
    ck::ui::emitf("    argus help            %sthis screen%s\n", C_DIM, C_RESET);
    ck::ui::emitf("    argus list [filter]   %slist all tools%s\n", C_DIM, C_RESET);
    ck::ui::emitf("    argus run             %sinteractive picker%s\n", C_DIM, C_RESET);
    ck::ui::emitf("    argus bye             %ssign off / credits%s\n", C_DIM, C_RESET);
    ck::ui::emitf("    argus version\n");
    ck::ui::emitf("\n");
    topRule();
    ck::ui::emitf("  %sEXAMPLES%s\n", C_BOLD, C_RESET);
    ck::ui::emitf("    %sargus hash --alg sha256 --file sample.bin%s\n", C_KEY, C_RESET);
    ck::ui::emitf("    %sargus pw-audit --file passwords.txt --top 10%s\n", C_KEY, C_RESET);
    ck::ui::emitf("    %sargus tls-audit --host lab.internal --i-own-this%s\n", C_KEY, C_RESET);
    ck::ui::emitf("    %sargus log-hunt --file Security.evtx --since 24h%s\n", C_KEY, C_RESET);
    ck::ui::emitf("    %sargus help hash%s\n", C_KEY, C_RESET);
    ck::ui::emitf("\n");
    topRule();
ck::ui::emitf("  %s%s%s  Active scanners require %s--i-own-this%s or an entry in %s~/.argus/allow.txt%s\n",
    C_DIM, "NOTES", C_RESET, C_CRIT, C_RESET, C_KEY, C_RESET);
    ck::ui::emitf("  %s       Every network tool is rate-limited and non-destructive by default.%s\n\n",
           C_DIM, C_RESET);
}

void listTools(const std::string& filter) {
    auto& reg = ck::Registry::instance();
    auto cats = reg.categories();

    std::vector<const ck::Tool*> shown;
    for (auto& t : reg.all()) {
        if (!filter.empty() && !ck::icontains(t.name, filter) &&
            !ck::icontains(t.brief, filter) && !ck::icontains(t.category, filter))
            continue;
        shown.push_back(&t);
    }

    ck::ui::emitf("\n");
    topRule();
    ck::ui::emitf("  %sTOOL REGISTRY%s %s(%zu tool%s%s%s)\n", C_BOLD, C_RESET, C_DIM,
           shown.size(), shown.size() == 1 ? "" : "s", C_RESET,
           filter.empty() ? "" : (std::string(" matching \"") + filter + "\"").c_str());
    topRule();

    if (shown.empty()) {
        ck::ui::emitf("  %sno tool matches \"%s\"%s\n\n", C_DIM, filter.c_str(), C_RESET);
        return;
    }

    int ci = 0;
    for (auto& cat : cats) {
        bool catShown = false;
        std::vector<const ck::Tool*> group;
        for (auto* t : shown)
            if (t->category == cat) group.push_back(t);
        if (group.empty()) continue;
        catColor(ci++);
        ck::ui::emitf("  %s\u25B8%s %s%s%s  %s(%zu)%s\n", cat.c_str(), C_RESET, C_BOLD, cat.c_str(),
                      C_RESET, C_DIM, group.size(), C_RESET);
        for (auto* t : group)
            ck::ui::emitf("    %s%-13s%s %s%s%s\n", C_KEY, t->name.c_str(), C_RESET, C_DIM,
                          ck::ui::truncateTo(t->brief, 60).c_str(), C_RESET);
    }
    ck::ui::emitf("\n");
    topRule();
    ck::ui::emitf("  %sdetails: argus help <tool>%s\n\n", C_DIM, C_RESET);
}

void toolHelp(const ck::Tool& t) {
    ck::ui::emitf("\n");
    topRule();
    ck::ui::emitf("  %s%s%s  %s%s%s\n", C_BOLD, t.name.c_str(), C_RESET, C_DIM, t.category.c_str(), C_RESET);
    topRule();
    ck::ui::emitf("\n  ABOUT\n    %s\n", t.brief.c_str());
    ck::ui::emitf("\n  USAGE\n    %s\n", t.usage.c_str());
    ck::ui::emitf("\n  RUN\n    argus %s\n\n", t.name.c_str());
    ck::ui::emitf("  help <tool> for usage, list for all tools\n\n");
}

std::vector<std::string> tokenize(const std::string& s) {
    std::vector<std::string> out;
    std::string cur;
    bool q = false;
    for (char c : s) {
        if (c == '"') { q = !q; continue; }
        if (!q && (c == ' ' || c == '\t')) {
            if (!cur.empty()) { out.push_back(cur); cur.clear(); }
            continue;
        }
        cur += c;
    }
    if (!cur.empty()) out.push_back(cur);
    return out;
}

void interactive() {
    int runs = 0;
    auto& reg = ck::Registry::instance();
    banner();
    topRule();
    ck::ui::emitf("  %sINTERACTIVE MODE%s  %stype a number or name, 'q' to quit%s\n", C_BOLD, C_RESET,
           C_DIM, C_RESET);
    topRule();

    int ci = 0;
    int idx = 0;
    std::vector<std::string> names;
    for (auto& cat : reg.categories()) {
        catColor(ci++);
        ck::ui::emitf("\n  %s\u25B8%s %s%s%s\n", cat.c_str(), C_RESET, C_BOLD, cat.c_str(), C_RESET);
        for (auto& t : reg.all()) {
            if (t.category != cat) continue;
            char num[8];
            snprintf(num, sizeof(num), "%2d", ++idx);
            ck::ui::emitf("    %s%s%s %s%-12s%s %s%s%s\n", C_DIM, num, C_RESET, C_KEY,
                   t.name.c_str(), C_RESET, C_DIM, ck::ui::truncateTo(t.brief, 54).c_str(),
                   C_RESET);
            names.push_back(t.name);
        }
    }
    ck::ui::emitf("\n");
    topRule();

    while (true) {
        ck::ui::emitf("%s  \u276F%s ", C_B, C_RESET);
        fflush(stdout);
        std::string line;
        if (!std::getline(std::cin, line)) break;
        line = ck::trim(line);
        if (line.empty()) continue;
        if (line == "q" || line == "quit" || line == "exit") break;

        const ck::Tool* t = nullptr;
        if (line.size() <= 3 && line.find_first_not_of("0123456789") == std::string::npos) {
            int n = std::atoi(line.c_str());
            if (n >= 1 && n <= (int)names.size()) t = reg.find(names[n - 1]);
        } else {
            t = reg.find(line);
        }
        if (!t) {
            ck::ui::emitf("%s  unknown tool: %s%s\n", C_CRIT, line.c_str(), C_RESET);
            continue;
        }
        ck::ui::emitf("\n%s  %s%s%s  %s%s%s\n", C_B, C_BOLD, t->name.c_str(), C_RESET, C_DIM,
               t->usage.c_str(), C_RESET);
        ck::ui::emitf("%s  args> %s", C_KEY, C_RESET);
        fflush(stdout);
        std::string a;
        if (!std::getline(std::cin, a)) break;
        std::vector<std::string> argv;
        for (auto& s : tokenize(a)) argv.push_back(s);
        ck::Args args(argv);
        int rc = t->run(args);
        ++runs;        ck::ui::emitf("\n");
        (void)rc;
    }
    signOff(runs);
}

}  // namespace

int main(int argc, char** argv) {
    bool noColor = false;
    std::vector<std::string> args;
    for (int i = 1; i < argc; ++i) {
        std::string a = argv[i];
        if (a == "--no-color" || a == "--nocolor") noColor = true;
        else args.push_back(a);
    }

    ck::ui::initConsole();
    ck::ui::setColor(!noColor);
    ck::netInit();

    int rc = 0;
    if (args.empty()) {
        cmdHelp();
        ck::netShutdown();
        return 0;
    }

    std::string cmd = args[0];
    std::vector<std::string> rest(args.begin() + 1, args.end());

    if (cmd == "help" || cmd == "--help" || cmd == "-h" || cmd == "--help") {
        if (rest.empty()) cmdHelp();
        else {
            const ck::Tool* t = ck::Registry::instance().find(rest[0]);
            if (t) toolHelp(*t);
            else {
                ck::ui::emitf("\n  %sno such tool: %s%s\n\n", C_CRIT, rest[0].c_str(), C_RESET);
                rc = 1;
            }
        }
    } else if (cmd == "version" || cmd == "--version" || cmd == "-v") {
        ck::ui::emitf("argus 2.0  %s25 tools  |  built %s%s\n", C_DIM, __DATE__, C_RESET);
    } else if (cmd == "list" || cmd == "ls") {
        listTools(rest.empty() ? "" : rest[0]);
    } else if (cmd == "run" || cmd == "ui" || cmd == "menu") {
        interactive();
    } else if (cmd == "bye") {
        signOff(0);
    } else {
        const ck::Tool* t = ck::Registry::instance().find(cmd);
        if (!t) {
            ck::ui::emitf("\n  %sunknown tool%s %s\n", C_CRIT, cmd.c_str(), C_RESET);
            ck::ui::emitf("  %srun 'argus list' to see all 25 tools%s\n\n", C_DIM, C_RESET);
            rc = 1;
        } else {
            rc = t->run(ck::Args(rest));
        }
    }

    ck::netShutdown();
    return rc;
}
