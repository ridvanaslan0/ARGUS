#include "ck/kit.h"

#include <cstdarg>
#include <cstdio>
#include <cstring>
#include <cmath>
#include <algorithm>
#include <iomanip>
#include <sstream>

#if CK_WINDOWS
#  include <windows.h>
#else
#  include <unistd.h>
#endif

namespace ck {
namespace ui {
namespace {

bool gColor = false;
bool gUnicode = false;

struct Theme {
    std::string reset = "\033[0m";
    std::string dim = "\033[2;37m";
    std::string bold = "\033[1m";
    std::string accent = "\033[38;5;44m";
    std::string accent2 = "\033[38;5;205m";
    std::string ok = "\033[38;5;46m";
    std::string warn = "\033[38;5;214m";
    std::string crit = "\033[38;5;196m";
    std::string info = "\033[38;5;39m";
    std::string key = "\033[38;5;250m";
    std::string border = "\033[38;5;60m";
};

const Theme THEME;

void enableVt() {
#if CK_WINDOWS
    HANDLE h = GetStdHandle(STD_OUTPUT_HANDLE);
    DWORD mode = 0;
    if (GetConsoleMode(h, &mode) && !(mode & ENABLE_VIRTUAL_TERMINAL_PROCESSING))
        SetConsoleMode(h, mode | ENABLE_VIRTUAL_TERMINAL_PROCESSING);
    HANDLE hin = GetStdHandle(STD_INPUT_HANDLE);
    DWORD imode = 0;
    if (GetConsoleMode(hin, &imode) && !(imode & ENABLE_VIRTUAL_TERMINAL_PROCESSING))
        SetConsoleMode(hin, imode | ENABLE_VIRTUAL_TERMINAL_PROCESSING);
#endif
}

size_t charWidth(unsigned char c) {
    if (c < 0x20) return 0;
    if ((c >= 0x41 && c <= 0x5A) || (c >= 0x61 && c <= 0x7A) || (c >= '0' && c <= '9'))
        return 1;
    static const char* wide = "\xE2\x96\x80\xE2\x96\x81\xE2\x96\x82\xE2\x96\x83\xE2\x96\x84"
                              "\xE2\x96\x85\xE2\x96\x86\xE2\x96\x87\xE2\x96\x88\xE2\x96\x89"
                              "\xE2\x96\x8A\xE2\x96\x8B\xE2\x96\x8C\xE2\x96\x8D\xE2\x96\x8E"
                              "\xE2\x96\x8F\xE2\x97\x80\xE2\x97\x81\xE2\x97\x82\xE2\x97\x83"
                              "\xE2\x97\x84\xE2\x97\x85\xE2\x97\x86\xE2\x97\x87\xE2\x97\x88"
                              "\xE2\x97\x89\xE2\x97\x8A\xE2\x97\x8B\xE2\x97\x8C\xE2\x97\x8D"
                              "\xE2\x97\x8E\xE2\x97\x8F";
    std::string one(1, (char)c);
    if (strstr(wide, one.c_str())) return 2;
    return 1;
}

size_t displayWidthImpl(const std::string& s) {
    size_t w = 0;
    for (size_t i = 0; i < s.size();) {
        if (s[i] == '\033') {
            while (i < s.size() && s[i] != 'm') ++i;
            ++i;
            continue;
        }
        w += charWidth((unsigned char)s[i]);
        ++i;
    }
    return w;
}

std::string padToImpl(const std::string& s, size_t w) {
    size_t cur = displayWidthImpl(s);
    if (cur >= w) return s;
    std::string out = s;
    out += std::string(w - cur, ' ');
    return out;
}

std::string truncateToImpl(const std::string& s, size_t w) {
    if (displayWidthImpl(s) <= w) return s;
    size_t out = 0, i = 0;
    std::string r;
    while (i < s.size() && out < w - 1) {
        if (s[i] == '\033') {
            while (i < s.size() && s[i] != 'm') { r += s[i]; ++i; }
            if (i < s.size()) { r += s[i]; ++i; }
            continue;
        }
        size_t cw = charWidth((unsigned char)s[i]);
        if (out + cw > w - 1) break;
        r += s[i];
        out += cw;
        ++i;
    }
    r += "\033[0m~";
    return r;
}

std::string boxH(const char* l, const char* m, const char* r, size_t w) {
    std::string out = l;
    for (size_t i = 0; i < w; ++i) out += m;
    out += r;
    return out;
}

std::string hlineImpl(size_t n) {
    std::string out;
    for (size_t i = 0; i < n; ++i) out += "\u2500";
    return out;
}

void printBox(const std::string& title, const std::vector<std::string>& rows, int tone) {
    size_t inner = 74;
    size_t tw = displayWidth(title);
    if (tw + 4 > inner) inner = tw + 4;

    const std::string& toneColor = tone == 0 ? THEME.accent : tone == 1 ? THEME.accent2 : THEME.ok;

    std::string top;
    if (title.empty()) {
        top = THEME.border + "\u250c" + hlineImpl(inner) + "\u2510" + THEME.reset;
    } else {
        top = THEME.border + "\u250c\u2500 " + toneColor + THEME.bold + title + THEME.reset +
              THEME.border + " ";
        size_t used = 3 + tw + 1;
        for (size_t i = used; i < inner + 1; ++i) top += "\u2500";
        top += "\u2510" + THEME.reset;
    }

    line(top);
    for (auto& r : rows) {
        std::string clean = r;
        line(THEME.border + "\u2502" + THEME.reset + " " + truncateTo(clean, inner) +
             std::string(inner > displayWidth(clean) ? inner - displayWidth(clean) : 0, ' ') +
             " " + THEME.border + "\u2502" + THEME.reset);
    }
    line(THEME.border + "\u2514" + hlineImpl(inner) + "\u2518" + THEME.reset);
}

}  // namespace

std::string hline(size_t n);

size_t displayWidth(const std::string& s) { return ui::displayWidthImpl(s); }
std::string padTo(const std::string& s, size_t w) { return ui::padToImpl(s, w); }
std::string truncateTo(const std::string& s, size_t w) { return ui::truncateToImpl(s, w); }

std::string hline(size_t n) { return ui::hlineImpl(n); }

bool colorEnabled() { return gColor; }

static bool g_unicode = false;

bool unicodeOk() { return g_unicode; }

void initConsole() {
#if CK_WINDOWS
    SetConsoleOutputCP(CP_UTF8);
    SetConsoleCP(CP_UTF8);
    HANDLE h = GetStdHandle(STD_OUTPUT_HANDLE);
    CONSOLE_FONT_INFOEX fi;
    memset(&fi, 0, sizeof(fi));
    fi.cbSize = sizeof(fi);
    fi.dwFontSize.X = 11;
    fi.dwFontSize.Y = 11;
    const wchar_t* faces[] = {L"Cascadia Mono", L"Consolas", L"Lucida Console", L"Courier New"};
    bool okFont = false;
    for (auto f : faces) {
        wcscpy_s(fi.FaceName, f);
        if (SetCurrentConsoleFontEx(h, TRUE, &fi)) { okFont = true; break; }
    }
    g_unicode = (GetConsoleOutputCP() == CP_UTF8) && okFont;
    if (!g_unicode && GetConsoleOutputCP() == CP_UTF8) {
        CONSOLE_FONT_INFOEX cur;
        memset(&cur, 0, sizeof(cur));
        cur.cbSize = sizeof(cur);
        if (GetCurrentConsoleFontEx(h, FALSE, &cur)) {
            static const wchar_t* tt[] = {L"Cascadia Mono", L"Cascadia Code", L"Consolas",
                                          L"Lucida Console", L"NSimSun", L"MS Gothic"};
            for (auto f : tt)
                if (_wcsicmp(cur.FaceName, f) == 0) { g_unicode = true; break; }
        }
    }
#else
    g_unicode = true;
#endif
}

std::string translit(const std::string& s) {
    if (g_unicode) return s;
    static const struct { const char* u; char a; } map[] = {
        {"\u2500", '-'}, {"\u2501", '='}, {"\u2502", '|'}, {"\u2503", '|'},
        {"\u250c", '+'}, {"\u250f", '+'}, {"\u2510", '+'}, {"\u2513", '+'},
        {"\u2514", '+'}, {"\u2517", '+'}, {"\u2518", '+'}, {"\u251b", '+'},
        {"\u251c", '+'}, {"\u2524", '+'}, {"\u252c", '+'}, {"\u2534", '+'},
        {"\u253c", '+'}, {"\u250d", '+'}, {"\u251e", '+'}, {"\u2525", '+'},
        {"\u252f", '+'}, {"\u2535", '+'}, {"\u253f", '+'},
        {"\u2588", '#'}, {"\u2593", '#'}, {"\u2591", '.'}, {"\u2592", ':'},
        {"\u25b8", '>'}, {"\u25b6", '>'}, {"\u2022", '-'}, {"\u00b7", '-'},
        {"\u2713", '+'}, {"\u2714", '+'}, {"\u2717", 'x'}, {"\u2718", 'x'},
        {"\u00bb", '>'}, {"\u203a", '>'},
        {"\u2014", '-'}, {"\u2013", '-'}, {"\u2212", '-'}, {"\u00d7", 'x'},
        {"\u2018", '\''}, {"\u2019", '\''}, {"\u201c", '"'}, {"\u201d", '"'},
        {"\u2026", '.'}, {"\u00a0", ' '}, {"\u2192", '>'}, {"\u2190", '<'},
        {"\u280b", '*'}, {"\u2819", '*'}, {"\u2839", '*'}, {"\u2838", '*'},
        {"\u283c", '*'}, {"\u2834", '*'}, {"\u2826", '*'}, {"\u2827", '*'},
        {"\u2807", '*'}, {"\u280f", '*'},
    };
    std::string out;
    out.reserve(s.size());
    size_t i = 0;
    while (i < s.size()) {
        unsigned char c = (unsigned char)s[i];
        if (c == 0x1B) {
            size_t j = i + 1;
            if (j < s.size() && s[j] == '[') {
                ++j;
                while (j < s.size() && s[j] != 'm') ++j;
                if (j < s.size()) ++j;
            }
            out.append(s, i, j - i);
            i = j;
            continue;
        }
        if (c < 0x80) { out += (char)c; ++i; continue; }
        size_t len = 0;
        if ((c & 0xE0) == 0xC0) len = 2;
        else if ((c & 0xF0) == 0xE0) len = 3;
        else if ((c & 0xF8) == 0xF0) len = 4;
        else { ++i; continue; }
        if (i + len > s.size()) { ++i; continue; }
        bool matched = false;
        for (auto& m : map) {
            if (s.compare(i, len, m.u) == 0) { out += m.a; matched = true; break; }
        }
        if (!matched) out += '?';
        i += len;
    }
    return out;
}

void emit(const std::string& s) {
    fputs(translit(s).c_str(), stdout);
}

void emitf(const char* fmt, ...) {
    char stackBuf[1024];
    va_list ap;
    va_start(ap, fmt);
    int n = vsnprintf(stackBuf, sizeof(stackBuf), fmt, ap);
    va_end(ap);
    if (n < 0) return;
    if (n < (int)sizeof(stackBuf)) { emit(std::string(stackBuf, n)); return; }
    std::vector<char> big((size_t)n + 1);
    va_start(ap, fmt);
    vsnprintf(big.data(), big.size(), fmt, ap);
    va_end(ap);
    emit(std::string(big.data(), n));
}

void setColor(bool on) {
    if (on) enableVt();
    gColor = on;
#if CK_WINDOWS
    gUnicode = GetConsoleOutputCP() == 65001;
#else
    gUnicode = true;
#endif
}

void title(const std::string& s) {
    std::string t = THEME.bold + THEME.accent + "  " + s + THEME.reset;
    line(t);
}

void section(const std::string& s) {
    line("");
    std::string bar = THEME.accent2 + "\u250c\u2500\u2500 " + THEME.bold + THEME.reset + THEME.accent2 +
                      s + THEME.reset;
    size_t w = displayWidth(s) + 5;
    line(bar);
    line(THEME.accent2 + "\u2514" + hlineImpl(w < 76 ? w : 76) + THEME.reset);
}

void kv(const std::string& k, const std::string& v) {
    std::string key = padTo(k, 30);
    line("  " + THEME.key + key + THEME.reset + " " + THEME.dim + "\u2502" + THEME.reset + " " + v);
}

void line(const std::string& s) { emit(s + "\n"); }

void raw(const std::string& s) { emit(s); }

void ok(const std::string& s) {
    line("  " + THEME.ok + "[ \u2713 ]" + THEME.reset + " " + s);
}

void warn(const std::string& s) {
    line("  " + THEME.warn + "[ ! ]" + THEME.reset + " " + s);
}

void fail(const std::string& s) {
    line("  " + THEME.crit + "[ \u2717 ]" + THEME.reset + " " + s);
}

void info(const std::string& s) {
    line("  " + THEME.info + "[ i ]" + THEME.reset + " " + s);
}

void bullet(const std::string& s) {
    line("    " + THEME.dim + "\u2022" + THEME.reset + " " + s);
}

static const size_t kTableWidth = 76;

static void allocCols(const std::vector<size_t>& nat, size_t budget, size_t minW,
                      std::vector<size_t>& w) {
    size_t n = nat.size();
    w.assign(n, minW);
    size_t sumNat = 0;
    for (size_t v : nat) sumNat += v;
    if (sumNat <= budget) { w = nat; return; }
    size_t given = 0;
    std::vector<std::pair<double, size_t>> rem(n);
    for (size_t i = 0; i < n; ++i) {
        double share = (double)nat[i] / (double)sumNat * (double)budget;
        size_t add = (size_t)share;
        if (add < minW) add = minW;
        rem[i] = {share - (double)add, i};
        w[i] += add;
        given += add;
    }
    size_t total = 0;
    for (size_t v : w) total += v;
    while (total > budget) {
        size_t widest = 0;
        for (size_t i = 1; i < n; ++i)
            if (w[i] > w[widest]) widest = i;
        if (w[widest] <= minW) break;
        --w[widest];
        --total;
    }
}

void table(const std::vector<std::string>& headers, const std::vector<std::vector<std::string>>& rows) {
    if (headers.empty()) return;
    size_t cols = headers.size();
    std::vector<size_t> nat(cols, 0);
    for (size_t i = 0; i < cols; ++i) nat[i] = std::max<size_t>(4, displayWidth(headers[i]));
    for (auto& r : rows)
        for (size_t i = 0; i < r.size() && i < cols; ++i)
            nat[i] = std::max(nat[i], displayWidth(r[i]));

    size_t budget = kTableWidth - 3 * cols - 1;
    size_t floor = 6 * cols;
    if (budget < floor) budget = floor;

    std::vector<size_t> w;
    allocCols(nat, budget, 6, w);

    size_t inner = 1;
    for (size_t i = 0; i < cols; ++i) inner += w[i] + 2;
    inner += cols - 1;

    std::string bar = THEME.border + "\u250c";
    for (size_t i = 0; i < cols; ++i) {
        if (i) bar += "\u252c";
        bar += hlineImpl(w[i] + 2);
    }
    line(bar + "\u2510" + THEME.reset);

    std::string sep = THEME.border + "\u251c";
    for (size_t i = 0; i < cols; ++i) {
        if (i) sep += "\u253c";
        sep += hlineImpl(w[i] + 2);
    }
    sep += "\u2524" + THEME.reset;
    line(sep);

    std::string head = THEME.border + "\u2502" + THEME.reset + " ";
    for (size_t i = 0; i < cols; ++i) {
        head += THEME.bold + THEME.accent + padTo(truncateTo(headers[i], w[i]), w[i]) + THEME.reset + " ";
        if (i + 1 < cols) head += THEME.border + "\u2502" + THEME.reset + " ";
    }
    head += THEME.border + "\u2502" + THEME.reset;
    line(head);
    line(sep);

    for (auto& r : rows) {
        std::string row = THEME.border + "\u2502" + THEME.reset + " ";
        for (size_t i = 0; i < cols; ++i) {
            std::string cell = i < r.size() ? r[i] : "";
            row += padTo(truncateTo(cell, w[i]), w[i]) + " ";
            if (i + 1 < cols) row += THEME.border + "\u2502" + THEME.reset + " ";
        }
        row += THEME.border + "\u2502" + THEME.reset;
        line(row);
    }
    line(THEME.border + "\u2514" + [&] {
        std::string b;
        for (size_t i = 0; i < cols; ++i) {
            if (i) b += "\u2534";
            b += hlineImpl(w[i] + 2);
        }
        return b;
    }() + "\u2518" + THEME.reset);
}

std::string bar(double fraction, int width) {
    if (fraction < 0) fraction = 0;
    if (fraction > 1) fraction = 1;
    int filled = (int)(fraction * width + 0.5);
    std::string out = THEME.accent;
    for (int i = 0; i < filled; ++i) out += "\u2588";
    if (filled < width) {
        out += THEME.dim;
        for (int i = filled; i < width; ++i) out += "\u2591";
    }
    out += THEME.reset;
    char buf[32];
    snprintf(buf, sizeof(buf), " %5.1f%%", fraction * 100.0);
    out += buf;
    return out;
}

double severityScore(int low, int med, int high, int crit) {
    double s = (double)low * 2 + med * 6 + high * 14 + crit * 30;
    return s;
}

std::string severityLabel(double score) {
    if (score < 10) return THEME.ok + "LOW" + THEME.reset;
    if (score < 40) return THEME.warn + "MEDIUM" + THEME.reset;
    if (score < 90) return THEME.warn + "HIGH" + THEME.reset;
    return THEME.crit + "CRITICAL" + THEME.reset;
}

int severityColor(double score) {
    if (score < 10) return 0;
    if (score < 40) return 1;
    if (score < 90) return 2;
    return 3;
}

void printCard(const std::string& t, const std::vector<std::string>& rows, int tone) {
    printBox(t, rows, tone);
}

}  // namespace ui

void progressBar(const std::string& label, size_t done, size_t total, int width) {
    static const std::string accent2 = "\033[38;5;205m";
    static const std::string reset = "\033[0m";
    double f = total ? (double)done / (double)total : 0.0;
    std::string msg = "  " + accent2 + label + reset + " " + ui::bar(f, width);
    size_t pad = 84 > msg.size() ? 84 - ui::displayWidth(msg) : 0;
    ck::ui::emit(msg + std::string(pad, ' '));
    fputs("\r", stdout);
    fflush(stdout);
}

void spinnerStart(const std::string& msg) {
    static const std::string accent2 = "\033[38;5;205m";
    static const std::string reset = "\033[0m";
    ck::ui::emit("  " + accent2 + (ck::ui::unicodeOk() ? "\u280B" : "*") + reset + " " + msg);
    fputs("\r", stdout);
    fflush(stdout);
}

void spinnerStop() {
    fputs("\r\033[K", stdout);
    fflush(stdout);
}

}  // namespace ck
