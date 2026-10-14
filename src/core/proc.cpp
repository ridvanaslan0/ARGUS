#include "ck/kit.h"

#include <cstdio>
#include <cstring>
#include <cstdlib>
#include <thread>
#include <chrono>
#include <atomic>

#if CK_WINDOWS
#  include <windows.h>
#else
#  include <unistd.h>
#  include <sys/wait.h>
#  include <signal.h>
#endif

namespace ck {

std::string runCapture(const std::string& cmd, int timeoutMs, bool* ok) {
    std::string out;
    if (ok) *ok = false;
#if CK_WINDOWS
    SECURITY_ATTRIBUTES sa;
    sa.nLength = sizeof(sa);
    sa.lpSecurityDescriptor = nullptr;
    sa.bInheritHandle = TRUE;
    HANDLE r, w;
    if (!CreatePipe(&r, &w, &sa, 0)) return out;
    SetHandleInformation(r, HANDLE_FLAG_INHERIT, 0);
    STARTUPINFOA si;
    memset(&si, 0, sizeof(si));
    si.cb = sizeof(si);
    si.dwFlags = STARTF_USESTDHANDLES;
    si.hStdOutput = w;
    si.hStdError = w;
    si.hStdInput = GetStdHandle(STD_INPUT_HANDLE);
    PROCESS_INFORMATION pi;
    memset(&pi, 0, sizeof(pi));
    std::string line = cmd + " 2>&1";
    if (!CreateProcessA(nullptr, (LPSTR)line.c_str(), nullptr, nullptr, TRUE,
                        CREATE_NO_WINDOW, nullptr, nullptr, &si, &pi)) {
        CloseHandle(r);
        CloseHandle(w);
        return out;
    }
    CloseHandle(w);
    char buf[4096];
    DWORD n;
    auto start = std::chrono::steady_clock::now();
    bool killed = false;
    while (true) {
        if (PeekNamedPipe(r, nullptr, 0, nullptr, &n, nullptr) && n == 0) {
            if (WaitForSingleObject(pi.hProcess, 0) == WAIT_OBJECT_0) break;
        }
        if (!ReadFile(r, buf, sizeof(buf), &n, nullptr) || n == 0) break;
        out.append(buf, n);
        if (std::chrono::duration_cast<std::chrono::milliseconds>(
                std::chrono::steady_clock::now() - start).count() > timeoutMs) {
            TerminateProcess(pi.hProcess, 1);
            killed = true;
            break;
        }
    }
    WaitForSingleObject(pi.hProcess, 2000);
    DWORD code = 1;
    GetExitCodeProcess(pi.hProcess, &code);
    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);
    CloseHandle(r);
    if (ok) *ok = !killed && code == 0;
#else
    FILE* f = popen((cmd + " 2>/dev/null").c_str(), "r");
    if (!f) return out;
    char buf[4096];
    size_t n;
    auto start = std::chrono::steady_clock::now();
    while ((n = fread(buf, 1, sizeof(buf), f)) > 0) {
        out.append(buf, n);
        if (std::chrono::duration_cast<std::chrono::milliseconds>(
                std::chrono::steady_clock::now() - start).count() > timeoutMs)
            break;
    }
    int code = pclose(f);
    if (ok) *ok = (code == 0);
#endif
    return out;
}

int runInteractive(const std::string& cmd) {
#if CK_WINDOWS
    return system((cmd + " 2>&1").c_str());
#else
    return system((cmd + " 2>&1").c_str());
#endif
}

std::string which(const std::string& exe) {
#if CK_WINDOWS
    if (GetFileAttributesA(exe.c_str()) != INVALID_FILE_ATTRIBUTES) return exe;
    std::string path = runCapture("where " + exe + " 2>NUL");
    if (!path.empty()) return splitLines(path)[0];
    return "";
#else
    if (exe.find('/') != std::string::npos) return exe;
    std::string out = runCapture("command -v " + exe);
    return trim(out);
#endif
}

}  // namespace ck