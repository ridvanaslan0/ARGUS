#include "ck/kit.h"

#include <cstring>
#include <cstdio>

#if CK_WINDOWS
#  include <windows.h>
#  include <bcrypt.h>
#  include <stdlib.h>
#  pragma comment(lib, "bcrypt.lib")
#  pragma comment(lib, "advapi32.lib")
#else
#  include <unistd.h>
#  include <fcntl.h>
#  include <sys/random.h>
#endif

namespace ck {

namespace {

bool osRandom(uint8_t* out, size_t n) {
#if CK_WINDOWS
    if (BCryptGenRandom(nullptr, out, (ULONG)n, BCRYPT_USE_SYSTEM_PREFERRED_RNG) == 0)
        return true;
    typedef BOOLEAN(WINAPI * RtlGenRandomFn)(PVOID, ULONG);
    static RtlGenRandomFn rtl = nullptr;
    static bool resolved = false;
    if (!resolved) {
        resolved = true;
        HMODULE k32 = GetModuleHandleA("kernel32.dll");
        (void)k32;
        HMODULE adv = LoadLibraryA("advapi32.dll");
        if (adv)
            rtl = (RtlGenRandomFn)(void*)GetProcAddress(adv, "SystemFunction036");
    }
    if (rtl) {
        ULONG chunk = 0x8000;
        size_t done = 0;
        while (done < n) {
            ULONG take = (ULONG)((n - done < chunk) ? (n - done) : chunk);
            if (!rtl(out + done, take)) return false;
            done += take;
        }
        return true;
    }
    return false;
#else
    size_t got = 0;
    while (got < n) {
        ssize_t r = getrandom(out + got, n - got, 0);
        if (r <= 0) {
            int fd = open("/dev/urandom", O_RDONLY);
            if (fd < 0) return false;
            while (got < n) {
                ssize_t rr = read(fd, out + got, n - got);
                if (rr <= 0) break;
                got += (size_t)rr;
            }
            close(fd);
            return got == n;
        }
        got += (size_t)r;
    }
    return true;
#endif
}

}  // namespace

bool secureRandomAvailable() {
    uint8_t a[32], b[32];
    if (!osRandom(a, 32) || !osRandom(b, 32)) return false;
    return memcmp(a, b, 32) != 0;
}

void randomBytes(uint8_t* out, size_t n) {
    if (n == 0) return;
    if (osRandom(out, n)) return;
    for (size_t i = 0; i < n; ++i) out[i] = (uint8_t)(rand() & 0xFF);
}

Bytes randomBytes(size_t n) {
    Bytes b(n);
    if (n) randomBytes(b.data(), n);
    return b;
}

uint32_t randomU32() {
    uint8_t b[4];
    randomBytes(b, 4);
    return (uint32_t)b[0] | ((uint32_t)b[1] << 8) | ((uint32_t)b[2] << 16) | ((uint32_t)b[3] << 24);
}

uint32_t randomRange(uint32_t loInclusive, uint32_t hiExclusive) {
    if (hiExclusive <= loInclusive) return loInclusive;
    uint32_t span = hiExclusive - loInclusive;
    uint32_t limit = (uint32_t)(0xFFFFFFFFu - (0xFFFFFFFFu % span) - 1);
    for (int i = 0; i < 64; ++i) {
        uint32_t v = randomU32();
        if (v <= limit) return loInclusive + (v % span);
    }
    return loInclusive + (randomU32() % span);
}

std::string randomHex(size_t bytes) {
    return hexEncode(randomBytes(bytes).data(), bytes);
}

std::string uuidV4() {
    Bytes b = randomBytes(16);
    b[6] = (uint8_t)((b[6] & 0x0F) | 0x40);
    b[8] = (uint8_t)((b[8] & 0x3F) | 0x80);
    std::string h = hexEncode(b.data(), 16);
    return h.substr(0, 8) + "-" + h.substr(8, 4) + "-" + h.substr(12, 4) + "-" +
           h.substr(16, 4) + "-" + h.substr(20, 12);
}

std::string secureToken(size_t bytes) {
    Bytes b = randomBytes(bytes);
    return base64Encode(b, true, false);
}

}  // namespace ck