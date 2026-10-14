#include "ck/kit.h"

#include <cstring>
#include <algorithm>

namespace ck {
namespace aes {
namespace {

const uint8_t SBOX[256] = {
0x63,0x7c,0x77,0x7b,0xf2,0x6b,0x6f,0xc5,0x30,0x01,0x67,0x2b,0xfe,0xd7,0xab,0x76,
0xca,0x82,0xc9,0x7d,0xfa,0x59,0x47,0xf0,0xad,0xd4,0xa2,0xaf,0x9c,0xa4,0x72,0xc0,
0xb7,0xfd,0x93,0x26,0x36,0x3f,0xf7,0xcc,0x34,0xa5,0xe5,0xf1,0x71,0xd8,0x31,0x15,
0x04,0xc7,0x23,0xc3,0x18,0x96,0x05,0x9a,0x07,0x12,0x80,0xe2,0xeb,0x27,0xb2,0x75,
0x09,0x83,0x2c,0x1a,0x1b,0x6e,0x5a,0xa0,0x52,0x3b,0xd6,0xb3,0x29,0xe3,0x2f,0x84,
0x53,0xd1,0x00,0xed,0x20,0xfc,0xb1,0x5b,0x6a,0xcb,0xbe,0x39,0x4a,0x4c,0x58,0xcf,
0xd0,0xef,0xaa,0xfb,0x43,0x4d,0x33,0x85,0x45,0xf9,0x02,0x7f,0x50,0x3c,0x9f,0xa8,
0x51,0xa3,0x40,0x8f,0x92,0x9d,0x38,0xf5,0xbc,0xb6,0xda,0x21,0x10,0xff,0xf3,0xd2,
0xcd,0x0c,0x13,0xec,0x5f,0x97,0x44,0x17,0xc4,0xa7,0x7e,0x3d,0x64,0x5d,0x19,0x73,
0x60,0x81,0x4f,0xdc,0x22,0x2a,0x90,0x88,0x46,0xee,0xb8,0x14,0xde,0x5e,0x0b,0xdb,
0xe0,0x32,0x3a,0x0a,0x49,0x06,0x24,0x5c,0xc2,0xd3,0xac,0x62,0x91,0x95,0xe4,0x79,
0xe7,0xc8,0x37,0x6d,0x8d,0xd5,0x4e,0xa9,0x6c,0x56,0xf4,0xea,0x65,0x7a,0xae,0x08,
0xba,0x78,0x25,0x2e,0x1c,0xa6,0xb4,0xc6,0xe8,0xdd,0x74,0x1f,0x4b,0xbd,0x8b,0x8a,
0x70,0x3e,0xb5,0x66,0x48,0x03,0xf6,0x0e,0x61,0x35,0x57,0xb9,0x86,0xc1,0x1d,0x9e,
0xe1,0xf8,0x98,0x11,0x69,0xd9,0x8e,0x94,0x9b,0x1e,0x87,0xe9,0xce,0x55,0x28,0xdf,
0x8c,0xa1,0x89,0x0d,0xbf,0xe6,0x42,0x68,0x41,0x99,0x2d,0x0f,0xb0,0x54,0xbb,0x16};

uint8_t RSBOX[256];
bool rsboxReady = false;

void ensureRsbox() {
    if (rsboxReady) return;
    for (int i = 0; i < 256; ++i) RSBOX[SBOX[i]] = (uint8_t)i;
    rsboxReady = true;
}

uint8_t xtime(uint8_t x) { return (uint8_t)((x << 1) ^ ((x & 0x80) ? 0x1b : 0x00)); }

uint8_t gmul(uint8_t a, uint8_t b) {
    uint8_t p = 0;
    for (int i = 0; i < 8; ++i) {
        if (b & 1) p ^= a;
        uint8_t hi = (uint8_t)(a & 0x80);
        a = (uint8_t)(a << 1);
        if (hi) a ^= 0x1b;
        b = (uint8_t)(b >> 1);
    }
    return p;
}

void addRoundKey(uint8_t* s, const uint8_t* rk) {
    for (int i = 0; i < 16; ++i) s[i] ^= rk[i];
}

void subBytes(uint8_t* s) {
    for (int i = 0; i < 16; ++i) s[i] = SBOX[s[i]];
}

void invSubBytes(uint8_t* s) {
    ensureRsbox();
    for (int i = 0; i < 16; ++i) s[i] = RSBOX[s[i]];
}

void shiftRows(uint8_t* s) {
    uint8_t t[16];
    for (int r = 0; r < 4; ++r)
        for (int c = 0; c < 4; ++c)
            t[r + 4 * c] = s[r + 4 * ((c + r) % 4)];
    memcpy(s, t, 16);
}

void invShiftRows(uint8_t* s) {
    uint8_t t[16];
    for (int r = 0; r < 4; ++r)
        for (int c = 0; c < 4; ++c)
            t[r + 4 * ((c + r) % 4)] = s[r + 4 * c];
    memcpy(s, t, 16);
}

void mixColumns(uint8_t* s) {
    for (int c = 0; c < 4; ++c) {
        uint8_t* col = s + 4 * c;
        uint8_t a0 = col[0], a1 = col[1], a2 = col[2], a3 = col[3];
        col[0] = (uint8_t)(gmul(a0,2) ^ gmul(a1,3) ^ a2 ^ a3);
        col[1] = (uint8_t)(a0 ^ gmul(a1,2) ^ gmul(a2,3) ^ a3);
        col[2] = (uint8_t)(a0 ^ a1 ^ gmul(a2,2) ^ gmul(a3,3));
        col[3] = (uint8_t)(gmul(a0,3) ^ a1 ^ a2 ^ gmul(a3,2));
    }
}

void invMixColumns(uint8_t* s) {
    for (int c = 0; c < 4; ++c) {
        uint8_t* col = s + 4 * c;
        uint8_t a0 = col[0], a1 = col[1], a2 = col[2], a3 = col[3];
        col[0] = (uint8_t)(gmul(a0,14) ^ gmul(a1,11) ^ gmul(a2,13) ^ gmul(a3,9));
        col[1] = (uint8_t)(gmul(a0,9) ^ gmul(a1,14) ^ gmul(a2,11) ^ gmul(a3,13));
        col[2] = (uint8_t)(gmul(a0,13) ^ gmul(a1,9) ^ gmul(a2,14) ^ gmul(a3,11));
        col[3] = (uint8_t)(gmul(a0,11) ^ gmul(a1,13) ^ gmul(a2,9) ^ gmul(a3,14));
    }
}

uint64_t loadU64be(const uint8_t* p) {
    uint64_t v = 0;
    for (int i = 0; i < 8; ++i) v = (v << 8) | p[i];
    return v;
}

void storeU64be(uint8_t* p, uint64_t v) {
    for (int i = 0; i < 8; ++i) p[i] = (uint8_t)(v >> (56 - 8 * i));
}

struct GHash {
    uint8_t y[16] = {0};
    uint8_t buf[16] = {0};
    size_t bufLen = 0;
    Bytes h;

    void reset() {
        memset(y, 0, 16);
        memset(buf, 0, 16);
        bufLen = 0;
    }

    void xorAndMul() {
        for (int i = 0; i < 16; ++i) y[i] ^= buf[i];
        mul();
    }

    void absorb(const uint8_t* p, size_t n) {
        while (n > 0) {
            size_t take = 16 - bufLen;
            if (take > n) take = n;
            memcpy(buf + bufLen, p, take);
            bufLen += take;
            p += take;
            n -= take;
            if (bufLen == 16) {
                xorAndMul();
                memset(buf, 0, 16);
                bufLen = 0;
            }
        }
    }

    void padTo16() {
        if (bufLen == 0) return;
        memset(buf + bufLen, 0, 16 - bufLen);
        xorAndMul();
        memset(buf, 0, 16);
        bufLen = 0;
    }

    void mul() {
        uint64_t zh = 0, zl = 0, vh = loadU64be(h.data()), vl = loadU64be(h.data() + 8);
        uint64_t xh = loadU64be(y), xl = loadU64be(y + 8);
        for (int i = 0; i < 128; ++i) {
            uint64_t bit = (i < 64) ? ((xh >> (63 - i)) & 1ULL) : ((xl >> (127 - i)) & 1ULL);
            if (bit) { zh ^= vh; zl ^= vl; }
            uint64_t lsb = vl & 1ULL;
            vl = (vl >> 1) | (vh << 63);
            vh = vh >> 1;
            if (lsb) vh ^= 0xe100000000000000ULL;
        }
        storeU64be(y, zh);
        storeU64be(y + 8, zl);
    }

    void lengths(size_t aadLen, size_t ctLen) {
        uint8_t l[16];
        storeU64be(l, (uint64_t)aadLen * 8);
        storeU64be(l + 8, (uint64_t)ctLen * 8);
        absorb(l, 16);
    }
};

Bytes inc32(Bytes block) {
    for (int i = 15; i >= 12; --i) if (++block[i] != 0) break;
    return block;
}

}  // namespace

size_t keyBitsFromName(const std::string& s) {
    std::string n = toLower(s);
    if (n == "128" || n == "aes128") return 128;
    if (n == "192" || n == "aes192") return 192;
    return 256;
}

std::string name() { return "AES-128/192/256 ECB/CBC/CTR/GCM"; }

Bytes randomBytesOnly(size_t n) { return randomBytes(n); }

Bytes expandKey(const Bytes& key) {
    size_t nk = key.size() / 4;
    if (nk < 4 || nk > 8) return Bytes();
    size_t rounds = nk + 6;
    size_t total = 16 * (rounds + 1);
    Bytes rk(total, 0);
    memcpy(rk.data(), key.data(), key.size());

    uint8_t rcon = 1;
    for (size_t i = key.size(); i < total; i += 4) {
        uint8_t t[4] = {rk[i - 4], rk[i - 3], rk[i - 2], rk[i - 1]};
        if ((i / 4) % nk == 0) {
            uint8_t tmp = t[0];
            t[0] = (uint8_t)(SBOX[t[1]] ^ rcon);
            t[1] = SBOX[t[2]];
            t[2] = SBOX[t[3]];
            t[3] = SBOX[tmp];
            rcon = xtime(rcon);
        } else if (nk > 6 && (i / 4) % nk == 4) {
            for (int k = 0; k < 4; ++k) t[k] = SBOX[t[k]];
        }
        for (int k = 0; k < 4; ++k) rk[i + k] = (uint8_t)(rk[i - nk * 4 + k] ^ t[k]);
    }
    return rk;
}

Bytes encryptBlock(const Bytes& roundKeys, const Bytes& block) {
    if (roundKeys.empty() || block.size() < 16) return Bytes();
    size_t rounds = roundKeys.size() / 16 - 1;
    uint8_t s[16];
    memcpy(s, block.data(), 16);

    addRoundKey(s, roundKeys.data());
    for (size_t r = 1; r < rounds; ++r) {
        subBytes(s);
        shiftRows(s);
        mixColumns(s);
        addRoundKey(s, roundKeys.data() + r * 16);
    }
    subBytes(s);
    shiftRows(s);
    addRoundKey(s, roundKeys.data() + rounds * 16);
    return Bytes(s, s + 16);
}

Bytes decryptBlock(const Bytes& roundKeys, const Bytes& block) {
    if (roundKeys.empty() || block.size() < 16) return Bytes();
    size_t rounds = roundKeys.size() / 16 - 1;
    uint8_t s[16];
    memcpy(s, block.data(), 16);

    addRoundKey(s, roundKeys.data() + rounds * 16);
    for (size_t r = rounds; r > 0; --r) {
        invShiftRows(s);
        invSubBytes(s);
        addRoundKey(s, roundKeys.data() + (r - 1) * 16);
        if (r > 1) invMixColumns(s);
    }
    return Bytes(s, s + 16);
}

Bytes ecbEncrypt(const Bytes& key, const Bytes& in) {
    Bytes rk = expandKey(key);
    if (rk.empty()) return Bytes();
    Bytes out;
    for (size_t i = 0; i + 16 <= in.size(); i += 16) {
        Bytes blk(in.begin() + i, in.begin() + i + 16);
        Bytes c = encryptBlock(rk, blk);
        out.insert(out.end(), c.begin(), c.end());
    }
    return out;
}

Bytes cbcEncrypt(const Bytes& key, const Bytes& iv, const Bytes& pt) {
    Bytes rk = expandKey(key);
    if (rk.empty() || iv.size() != 16) return Bytes();
    Bytes data = pt;
    uint8_t pad = (uint8_t)(16 - (data.size() % 16));
    data.insert(data.end(), pad, pad);
    Bytes out;
    uint8_t prev[16];
    memcpy(prev, iv.data(), 16);
    for (size_t i = 0; i < data.size(); i += 16) {
        uint8_t blk[16];
        for (int j = 0; j < 16; ++j) blk[j] = (uint8_t)(data[i + j] ^ prev[j]);
        Bytes c = encryptBlock(rk, Bytes(blk, blk + 16));
        memcpy(prev, c.data(), 16);
        out.insert(out.end(), c.begin(), c.end());
    }
    return out;
}

Bytes cbcDecrypt(const Bytes& key, const Bytes& iv, const Bytes& ct) {
    Bytes rk = expandKey(key);
    if (rk.empty() || iv.size() != 16 || ct.size() % 16 != 0) return Bytes();
    Bytes out;
    uint8_t prev[16];
    memcpy(prev, iv.data(), 16);
    for (size_t i = 0; i < ct.size(); i += 16) {
        uint8_t cur[16];
        memcpy(cur, ct.data() + i, 16);
        Bytes d = decryptBlock(rk, Bytes(cur, cur + 16));
        for (int j = 0; j < 16; ++j) d[j] = (uint8_t)(d[j] ^ prev[j]);
        memcpy(prev, cur, 16);
        out.insert(out.end(), d.begin(), d.end());
    }
    if (!out.empty()) {
        uint8_t pad = out.back();
        if (pad >= 1 && pad <= 16 && (size_t)pad <= out.size())
            out.resize(out.size() - pad);
    }
    return out;
}

Bytes ctrCrypt(const Bytes& key, const Bytes& iv, const Bytes& in, uint64_t counter) {
    Bytes rk = expandKey(key);
    if (rk.empty() || iv.size() != 16) return Bytes();
    Bytes out = in;
    Bytes ctr = iv;
    for (int b = 0; b < 8; ++b) ctr[15 - b] = (uint8_t)((counter >> (8 * b)) & 0xFF);
    for (size_t i = 0; i < out.size(); i += 16) {
        Bytes ks = encryptBlock(rk, ctr);
        size_t take = out.size() - i < 16 ? out.size() - i : 16;
        for (size_t j = 0; j < take; ++j) out[i + j] = (uint8_t)(out[i + j] ^ ks[j]);
        ctr = inc32(ctr);
    }
    return out;
}

static bool gcmSetup(const Bytes& key, const Bytes& iv, Bytes& rk, Bytes& h, Bytes& j0) {
    rk = expandKey(key);
    if (rk.empty()) return false;
    Bytes zero(16, 0);
    h = encryptBlock(rk, zero);
    if (iv.size() == 12) {
        j0 = iv;
        j0.push_back(0);
        j0.push_back(0);
        j0.push_back(0);
        j0.push_back(1);
    } else {
        GHash g;
        g.h = h;
        g.absorb(iv.data(), iv.size());
        g.padTo16();
        uint8_t l[16] = {0};
        storeU64be(l + 8, (uint64_t)iv.size() * 8);
        g.absorb(l, 16);
        j0.assign(g.y, g.y + 16);
    }
    return true;
}

static Bytes gctr(const Bytes& rk, Bytes ctr, const Bytes& in) {
    Bytes out;
    if (in.empty()) return out;
    out.reserve(in.size());
    for (size_t i = 0; i < in.size(); i += 16) {
        Bytes ks = encryptBlock(rk, ctr);
        size_t take = std::min<size_t>(16, in.size() - i);
        for (size_t j = 0; j < take; ++j) out.push_back((uint8_t)(in[i + j] ^ ks[j]));
        ctr = inc32(ctr);
    }
    return out;
}

static Bytes gcmTag(const Bytes& h, const Bytes& rk, const Bytes& j0, const Bytes& ct,
                    const Bytes& aad) {
    GHash g;
    g.h = h;
    g.absorb(aad.data(), aad.size());
    g.padTo16();
    g.absorb(ct.data(), ct.size());
    g.padTo16();
    g.lengths(aad.size(), ct.size());
    Bytes ej0 = encryptBlock(rk, j0);
    Bytes tag(16);
    for (int i = 0; i < 16; ++i) tag[i] = (uint8_t)(g.y[i] ^ ej0[i]);
    return tag;
}

GcmResult gcmEncrypt(const Bytes& key, const Bytes& iv, const Bytes& pt,
                     const Bytes& aad, size_t tagSize) {
    GcmResult res;
    Bytes rk, h, j0;
    if (!gcmSetup(key, iv, rk, h, j0)) return res;
    res.ct = gctr(rk, inc32(j0), pt);
    res.tag = gcmTag(h, rk, j0, res.ct, aad);
    if (tagSize < 4 || tagSize > 16) tagSize = 16;
    if (res.tag.size() > tagSize) res.tag.resize(tagSize);
    return res;
}

bool gcmDecrypt(const Bytes& key, const Bytes& iv, const Bytes& ct, const Bytes& tag,
                const Bytes& aad, Bytes* out) {
    Bytes rk, h, j0;
    if (!gcmSetup(key, iv, rk, h, j0)) return false;
    Bytes expect = gcmTag(h, rk, j0, ct, aad);
    size_t t = tag.size() < expect.size() ? tag.size() : expect.size();
    uint8_t diff = 0;
    for (size_t i = 0; i < t; ++i) diff = (uint8_t)(diff | (expect[i] ^ tag[i]));
    if (diff != 0 || t < 8) return false;
    if (out) *out = gctr(rk, inc32(j0), ct);
    return true;
}

}  // namespace aes
}  // namespace ck