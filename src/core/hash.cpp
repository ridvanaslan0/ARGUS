#include "ck/kit.h"

#include <cstring>
#include <cstdio>

namespace ck {
namespace {

inline uint32_t rotl32(uint32_t x, int n) { return (x << n) | (x >> (32 - n)); }
inline uint32_t rotr32(uint32_t x, int n) { return (x >> n) | (x << (32 - n)); }
inline uint64_t rotr64(uint64_t x, int n) { return (x >> n) | (x << (64 - n)); }
inline uint64_t rotl64(uint64_t x, int n) { return (x << n) | (x >> (64 - n)); }

inline void store32be(uint8_t* p, uint32_t v) {
    p[0] = (uint8_t)(v >> 24); p[1] = (uint8_t)(v >> 16);
    p[2] = (uint8_t)(v >> 8);  p[3] = (uint8_t)v;
}
inline void store64be(uint8_t* p, uint64_t v) {
    for (int i = 0; i < 8; ++i) p[i] = (uint8_t)(v >> (56 - 8 * i));
}
inline uint32_t load32be(const uint8_t* p) {
    return ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) | ((uint32_t)p[2] << 8) | p[3];
}
inline uint64_t load64be(const uint8_t* p) {
    uint64_t v = 0;
    for (int i = 0; i < 8; ++i) v = (v << 8) | p[i];
    return v;
}
inline uint32_t load32le(const uint8_t* p) {
    return (uint32_t)p[0] | ((uint32_t)p[1] << 8) | ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
}
inline uint64_t load64le(const uint8_t* p) {
    uint64_t v = 0;
    for (int i = 7; i >= 0; --i) v = (v << 8) | p[i];
    return v;
}
inline void store32le(uint8_t* p, uint32_t v) {
    p[0] = (uint8_t)v; p[1] = (uint8_t)(v >> 8);
    p[2] = (uint8_t)(v >> 16); p[3] = (uint8_t)(v >> 24);
}

const uint32_t K256[64] = {
    0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,
    0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,
    0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,
    0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,
    0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,
    0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070,
    0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,
    0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2};

const uint64_t K512[80] = {
    0x428a2f98d728ae22ULL,0x7137449123ef65cdULL,0xb5c0fbcfec4d3b2fULL,0xe9b5dba58189dbbcULL,
    0x3956c25bf348b538ULL,0x59f111f1b605d019ULL,0x923f82a4af194f9bULL,0xab1c5ed5da6d8118ULL,
    0xd807aa98a3030242ULL,0x12835b0145706fbeULL,0x243185be4ee4b28cULL,0x550c7dc3d5ffb4e2ULL,
    0x72be5d74f27b896fULL,0x80deb1fe3b1696b1ULL,0x9bdc06a725c71235ULL,0xc19bf174cf692694ULL,
    0xe49b69c19ef14ad2ULL,0xefbe4786384f25e3ULL,0x0fc19dc68b8cd5b5ULL,0x240ca1cc77ac9c65ULL,
    0x2de92c6f592b0275ULL,0x4a7484aa6ea6e483ULL,0x5cb0a9dcbd41fbd4ULL,0x76f988da831153b5ULL,
    0x983e5152ee66dfabULL,0xa831c66d2db43210ULL,0xb00327c898fb213fULL,0xbf597fc7beef0ee4ULL,
    0xc6e00bf33da88fc2ULL,0xd5a79147930aa725ULL,0x06ca6351e003826fULL,0x142929670a0e6e70ULL,
    0x27b70a8546d22ffcULL,0x2e1b21385c26c926ULL,0x4d2c6dfc5ac42aedULL,0x53380d139d95b3dfULL,
    0x650a73548baf63deULL,0x766a0abb3c77b2a8ULL,0x81c2c92e47edaee6ULL,0x92722c851482353bULL,
    0xa2bfe8a14cf10364ULL,0xa81a664bbc423001ULL,0xc24b8b70d0f89791ULL,0xc76c51a30654be30ULL,
    0xd192e819d6ef5218ULL,0xd69906245565a910ULL,0xf40e35855771202aULL,0x106aa07032bbd1b8ULL,
    0x19a4c116b8d2d0c8ULL,0x1e376c085141ab53ULL,0x2748774cdf8eeb99ULL,0x34b0bcb5e19b48a8ULL,
    0x391c0cb3c5c95a63ULL,0x4ed8aa4ae3418acbULL,0x5b9cca4f7763e373ULL,0x682e6ff3d6b2b8a3ULL,
    0x748f82ee5defb2fcULL,0x78a5636f43172f60ULL,0x84c87814a1f0ab72ULL,0x8cc702081a6439ecULL,
    0x90befffa23631e28ULL,0xa4506cebde82bde9ULL,0xbef9a3f7b2c67915ULL,0xc67178f2e372532bULL,
    0xca273eceea26619cULL,0xd186b8c721c0c207ULL,0xeada7dd6cde0eb1eULL,0xf57d4f7fee6ed178ULL,
    0x06f067aa72176fbaULL,0x0a637dc5a2c898a6ULL,0x113f9804bef90daeULL,0x1b710b35131c471bULL,
    0x28db77f523047d84ULL,0x32caab7b40c72493ULL,0x3c9ebe0a15c9bebcULL,0x431d67c49c100d4cULL,
    0x4cc5d4becb3e42b6ULL,0x597f299cfc657e2aULL,0x5fcb6fab3ad6faecULL,0x6c44198c4a475817ULL};

struct Md5Ctx {
    uint32_t h[4];
    uint64_t len;
    uint8_t buf[64];
    size_t bufLen;
};

struct Sha1Ctx {
    uint32_t h[5];
    uint64_t len;
    uint8_t buf[64];
    size_t bufLen;
};

struct Sha256Ctx {
    uint32_t h[8];
    uint64_t len;
    uint8_t buf[64];
    size_t bufLen;
    bool is224;
};

struct Sha512Ctx {
    uint64_t h[8];
    uint64_t lenLo, lenHi;
    uint8_t buf[128];
    size_t bufLen;
    bool is384;
};

struct KeccakCtx {
    uint64_t s[25];
    size_t rate;
    uint8_t buf[200];
    size_t bufLen;
    uint64_t len;
    bool is224, is256, is384, is512;
};

void md5Init(Md5Ctx& c) {
    c.h[0] = 0x67452301; c.h[1] = 0xefcdab89;
    c.h[2] = 0x98badcfe; c.h[3] = 0x10325476;
    c.len = 0; c.bufLen = 0;
}

void md5Block(Md5Ctx& c, const uint8_t* p) {
    static const uint32_t S[64] = {
        7,12,17,22,7,12,17,22,7,12,17,22,7,12,17,22,
        5,9,14,20,5,9,14,20,5,9,14,20,5,9,14,20,
        4,11,16,23,4,11,16,23,4,11,16,23,4,11,16,23,
        6,10,15,21,6,10,15,21,6,10,15,21,6,10,15,21};
    static const uint32_t K[64] = {
        0xd76aa478,0xe8c7b756,0x242070db,0xc1bdceee,0xf57c0faf,0x4787c62a,0xa8304613,0xfd469501,
        0x698098d8,0x8b44f7af,0xffff5bb1,0x895cd7be,0x6b901122,0xfd987193,0xa679438e,0x49b40821,
        0xf61e2562,0xc040b340,0x265e5a51,0xe9b6c7aa,0xd62f105d,0x02441453,0xd8a1e681,0xe7d3fbc8,
        0x21e1cde6,0xc33707d6,0xf4d50d87,0x455a14ed,0xa9e3e905,0xfcefa3f8,0x676f02d9,0x8d2a4c8a,
        0xfffa3942,0x8771f681,0x6d9d6122,0xfde5380c,0xa4beea44,0x4bdecfa9,0xf6bb4b60,0xbebfbc70,
        0x289b7ec6,0xeaa127fa,0xd4ef3085,0x04881d05,0xd9d4d039,0xe6db99e5,0x1fa27cf8,0xc4ac5665,
        0xf4292244,0x432aff97,0xab9423a7,0xfc93a039,0x655b59c3,0x8f0ccc92,0xffeff47d,0x85845dd1,
        0x6fa87e4f,0xfe2ce6e0,0xa3014314,0x4e0811a1,0xf7537e82,0xbd3af235,0x2ad7d2bb,0xeb86d391};
    uint32_t m[16];
    for (int i = 0; i < 16; ++i) m[i] = load32le(p + i * 4);
    uint32_t a = c.h[0], b = c.h[1], d = c.h[2], e = c.h[3];
    for (int i = 0; i < 64; ++i) {
        uint32_t f; int g;
        if (i < 16)      { f = (b & d) | (~b & e);        g = i; }
        else if (i < 32) { f = (e & b) | (~e & d);        g = (5 * i + 1) % 16; }
        else if (i < 48) { f = b ^ d ^ e;                 g = (3 * i + 5) % 16; }
        else             { f = d ^ (b | ~e);              g = (7 * i) % 16; }
        uint32_t tmp = d;
        d = e;
        e = b;
        b = b + rotl32(a + f + K[i] + m[g], (int)S[i]);
        a = tmp;
    }
    c.h[0] += a; c.h[1] += b; c.h[2] += d; c.h[3] += e;
}

void sha1Block(Sha1Ctx& c, const uint8_t* p) {
    uint32_t w[80];
    for (int i = 0; i < 16; ++i) w[i] = load32be(p + i * 4);
    for (int i = 16; i < 80; ++i) w[i] = rotl32(w[i-3] ^ w[i-8] ^ w[i-14] ^ w[i-16], 1);
    uint32_t a = c.h[0], b = c.h[1], d = c.h[2], e = c.h[3], f = c.h[4];
    for (int i = 0; i < 80; ++i) {
        uint32_t k, t;
        if (i < 20)      { t = (b & d) | (~b & e);        k = 0x5a827999; }
        else if (i < 40) { t = b ^ d ^ e;                 k = 0x6ed9eba1; }
        else if (i < 60) { t = (b & d) | (b & e) | (d & e); k = 0x8f1bbcdc; }
        else             { t = b ^ d ^ e;                 k = 0xca62c1d6; }
        uint32_t tmp = rotl32(a, 5) + t + f + k + w[i];
        f = e; e = d; d = rotl32(b, 30); b = a; a = tmp;
    }
    c.h[0] += a; c.h[1] += b; c.h[2] += d; c.h[3] += e; c.h[4] += f;
}

void sha256Block(Sha256Ctx& c, const uint8_t* p) {
    uint32_t w[64];
    for (int i = 0; i < 16; ++i) w[i] = load32be(p + i * 4);
    for (int i = 16; i < 64; ++i) {
        uint32_t s0 = rotr32(w[i-15],7) ^ rotr32(w[i-15],18) ^ (w[i-15] >> 3);
        uint32_t s1 = rotr32(w[i-2],17) ^ rotr32(w[i-2],19) ^ (w[i-2] >> 10);
        w[i] = w[i-16] + s0 + w[i-7] + s1;
    }
    uint32_t a=c.h[0],b=c.h[1],d=c.h[2],e=c.h[3],f=c.h[4],g=c.h[5],hh=c.h[6],i2=c.h[7];
    for (int i = 0; i < 64; ++i) {
        uint32_t S1 = rotr32(f,6) ^ rotr32(f,11) ^ rotr32(f,25);
        uint32_t ch = (f & g) ^ (~f & hh);
        uint32_t t1 = i2 + S1 + ch + K256[i] + w[i];
        uint32_t S0 = rotr32(a,2) ^ rotr32(a,13) ^ rotr32(a,22);
        uint32_t mj = (a & b) ^ (a & d) ^ (b & d);
        uint32_t t2 = S0 + mj;
        i2=hh; hh=g; g=f; f=e+t1; e=d; d=b; b=a; a=t1+t2;
    }
    c.h[0]+=a; c.h[1]+=b; c.h[2]+=d; c.h[3]+=e; c.h[4]+=f; c.h[5]+=g; c.h[6]+=hh; c.h[7]+=i2;
}

void sha512Block(Sha512Ctx& c, const uint8_t* p) {
    uint64_t w[80];
    for (int i = 0; i < 16; ++i) w[i] = load64be(p + i * 8);
    for (int i = 16; i < 80; ++i) {
        uint64_t s0 = rotr64(w[i-15],1) ^ rotr64(w[i-15],8) ^ (w[i-15] >> 7);
        uint64_t s1 = rotr64(w[i-2],19) ^ rotr64(w[i-2],61) ^ (w[i-2] >> 6);
        w[i] = w[i-16] + s0 + w[i-7] + s1;
    }
    uint64_t a=c.h[0],b=c.h[1],d=c.h[2],e=c.h[3],f=c.h[4],g=c.h[5],h=c.h[6],i2=c.h[7];
    for (int i = 0; i < 80; ++i) {
        uint64_t S1 = rotr64(f,14) ^ rotr64(f,18) ^ rotr64(f,41);
        uint64_t ch = (f & g) ^ (~f & h);
        uint64_t t1 = i2 + S1 + ch + K512[i] + w[i];
        uint64_t S0 = rotr64(a,28) ^ rotr64(a,34) ^ rotr64(a,39);
        uint64_t mj = (a & b) ^ (a & d) ^ (b & d);
        uint64_t t2 = S0 + mj;
        i2=h; h=g; g=f; f=e+t1; e=d; d=b; b=a; a=t1+t2;
    }
    c.h[0]+=a; c.h[1]+=b; c.h[2]+=d; c.h[3]+=e; c.h[4]+=f; c.h[5]+=g; c.h[6]+=h; c.h[7]+=i2;
}

void keccakF(uint64_t s[25]) {
    static const uint64_t RC[24] = {
        0x0000000000000001ULL, 0x0000000000008082ULL, 0x800000000000808aULL, 0x8000000080008000ULL,
        0x000000000000808bULL, 0x0000000080000001ULL, 0x8000000080008081ULL, 0x8000000000008009ULL,
        0x000000000000008aULL, 0x0000000000000088ULL, 0x0000000080008009ULL, 0x000000008000000aULL,
        0x000000008000808bULL, 0x800000000000008bULL, 0x8000000000008089ULL, 0x8000000000008003ULL,
        0x8000000000008002ULL, 0x8000000000000080ULL, 0x000000000000800aULL, 0x800000008000000aULL,
        0x8000000080008081ULL, 0x8000000000008080ULL, 0x0000000080000001ULL, 0x8000000080008008ULL};
    static const int RHO[24] = {1,3,6,10,15,21,28,36,45,55,2,14,
        27,41,56,8,25,43,62,18,39,61,20,44};
    static const int PI[24] = {10,7,11,17,18,3,5,16,8,21,24,4,
        15,23,19,13,12,2,20,14,22,9,6,1};
    for (int round = 0; round < 24; ++round) {
        uint64_t bc[5];
        for (int i = 0; i < 5; ++i)
            bc[i] = s[i] ^ s[i+5] ^ s[i+10] ^ s[i+15] ^ s[i+20];
        for (int i = 0; i < 5; ++i) {
            uint64_t t = bc[(i+4)%5] ^ rotl64(bc[(i+1)%5], 1);
            for (int j = 0; j < 25; j += 5) s[j+i] ^= t;
        }
        uint64_t tmp = s[1];
        for (int i = 0; i < 24; ++i) {
            int j = PI[i];
            uint64_t t2 = s[j];
            s[j] = rotl64(tmp, RHO[i]);
            tmp = t2;
        }
        for (int j = 0; j < 25; j += 5) {
            uint64_t tt[5];
            for (int i = 0; i < 5; ++i) tt[i] = s[j+i];
            for (int i = 0; i < 5; ++i)
                s[j+i] = tt[i] ^ (~tt[(i+1)%5] & tt[(i+2)%5]);
        }
        s[0] ^= RC[round];
    }
}

void keccakInit(KeccakCtx& c, int digestBits) {
    memset(c.s, 0, sizeof(c.s));
    c.len = 0; c.bufLen = 0;
    c.is224 = c.is256 = c.is384 = c.is512 = false;
    if (digestBits == 224) { c.is224 = true; c.rate = 144; }
    else if (digestBits == 256) { c.is256 = true; c.rate = 136; }
    else if (digestBits == 384) { c.is384 = true; c.rate = 104; }
    else { c.is512 = true; c.rate = 72; }
}

void keccakAbsorb(KeccakCtx& c, const uint8_t* p, size_t n) {
    while (n > 0) {
        size_t take = c.rate - c.bufLen;
        if (take > n) take = n;
        memcpy(c.buf + c.bufLen, p, take);
        c.bufLen += take; p += take; n -= take; c.len += take;
        if (c.bufLen == c.rate) {
            for (size_t i = 0; i < c.rate / 8; ++i)
                c.s[i] ^= load64le(c.buf + i * 8);
            keccakF(c.s);
            c.bufLen = 0;
        }
    }
}

void keccakFinal(KeccakCtx& c, Bytes& out) {
    size_t digestBytes = c.is224 ? 28 : c.is256 ? 32 : c.is384 ? 48 : 64;
    uint8_t pad[200] = {0};
    pad[0] = 0x06;
    memset(c.buf + c.bufLen, 0, c.rate - c.bufLen);
    c.buf[c.bufLen] ^= pad[0];
    c.buf[c.rate - 1] ^= 0x80;
    for (size_t i = 0; i < c.rate / 8; ++i)
        c.s[i] ^= load64le(c.buf + i * 8);
    keccakF(c.s);
    out.assign(digestBytes, 0);
    for (size_t i = 0; i < digestBytes; ++i)
        out[i] = (uint8_t)((c.s[i / 8] >> (8 * (i % 8))) & 0xFF);
}

}  // namespace

// ---------------------------------------------------------------- registry
const std::vector<HashSpec>& allHashes() {
    static const std::vector<HashSpec> specs = {
        {"md5", 16, 64, false, true},
        {"sha1", 20, 64, false, true},
        {"sha224", 28, 64, false, false},
        {"sha256", 32, 64, false, false},
        {"sha384", 48, 128, false, false},
        {"sha512", 64, 128, false, false},
        {"sha3-224", 28, 144, true, false},
        {"sha3-256", 32, 136, true, false},
        {"sha3-384", 48, 104, true, false},
        {"sha3-512", 64, 72, true, false},
    };
    return specs;
}

const HashSpec* findHash(const std::string& name) {
    std::string n = toLower(trim(name));
    for (auto& c : n) if (c == '_') c = '-';
    if (n.rfind("sha2-", 0) == 0) n = "sha" + n.substr(5);
    if (n == "sha2") n = "sha256";
    for (auto& s : allHashes())
        if (s.name == n) return &s;
    return nullptr;
}

bool isKnownHashName(const std::string& name) { return findHash(name) != nullptr; }

// ------------------------------------------------------------------ hash
Digest hashBytes(const std::string& alg, const uint8_t* data, size_t len) {
    const HashSpec* spec = findHash(alg);
    if (!spec) return Digest{};
    const std::string& a = spec->name;
    Digest out;

    if (a == "md5") {
        Md5Ctx c; md5Init(c);
        size_t i = 0;
        while (i < len) {
            size_t take = 64 - c.bufLen;
            if (take > len - i) take = len - i;
            memcpy(c.buf + c.bufLen, data + i, take);
            c.bufLen += take; i += take;
            if (c.bufLen == 64) { md5Block(c, c.buf); c.bufLen = 0; }
        }
        uint64_t bits = (uint64_t)len * 8;
        uint8_t pad = 0x80;
        c.buf[c.bufLen++] = pad;
        if (c.bufLen > 56) { memset(c.buf + c.bufLen, 0, 64 - c.bufLen); md5Block(c, c.buf); c.bufLen = 0; }
        memset(c.buf + c.bufLen, 0, 56 - c.bufLen);
        store32le(c.buf + 56, (uint32_t)bits);
        md5Block(c, c.buf);
        out.bytes.resize(16);
        for (int i2 = 0; i2 < 4; ++i2) store32le(out.bytes.data() + i2 * 4, c.h[i2]);
        return out;
    }

    if (a == "sha1") {
        Sha1Ctx c; c.h[0]=0x67452301;c.h[1]=0xefcdab89;c.h[2]=0x98badcfe;c.h[3]=0x10325476;c.h[4]=0xc3d2e1f0;
        c.len = 0; c.bufLen = 0;
        size_t i = 0;
        while (i < len) {
            size_t take = 64 - c.bufLen;
            if (take > len - i) take = len - i;
            memcpy(c.buf + c.bufLen, data + i, take);
            c.bufLen += take; i += take;
            if (c.bufLen == 64) { sha1Block(c, c.buf); c.bufLen = 0; }
        }
        uint64_t bits = (uint64_t)len * 8;
        c.buf[c.bufLen++] = 0x80;
        if (c.bufLen > 56) { memset(c.buf + c.bufLen, 0, 64 - c.bufLen); sha1Block(c, c.buf); c.bufLen = 0; }
        memset(c.buf + c.bufLen, 0, 56 - c.bufLen);
        for (int k = 0; k < 8; ++k) c.buf[56 + k] = (uint8_t)(bits >> (56 - 8 * k));
        sha1Block(c, c.buf);
        out.bytes.resize(20);
        for (int i2 = 0; i2 < 5; ++i2) store32be(out.bytes.data() + i2 * 4, c.h[i2]);
        return out;
    }

    if (a == "sha224" || a == "sha256") {
        Sha256Ctx c;
        if (a == "sha224") {
            c.is224 = true;
            static const uint32_t iv[8] = {0xc1059ed8,0x367cd507,0x3070dd17,0xf70e5939,
                                           0xffc00b31,0x68581511,0x64f98fa7,0xbefa4fa4};
            memcpy(c.h, iv, sizeof(iv));
        } else {
            c.is224 = false;
            static const uint32_t iv[8] = {0x6a09e667,0xbb67ae85,0x3c6ef372,0xa54ff53a,
                                           0x510e527f,0x9b05688c,0x1f83d9ab,0x5be0cd19};
            memcpy(c.h, iv, sizeof(iv));
        }
        c.len = 0; c.bufLen = 0;
        size_t i = 0;
        while (i < len) {
            size_t take = 64 - c.bufLen;
            if (take > len - i) take = len - i;
            memcpy(c.buf + c.bufLen, data + i, take);
            c.bufLen += take; i += take;
            if (c.bufLen == 64) { sha256Block(c, c.buf); c.bufLen = 0; }
        }
        uint64_t bits = (uint64_t)len * 8;
        c.buf[c.bufLen++] = 0x80;
        if (c.bufLen > 56) { memset(c.buf + c.bufLen, 0, 64 - c.bufLen); sha256Block(c, c.buf); c.bufLen = 0; }
        memset(c.buf + c.bufLen, 0, 56 - c.bufLen);
        for (int k = 0; k < 8; ++k) c.buf[56 + k] = (uint8_t)(bits >> (56 - 8 * k));
        sha256Block(c, c.buf);
        int words = c.is224 ? 7 : 8;
        out.bytes.resize(words * 4);
        for (int i2 = 0; i2 < words; ++i2) store32be(out.bytes.data() + i2 * 4, c.h[i2]);
        return out;
    }

    if (a == "sha384" || a == "sha512") {
        Sha512Ctx c;
        if (a == "sha384") {
            c.is384 = true;
            static const uint64_t iv[8] = {0xcbbb9d5dc1059ed8ULL,0x629a292a367cd507ULL,
                0x9159015a3070dd17ULL,0x152fecd8f70e5939ULL,0x67332667ffc00b31ULL,
                0x8eb44a8768581511ULL,0xdb0c2e0d64f98fa7ULL,0x47b5481dbefa4fa4ULL};
            memcpy(c.h, iv, sizeof(iv));
        } else {
            c.is384 = false;
            static const uint64_t iv[8] = {0x6a09e667f3bcc908ULL,0xbb67ae8584caa73bULL,
                0x3c6ef372fe94f82bULL,0xa54ff53a5f1d36f1ULL,0x510e527fade682d1ULL,
                0x9b05688c2b3e6c1fULL,0x1f83d9abfb41bd6bULL,0x5be0cd19137e2179ULL};
            memcpy(c.h, iv, sizeof(iv));
        }
        c.lenLo = c.lenHi = 0; c.bufLen = 0;
        size_t i = 0;
        while (i < len) {
            size_t take = 128 - c.bufLen;
            if (take > len - i) take = len - i;
            memcpy(c.buf + c.bufLen, data + i, take);
            c.bufLen += take; i += take;
            if (c.bufLen == 128) { sha512Block(c, c.buf); c.bufLen = 0; }
        }
        uint64_t bitsLo = (uint64_t)len * 8;
        uint64_t bitsHi = (uint64_t)len >> 61;
        c.buf[c.bufLen++] = 0x80;
        if (c.bufLen > 112) { memset(c.buf + c.bufLen, 0, 128 - c.bufLen); sha512Block(c, c.buf); c.bufLen = 0; }
        memset(c.buf + c.bufLen, 0, 112 - c.bufLen);
        for (int k = 0; k < 8; ++k) c.buf[112 + k] = (uint8_t)(bitsHi >> (56 - 8 * k));
        for (int k = 0; k < 8; ++k) c.buf[120 + k] = (uint8_t)(bitsLo >> (56 - 8 * k));
        sha512Block(c, c.buf);
        int words = c.is384 ? 6 : 8;
        out.bytes.resize(words * 8);
        for (int i2 = 0; i2 < words; ++i2) store64be(out.bytes.data() + i2 * 8, c.h[i2]);
        return out;
    }

    if (a.rfind("sha3-", 0) == 0) {
        KeccakCtx c;
        int bits = std::stoi(a.substr(5));
        keccakInit(c, bits);
        keccakAbsorb(c, data, len);
        keccakFinal(c, out.bytes);
        return out;
    }

    return out;
}

Digest hashBytes(const std::string& alg, const std::string& data) {
    return hashBytes(alg, (const uint8_t*)data.data(), data.size());
}

Digest hashFile(const std::string& alg, const std::string& path, std::string* err) {
    Bytes b;
    if (!readFile(path, b, err)) return Digest{};
    return hashBytes(alg, b.data(), b.size());
}

// ------------------------------------------------------------------ hmac
Digest hmacBytes(const std::string& alg, const Bytes& key, const uint8_t* msg, size_t len) {
    const HashSpec* spec = findHash(alg);
    Digest out;
    if (!spec) return out;
    size_t block = (size_t)spec->blockSize;
    Bytes k = key;
    if (k.size() > block) k = hashBytes(alg, k.data(), k.size()).bytes;
    k.resize(block, 0);

    Bytes ipad(block), opad(block);
    for (size_t i = 0; i < block; ++i) { ipad[i] = (uint8_t)(k[i] ^ 0x36); opad[i] = (uint8_t)(k[i] ^ 0x5c); }

    Bytes inner(ipad);
    inner.insert(inner.end(), msg, msg + len);
    Digest ih = hashBytes(alg, inner.data(), inner.size());

    Bytes outer(opad);
    outer.insert(outer.end(), ih.bytes.begin(), ih.bytes.end());
    return hashBytes(alg, outer.data(), outer.size());
}

Digest hmacBytes(const std::string& alg, const Bytes& key, const std::string& msg) {
    return hmacBytes(alg, key, (const uint8_t*)msg.data(), msg.size());
}

std::string hmacHex(const std::string& alg, const std::string& key, const std::string& msg) {
    return hmacBytes(alg, textToBytes(key), msg).hex();
}

// ---------------------------------------------------------------- pbkdf2
Bytes pbkdf2(const std::string& password, const Bytes& salt, int iterations, size_t dkLen,
             const std::string& prf) {
    Bytes out;
    if (iterations < 1) iterations = 1;
    const HashSpec* spec = findHash(prf);
    if (!spec) return out;
    size_t hLen = (size_t)spec->digestSize;
    uint32_t blocks = (uint32_t)((dkLen + hLen - 1) / hLen);
    Bytes pwd = textToBytes(password);

    for (uint32_t bi = 1; bi <= blocks; ++bi) {
        Bytes msg = salt;
        uint8_t idx[4] = {(uint8_t)(bi >> 24), (uint8_t)(bi >> 16),
                          (uint8_t)(bi >> 8), (uint8_t)bi};
        msg.insert(msg.end(), idx, idx + 4);
        Digest u = hmacBytes(prf, pwd, msg.data(), msg.size());
        Bytes t = u.bytes;
        for (int it = 1; it < iterations; ++it) {
            u = hmacBytes(prf, pwd, u.bytes.data(), u.bytes.size());
            for (size_t i = 0; i < t.size(); ++i) t[i] = (uint8_t)(t[i] ^ u.bytes[i]);
        }
        out.insert(out.end(), t.begin(), t.end());
    }
    out.resize(dkLen);
    return out;
}

}  // namespace ck