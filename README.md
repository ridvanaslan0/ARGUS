# argus

**Twenty-five tools. One binary. No dependencies.**

A console for people who need to see everything: cryptographic self-verification,
attack-surface enumeration, and defence auditing. Made by **Rio**.

```
     ##    ###     ###    #  #    ###  
    #  #   #  #   #       #  #   #     
    ####   ###    #       #  #    ###  
    #  #   # #    #  ##   #  #       #  
    #  #   #  #    ###     ##     ###
```

## Build

```bat
build.bat                 REM Windows / MSVC  (requires Visual Studio Build Tools)
```

```sh
./build.sh                REM Linux / macOS  (g++ or clang++)
```

Output: `build/argus` (`build\argus.exe` on Windows). Clean build, no
warnings.

### Launchers

Double-click the launcher for your platform. Each one resolves its own project
root, so the folder can live anywhere on disk. Pass arguments to run a tool
directly instead of opening the menu.

```
run/windows/argus.cmd        double-click, or: run\windows\run.cmd list
run/linux/argus.sh          ./run/linux/argus.sh aes --selftest
run/macos/argus.command     Finder double-click, or: ./run/macos/argus.command list
```

They switch the console to UTF-8, load a TrueType font when they can, and pause
before closing so a double-clicked window stays readable.

## Usage

```
argus                     help
argus list                all tools, grouped by category
argus list crypto         filtered list
argus help <tool>         usage for a single tool
argus run                 interactive picker
argus bye                 sign off / credits
argus <tool> [arguments]
argus --no-color <tool>   disable ANSI colour
```

Every tool speaks the same output language: coloured section headers,
key/value summaries, a findings table, and a **risk score out of 100** rendered
as a severity bar.

Exit codes are meaningful and stable, so the tools drop straight into CI:

| Code | Meaning |
|---|---|
| `0` | clean, no HIGH/CRITICAL findings |
| `1` | at least one HIGH or CRITICAL finding |
| `2` | active scan refused for lack of authorization |

## Tools

### Cryptography (10)

| Tool | What it does |
|---|---|
| `hash` | MD5/SHA-1/SHA-2/SHA-3 digests of a file or a string |
| `hash-id` | Identifies which algorithm produced a hash and flags collision risk |
| `hmac` | HMAC over any supported digest, with key-strength guidance |
| `codec` | base64 / base64url / base32 / base58 / hex / urlencode |
| `entropy` | Shannon entropy, chi-square and LZ77 compressibility to tell packed/encrypted from plain |
| `aes` | AES-128/192/256 ECB-CBC-CTR-**GCM**; **self-validates against FIPS-197 and NIST GCM vectors** |
| `cipher` | Caesar/ROT-N, Atbash, Vigenère, XOR, rail-fence + English frequency cracking |
| `jwt` | JWT decode and audit: `alg=none`, exp/nbf/iat, aud/iss, embedded JWK, jku/x5u SSRF |
| `rsa-audit` | Modulus size, weak exponent, small prime factors, perfect square, p×q consistency |
| `rng-test` | **NIST SP 800-22** battery: monobit, block frequency, runs, longest-run, cusum, apEnt, serial, pairwise — 12 tests |

### Passwords & secrets (3)

| Tool | What it does |
|---|---|
| `pw-audit` | Entropy-based audit: dictionary, sequences, repeats, leetspeak, **password reuse** |
| `pw-gen` | Password and passphrase generation from the OS CSPRNG, with policy flags |
| `credscan` | Tree scan for AWS/GitHub/Slack/Stripe keys, private keys, DB connection strings |

### Network (5)

| Tool | What it does |
|---|---|
| `cidr` | Subnet math: network/broadcast/hosts, masks, split plans, address enumeration |
| `portscan` | Rate-limited TCP connect scanner with banner capture |
| `hostdisc` | Concurrent TCP host discovery with PTR lookups |
| `tls-audit` | Live TLS version/cipher handshake probing **or** nginx/apache config file analysis |
| `http-audit` | Security headers, cookie flags, CORS policy |

> Active scanners (`portscan`, `hostdisc`, `tls-audit`, `http-audit`) **refuse to
> run by default**. The target must be loopback/RFC1918, or you must pass
> `--i-own-this`, or list it in `~/.argus/allow.txt`. All of them are
> non-destructive: no SYN flood, no exploitation, no data modification.

### Defense (4)

| Tool | What it does |
|---|---|
| `win-audit` | Windows posture: SMBv1, guest access, Defender, UAC, firewall profiles, RDP+NLA, BitLocker, SMB signing, lockout, audit policy |
| `log-hunt` | Brute-force and password-spraying detection in auth logs, plus account creation and privilege escalation events |
| `acl-audit` | File permissions: Everyone/Authenticated Users grants, world-writable, setuid, writes into system directories |
| `integrity` | SHA-256 baseline manifest creation and verification (tamper/deletion detection) |

### Forensics (3)

| Tool | What it does |
|---|---|
| `pcap` | pcap/pcapng reading: protocol mix, talkers, port histograms, **SYN sweep detection** |
| `sigmatch` | YARA-like signature engine: magic bytes, LOLBins, webshells, miners, injection, ransom notes |
| `x509` | PEM/DER certificate parsing plus policy audit (validity, SAN, KU, CA/pathlen, key size) |

## Tool reference

Every tool below has been exercised end to end. `argus help <tool>` prints the
same synopsis plus the live category.

### Cryptography

#### `hash` — digests of strings or files
```
argus hash --alg sha256,sha3-256 [--file <path> | <string> | --stdin]
```
Algorithms: `md5 sha1 sha224 sha256 sha384 sha512 sha3-224 sha3-256 sha3-384 sha3-512`.
Multiple algorithms produce a labelled table in one pass. Input is taken from
`--file`, the first positional argument, or `--stdin`, in that order.

#### `hash-id` — identify an unknown hash
```
argus hash-id <hash>  |  argus hash-id --file hashes.txt
```
Matches length, form (hex/base64/decimal) and entropy against every supported
algorithm, then flags collision risk for MD5, SHA-1 and truncated variants.

#### `hmac` — keyed digest with key-strength guidance
```
argus hmac --key <secret> [--msg <text> | --file <path>] [--alg sha256,sha512]
```
Emits the MAC plus a risk score driven by the actual key length in bytes.

#### `codec` — encoding round-trip
```
argus codec --enc base64 <text>   argus codec --dec base64 <b64>
```
Encodings: `base64 base64url base32 base58 hex urlencode`. Decoding reports the
recovered byte count and a charset breakdown, which is how encoded payloads are
often spotted.

#### `entropy` — randomness forensics
```
argus entropy [--file <path> | <string> | --stdin]
```
Shannon entropy per byte, chi-square, and an LZ77 compressibility estimate.
Used to tell packed/encrypted content from plain text, and to flag low-entropy
keys.

#### `aes` — block cipher with known-answer self-test
```
argus aes --selftest
argus aes --mode gcm --bits 256 --key-hex <64 hex> --iv-hex <24 hex> --in <text>
argus aes --mode gcm --key-hex <64 hex> --iv-hex <24 hex> --cipher-hex <ct> --tag-hex <tag>
```
Modes: `ecb cbc ctr gcm`. `--selftest` runs the FIPS-197 vectors for all three
key sizes, the NIST GCM test cases, a round trip, and **tag rejection on a
tampered ciphertext**. Key material must be exactly 16, 24 or 32 bytes — an
invalid size is a hard error, never a silent empty result. Use `--key` for raw
bytes and `--key-hex` for hex.

#### `cipher` — classical cipher lab
```
argus cipher --algo caesar --shift 13 "text"
argus cipher --algo caesar --crack "Uryyb"
argus cipher --algo vigenere --key secret "AttackAtDawn"
```
Algorithms: `caesar rot rot13 atbash vigenere xor railfence`. `--crack` scores all
26 ROT shifts by English frequency and ranks them.

#### `jwt` — token audit
```
argus jwt --token <jwt>  |  argus jwt --token <jwt> --secret <hmac-key>
```
Checks `alg=none` and algorithm confusion, `exp`/`nbf`, `aud`/`iss`, embedded JWK,
and the `jku`/`x5u`/`kid` SSRF and path-traversal angles.

#### `rsa-audit` — RSA key health
```
argus rsa-audit --file server.pem
argus rsa-audit --n <hex|dec|b64> [--e 65537] [--d ...] [--p ...] [--q ...]
```
Reads PKCS#1, PKCS#8 and SubjectPublicKeyInfo **without any external
dependency**. Reports modulus size, even moduli, small prime divisors, perfect
squares, p×q consistency, Wiener's/Fermat closeness, shared factors between
n/e/d, and degenerate exponents. A healthy 2048-bit key exits `0`.

#### `rng-test` — NIST SP 800-22 over the OS CSPRNG
```
argus rng-test [--bits 1048576] [--source <file>]
```
Twelve tests: monobit, block frequency, runs, longest run of ones, cumulative
sums (cusum), approximate entropy, serial, binary matrix rank, discrete Fourier,
linear complexity, Maurer, and non-overlapping templates. Reports p-values
against alpha 0.01.

### Passwords and secrets

#### `pw-audit` — password strength
```
argus pw-audit --password "Passw0rd!,Summer2024"
argus pw-audit --file creds.txt [--top 10]
```
Entropy-based scoring with dictionary hits, keyboard walks, sequences, repeats,
leet substitution, year patterns and cross-file reuse detection. Lists the
weakest entries first with a strength bar and a crack-time estimate.

#### `pw-gen` — CSPRNG generation
```
argus pw-gen [--count 5] [--length 24] [--symbols] [--passphrase]
argus pw-gen --passphrase [--count 3] [--separator -]
```
Character-class switches: `--no-caps --no-digits --no-lower --no-symbols`.
Passphrase mode reports the real word count, character count, word-list size and
entropy. Values are printed once and never stored.

#### `credscan` — hardcoded secret discovery
```
argus credscan [--path ./src;./config] [--no-recursive] [--max-size N]
```
Looks for AWS keys, GitHub tokens, Slack webhooks, Stripe live keys, private key
headers, database connection strings and passwords assigned to variables. Values
are masked in the report.

### Network

#### `cidr` — subnet arithmetic
```
argus cidr 10.0.0.0/24 --split 26 --enum --limit 32
```
Network, broadcast, first/last host, mask, wildcard, address class, RFC1918 scope,
a VLSM split plan and address enumeration.

#### `portscan` — TCP connect scanner
```
argus portscan <host|cidr-host> --ports 22,80,443 [--banner] [--timeout 1200]
```
Rate-limited, non-destructive, TCP connect only — no SYN flood. Captures banners
when asked and flags interesting services by port number.

#### `hostdisc` — host discovery
```
argus hostdisc 192.168.1.0/24 [--ports 80,443,22] [--threads 64] [--timeout 700]
```
Concurrent probes with PTR lookups and private/public scope labelling.

#### `tls-audit` — TLS configuration
```
argus tls-audit --host lab.internal [--port 443] [--i-own-this]
argus tls-audit --file /etc/nginx/nginx.conf
```
Live mode probes TLS 1.0/1.1/1.2/1.3 negotiation and cipher selection. File mode
parses nginx/apache directives and flags obsolete protocols, RC4/3DES/CBC-only
cipher lists, missing HSTS, `max-age=0`, missing DH params and stapling problems.
Exits `1` on any HIGH or CRITICAL configuration finding.

#### `http-audit` — headers, cookies, CORS
```
argus http-audit --url https://example.com [--i-own-this]
argus http-audit --host example.com --scheme http --port 8080 --i-own-this
argus http-audit --file headers.txt
```
Validates HSTS, CSP, X-Frame-Options, Referrer-Policy, X-Content-Type-Options,
cookie `Secure`/`HttpOnly`/`SameSite`, server version disclosure and CORS
wildcards.

> Active scanners (`portscan`, `hostdisc`, `tls-audit`, `http-audit`) **refuse to
> run by default**. The target must be loopback/RFC1918, or you must pass
> `--i-own-this`, or list it in `~/.argus/allow.txt`. All of them are
> non-destructive: no SYN flood, no exploitation, no data modification.

### Defense

#### `win-audit` — Windows posture
```
argus win-audit
```
SMBv1 driver state, guest and passwordless accounts, Defender status and
signature age, UAC `EnableLUA`, firewall profiles per network type, RDP exposure
and NLA, BitLocker, SMB signing, account lockout policy, audit policy, Windows
Update and local administrators. Run elevated for full coverage; unreadable
checks are reported as unknown rather than guessed.

#### `log-hunt` — authentication log analysis
```
argus log-hunt --file /var/log/auth.log [--threshold 5] [--since 24h]
```
Detects brute force and password spraying (distinct failure counts by source
and by user), successful logins from unusual sources, and notable account events
such as group additions and privilege changes. Accepts syslog/auth.log text and
exported Windows XML.

#### `acl-audit` — file and directory permissions
```
argus acl-audit ./config [--no-recursive] [--max 400]
```
Flags Everyone and Authenticated Users grants, world-writable files and
directories, setuid/setgid bits, and write access inside system directories.
Includes an ACE-profile distribution table.

#### `integrity` — baseline and tamper detection
```
argus integrity --mode create --path ./bin --out baseline.manifest
argus integrity --manifest baseline.manifest [--path ./bin]
```
Builds a SHA-256 manifest, then verifies it and reports `OK`, `CHANGED`,
`RESIZED` and `MISSING` per file with the actual digest, so a tampered binary is
obvious in the table.

### Forensics

#### `pcap` — capture file analysis
```
argus pcap --file capture.pcap [--detail]
```
Reads classic pcap (both endiannesses, micro and nanosecond) and pcapng.
Reports protocol distribution, top talkers, destination port histogram and
**SYN sweep detection** across a time window.

#### `sigmatch` — signature matching
```
argus sigmatch ./samples [--show-clean] [--max-size N]
```
Nineteen rules covering magic bytes (PE, ELF, Mach-O, ZIP, RAR, 7z, gzip, PDF)
and strings (PowerShell LOLBins, credential-dump tooling, persistence, ransom
note language, cryptominers, PHP webshells, SQLi, XSS, C2 tooling, debug builds).
Magic and string evidence are scored together, so a file needs more than one
weak indicator to fire.

#### `x509` — certificate parsing and policy
```
argus x509 --file cert.pem  |  argus x509 ./chain.pem
```
Parses PEM and DER, multiple certificates per file. Reports version, subject,
issuer, serial, validity window, public key algorithm and size, signature
algorithm, basic constraints, key usage, extended key usage, SAN entries and
chain consistency. Flags weak signature algorithms, undersized keys, missing
SANs and expired certificates.

## Examples

```bat
argus aes --selftest
argus hash --alg sha256,sha3-256 --file firmware.bin
argus hash-id 5d41402abc4b2a76b9719d911017c592
argus hmac --key <secret> --msg payload --alg sha512
argus codec --enc base64url "binary blob here"
argus entropy --file blob.bin
argus jwt --token eyJhbGciOiJub25lIn0... --secret <hmac-key>
argus rsa-audit --file server.pem
argus rng-test --bits 1048576
argus pw-audit --file creds.txt --top 10
argus pw-gen --count 10 --length 32 --symbols
argus pw-gen --count 3 --passphrase
argus credscan --path ./src;./config
argus cidr 10.20.0.0/22 --split 24 --enum --limit 32
argus portscan 127.0.0.1 --ports 22,80,443 --banner
argus hostdisc 192.168.1.0/24 --threads 64
argus tls-audit --host lab.internal --i-own-this
argus tls-audit --file /etc/nginx/conf.d/ssl.conf
argus http-audit --url https://example.com --i-own-this
argus http-audit --file headers.txt
argus win-audit
argus log-hunt --file /var/log/auth.log --threshold 5
argus integrity --mode create --path ./bin --out baseline.manifest
argus integrity --manifest baseline.manifest
argus acl-audit ./config
argus pcap --file capture.pcap --detail
argus sigmatch ./samples --show-clean
argus x509 ./chain.pem
```

### Quick triage by goal

| Goal | Command |
|---|---|
| Prove the crypto core is intact | `argus aes --selftest` |
| Prove the RNG is sound | `argus rng-test --bits 1048576` |
| Audit a JWT you were handed | `argus jwt --token <jwt>` |
| Audit an RSA key | `argus rsa-audit --file key.pem` |
| Rate a password list | `argus pw-audit --file creds.txt` |
| Find leaked secrets in a repo | `argus credscan --path .` |
| Review a TLS server config | `argus tls-audit --file ssl.conf` |
| Review response headers | `argus http-audit --file headers.txt` |
| Check a host for open ports | `argus portscan <host> --ports top --i-own-this` |
| Triage an incident capture | `argus pcap --file capture.pcap` |
| Scan a directory for malware | `argus sigmatch ./samples` |
| Detect file tampering | `argus integrity --mode create --path . --out b.manifest` |

## Design notes

- **CSPRNG is non-negotiable.** Key generation tries `BCryptGenRandom` →
  `SystemFunction036` → `getrandom`. If the OS CSPRNG cannot be verified the tool
  says so out loud; it never silently degrades to a deterministic `rand()`.
- **Verified cryptography.** `aes --selftest` runs the FIPS-197 and NIST GCM
  known-answer vectors, including tag rejection on a tampered ciphertext.
  `rng-test` applies NIST SP 800-22 to the operating system CSPRNG. The library
  code cannot drift away from its own tests.
- **One finding model.** Every audit produces `Finding{id, text, severity}` in
  the same shape; LOW/MED/HIGH/CRIT counts collapse into a 0-100 risk score.
  That makes output diffable across runs and the exit code meaningful in CI.
- **Terminal-native design.** A single 256-colour palette, box drawing, progress
  bars and a spinner, with width-aware alignment (ANSI escapes are measured,
  not guessed) and a `--no-color` plain-text mode.
- **Console encoding is handled, not assumed.** On startup the program switches
  the console to UTF-8 and tries to load a TrueType font (Cascadia Mono,
  Consolas, Lucida Console). If the console cannot render Unicode, every glyph
  is transliterated to ASCII — box drawing becomes `- | +`, `✓` becomes `+`,
  `█░` become `# .`, and en/em dashes and quotes become ASCII. Output is legible
  everywhere; it is only plainer in the fallback. All output funnels through a
  single `ui::emit()` chokepoint so nothing can bypass it.
- **No silent failures.** An invalid AES key size, an unparseable RSA key, an
  unreachable binary or a truncated pcap all produce a clear diagnostic and a
  non-zero exit code. A security tool that quietly prints an empty result is
  worse than one that refuses to run.
- **Tables are width-aware.** ANSI escapes are measured by their visible width,
  not their byte count, so colour never breaks column alignment, and long cells
  are truncated on a character boundary rather than mid-escape.

## Verification

The build is warning-free and the cryptography is self-checking:

```
argus aes --selftest     FIPS-197 + NIST GCM known-answer vectors
argus rng-test           NIST SP 800-22, 12 tests over the OS CSPRNG
```

`rsa-audit` and `x509` read keys and certificates with the project's own DER
parser rather than shelling out to OpenSSL, so they work on a machine with no
external tooling installed. `http-audit` and live `tls-audit` do use `curl` and
`openssl` when available and say so plainly when they are not.

## Layout

```
include/ck/kit.h        core API: hash, aes, net, rng, ui
include/ck/tool.h       tool registry + argument parser
src/core/hash.cpp       MD5, SHA-1, SHA-2, SHA-3, HMAC, PBKDF2
src/core/aes.cpp        AES-128/192/256, ECB/CBC/CTR/GCM, GHASH
src/core/rng.cpp        OS CSPRNG chain
src/core/net.cpp        sockets, IP/CIDR, connect, resolver
src/core/proc.cpp       subprocess execution
src/core/ui.cpp         theme, table, box, bar, spinner, transliteration
src/tools/c0*.cpp       25 tools grouped by category
src/main.cpp            banner, command dispatch, interactive menu
run/                    per-OS launchers (windows / linux / macos)
```

## Limits

- C++17, no third-party libraries. OpenSSL and curl are used **optionally** by
  `tls-audit --host` and `http-audit --url`; without them the tools say so and
  fall back to file/header analysis. Key parsing and cryptography never depend on
  them.
- The RSA audit does not perform cryptanalysis. It checks structural weaknesses:
  modulus size, exponent sanity, small prime divisors, perfect squares, p×q
  consistency.
- `log-hunt` does not parse binary `.evtx` directly. Export first:
  `wevtutil epl Security C:\Temp\Security.xml`, then point `--file` at the XML.
- `win-audit` needs elevation for full coverage; checks it cannot read are
  reported as unknown rather than guessed.
- `sigmatch` is a heuristic indicator engine, not a verdict. Treat hits as
  leads and confirm against a known-good baseline.
