#!/bin/sh
set -e

CXX=${CXX:-g++}
OUT=build/argus

mkdir -p build

SRCS="
src/main.cpp
src/registry.cpp
src/core/hash.cpp
src/core/aes.cpp
src/core/util.cpp
src/core/rng.cpp
src/core/net.cpp
src/core/proc.cpp
src/core/ui.cpp
src/tools/c01_crypto_basic.cpp
src/tools/c02_crypto_advanced.cpp
src/tools/c03_passwords.cpp
src/tools/c04_network.cpp
src/tools/c05_web.cpp
src/tools/c06_defense.cpp
src/tools/c07_integrity.cpp
src/tools/c08_forensics.cpp
src/tools/c09_x509.cpp
"

echo "  argus - building 25 tools with $CXX"
echo

"$CXX" -std=c++17 -O2 -Wall -Wextra -I include -I src -o "$OUT" $SRCS

echo
echo "  [OK] $OUT"
echo
"$OUT" list