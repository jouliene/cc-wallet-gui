#!/usr/bin/env bash
set -euo pipefail

PKG="cc-wallet-ui-slint"
BIN_NAME="cc-wallet-gui"
BASE_TRIPLE="x86_64-unknown-linux-gnu"
GLIBC_FLOOR="${GLIBC_FLOOR:-2.35}"

cd "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)"

export RUST_FONTCONFIG_DLOPEN=1

if cargo zigbuild --help >/dev/null 2>&1; then
    target="${BASE_TRIPLE}.${GLIBC_FLOOR}"
    echo "==> building $BIN_NAME for $target (glibc floor $GLIBC_FLOOR)"
    cargo zigbuild --release --locked --target "$target" -p "$PKG"
    binary="target/${BASE_TRIPLE}/release/${BIN_NAME}"
else
    echo "==> cargo-zigbuild not found; building against the host glibc" >&2
    echo "    the binary will require this host's glibc and is not portable to older ones" >&2
    cargo build --release --locked -p "$PKG"
    binary="target/release/${BIN_NAME}"
    GLIBC_FLOOR=""
fi

[ -f "$binary" ] || { echo "error: expected binary not found: $binary" >&2; exit 1; }

mapfile -t glibc_versions < <(
    readelf -V "$binary" 2>/dev/null |
        grep -oE 'GLIBC_[0-9]+\.[0-9]+(\.[0-9]+)?' |
        sed 's/^GLIBC_//' | sort -uV
)
if [ "${#glibc_versions[@]}" -eq 0 ]; then
    echo "error: no versioned glibc symbols found; unexpected for a glibc-dynamic binary" >&2
    exit 1
fi
required="${glibc_versions[-1]}"

if [ -n "$GLIBC_FLOOR" ]; then
    newest="$(printf '%s\n%s\n' "$required" "$GLIBC_FLOOR" | sort -V | tail -n1)"
    if [ "$required" != "$GLIBC_FLOOR" ] && [ "$newest" = "$required" ]; then
        echo "error: binary requires GLIBC_$required, above the requested floor $GLIBC_FLOOR" >&2
        exit 1
    fi
fi

echo
echo "portable build complete"
echo "  binary:        $binary"
echo "  size:          $(du -h "$binary" | cut -f1)"
echo "  requires glibc: $required"
echo "  dynamic deps:  $(readelf -d "$binary" | grep NEEDED | grep -oE '\[.*\]' | tr -d '[]' | tr '\n' ' ')"
