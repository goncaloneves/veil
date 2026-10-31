#!/bin/sh
set -eu

repo="goncaloneves/veil"
version="${VEIL_VERSION:-latest}"
dir="${VEIL_INSTALL_DIR:-$HOME/.local/bin}"

os=$(uname -s | tr '[:upper:]' '[:lower:]')
arch=$(uname -m)
case "$arch" in
  x86_64 | amd64) arch=x64 ;;
  arm64 | aarch64) arch=arm64 ;;
  *) echo "veil: no build for the $arch architecture" >&2; exit 1 ;;
esac
case "$os" in
  darwin | linux) ;;
  *) echo "veil: no build for $os" >&2; exit 1 ;;
esac

libc=""
if [ "$os" = linux ] && { ldd --version 2>&1 | grep -qi musl || ls /lib/ld-musl-* >/dev/null 2>&1; }; then
  libc="-musl"
fi
asset="veil-$os-$arch$libc"
if [ "$version" = latest ]; then
  base="https://github.com/$repo/releases/latest/download"
else
  base="https://github.com/$repo/releases/download/$version"
fi

tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT INT TERM

echo "Downloading $asset ($version)"
curl -fsSL "$base/$asset" -o "$tmp/veil"
curl -fsSL "$base/SHA256SUMS" -o "$tmp/SHA256SUMS"

expected=$(awk -v name="$asset" '$2 == name { print $1 }' "$tmp/SHA256SUMS")
if command -v sha256sum >/dev/null 2>&1; then
  actual=$(sha256sum "$tmp/veil" | awk '{ print $1 }')
else
  actual=$(shasum -a 256 "$tmp/veil" | awk '{ print $1 }')
fi
if [ -z "$expected" ] || [ "$expected" != "$actual" ]; then
  echo "veil: the download does not match its published checksum; nothing was installed" >&2
  exit 1
fi

mkdir -p "$dir"
install -m 755 "$tmp/veil" "$dir/veil"
echo "Installed veil $("$dir/veil" version) to $dir/veil"

case ":$PATH:" in
  *":$dir:"*) ;;
  *) echo "Add $dir to your PATH to run veil from anywhere." ;;
esac
