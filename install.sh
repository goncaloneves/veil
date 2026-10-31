#!/bin/sh
set -eu

repo="goncaloneves/veil"
version="${VEIL_VERSION:-latest}"
home="${HOME:-}"
if [ -n "${VEIL_INSTALL_DIR:-}" ]; then
  dir="$VEIL_INSTALL_DIR"
elif [ -n "$home" ] && [ "$home" != / ]; then
  dir="$home/.local/bin"
else
  echo "veil: HOME is not set to a home folder; set VEIL_INSTALL_DIR to the folder to install into" >&2
  exit 1
fi

os=$(uname -s | tr '[:upper:]' '[:lower:]')
arch=$(uname -m)
case "$arch" in
  x86_64 | amd64) arch=x64 ;;
  arm64 | aarch64) arch=arm64 ;;
  *) echo "veil: no build for the $arch architecture" >&2; exit 1 ;;
esac
case "$os" in
  darwin | linux) ;;
  mingw* | msys* | cygwin*)
    echo "veil: on Windows, install with PowerShell: irm https://raw.githubusercontent.com/$repo/main/install.ps1 | iex" >&2
    exit 1
    ;;
  *) echo "veil: no build for $os" >&2; exit 1 ;;
esac

libc=""
if [ "$os" = linux ]; then
  linker=$(ldd --version 2>&1 || true)
  if printf '%s' "$linker" | grep -qi musl; then
    libc="-musl"
  elif ! printf '%s' "$linker" | grep -qiE 'glibc|gnu libc' && ls /lib/ld-musl-* >/dev/null 2>&1; then
    libc="-musl"
  fi
fi
asset="veil-$os-$arch$libc"
if [ "$version" = latest ]; then
  base="https://github.com/$repo/releases/latest/download"
else
  base="https://github.com/$repo/releases/download/$version"
fi

fetch() {
  if command -v curl >/dev/null 2>&1; then
    curl -fsSL "$1" -o "$2"
  elif command -v wget >/dev/null 2>&1; then
    wget -q -O "$2" "$1"
  else
    echo "veil: curl or wget is needed to download veil" >&2
    exit 1
  fi
}

sha256() {
  if command -v sha256sum >/dev/null 2>&1; then
    sha256sum "$1" | awk '{ print $1 }'
  elif command -v shasum >/dev/null 2>&1; then
    shasum -a 256 "$1" | awk '{ print $1 }'
  elif command -v openssl >/dev/null 2>&1; then
    openssl dgst -sha256 "$1" | awk '{ print $NF }'
  else
    echo "veil: sha256sum, shasum or openssl is needed to check the download" >&2
    exit 1
  fi
}

tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT INT TERM

echo "Downloading $asset ($version)"
fetch "$base/$asset" "$tmp/veil"
fetch "$base/SHA256SUMS" "$tmp/SHA256SUMS"

expected=$(awk -v name="$asset" '$2 == name { print $1 }' "$tmp/SHA256SUMS")
actual=$(sha256 "$tmp/veil")
if [ -z "$expected" ] || [ "$expected" != "$actual" ]; then
  echo "veil: the download does not match its published checksum; nothing was installed" >&2
  exit 1
fi

if ! mkdir -p "$dir" 2>/dev/null || [ ! -w "$dir" ]; then
  echo "veil: cannot write to $dir; set VEIL_INSTALL_DIR to a writable folder" >&2
  exit 1
fi
cp "$tmp/veil" "$dir/veil.new"
chmod 755 "$dir/veil.new"
if ! installed=$("$dir/veil.new" version 2>/dev/null); then
  rm -f "$dir/veil.new"
  echo "veil: the downloaded build does not run on this system; nothing was installed" >&2
  exit 1
fi
mv -f "$dir/veil.new" "$dir/veil"
echo "Installed veil $installed to $dir/veil"

case ":$PATH:" in
  *":$dir:"*) ;;
  *) echo "Add $dir to your PATH to run veil from anywhere." ;;
esac
