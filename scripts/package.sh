#!/bin/sh
set -eu
binary=${1:-build/cincta}
if [ ! -x "$binary" ]; then
  echo "executable missing: $binary" >&2
  exit 2
fi
system=$(uname -s)
if [ "$system" != Linux ]; then
  echo 'release packaging must run on Linux' >&2
  exit 2
fi
arch=$(uname -m)
case "$arch" in
  x86_64) arch=x86_64 ;;
  aarch64|arm64) arch=aarch64 ;;
  *) echo "unsupported release architecture: $arch" >&2; exit 2 ;;
esac
version=$("$binary" --version | awk '{print $NF}')
case "$version" in
  ''|*[!0-9a-zA-Z._-]*) echo 'invalid version response' >&2; exit 2 ;;
esac
name="cincta-$version-linux-$arch"
mkdir -p dist
staging=$(mktemp -d)
trap 'rm -rf "$staging"' EXIT HUP INT TERM
mkdir "$staging/$name"
cp "$binary" "$staging/$name/cincta"
cp README.md LICENSE "$staging/$name/"
cp -R docs examples "$staging/$name/"
if git rev-parse --verify HEAD > "$staging/$name/SOURCE_REVISION" 2>/dev/null; then
  git diff --stat > "$staging/$name/WORKTREE_DIFF"
  git status --porcelain > "$staging/$name/WORKTREE_STATUS"
else
  printf '%s\n' "${CINCTA_SOURCE_REVISION:?export CINCTA_SOURCE_REVISION for an exported source tree}" > "$staging/$name/SOURCE_REVISION"
  printf '%s\n' 'Exported source tree; verify SOURCE_SHA256 against the recorded revision.' > "$staging/$name/WORKTREE_STATUS"
fi
find src include tests scripts docs examples -type f ! -name '*.pyc' -print0 \
  | sort -z | xargs -0 sha256sum > "$staging/$name/SOURCE_SHA256"
sha256sum Makefile Dockerfile README.md LICENSE >> "$staging/$name/SOURCE_SHA256"
file "$binary" > "$staging/$name/BINARY_INFO"
tar -C "$staging" -czf "dist/$name.tar.gz" "$name"
(cd dist && sha256sum "$name.tar.gz" > "$name.tar.gz.sha256")
printf '%s\n' "dist/$name.tar.gz" "dist/$name.tar.gz.sha256"
