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
host_arch=$(uname -m)
case "$host_arch" in
  x86_64) host_arch=x86_64 ;;
  aarch64|arm64) host_arch=aarch64 ;;
  *) echo "unsupported builder architecture: $host_arch" >&2; exit 2 ;;
esac
arch=${CINCTA_PACKAGE_ARCH:-$host_arch}
case "$arch" in
  x86_64|aarch64) ;;
  *) echo "unsupported release architecture: $arch" >&2; exit 2 ;;
esac
# Read the ELF header rather than executing a foreign target or trusting its name.
binary_arch=$(python3 - "$binary" <<'PY'
import struct,sys
with open(sys.argv[1],"rb") as stream:
    header=stream.read(64)
if len(header)!=64 or header[:6]!=b"\x7fELF\x02\x01":
    sys.exit("package input must be a little-endian ELF64 binary")
machine=struct.unpack_from("<H",header,18)[0]
architectures={62:"x86_64",183:"aarch64"}
if machine not in architectures:
    sys.exit("unsupported ELF e_machine: "+str(machine))
print(architectures[machine])
PY
)
if [ "$arch" != "$binary_arch" ]; then
  echo "release architecture $arch does not match ELF architecture $binary_arch" >&2
  exit 2
fi
if [ -n "${CINCTA_PACKAGE_VERSION:-}" ]; then
  version=$CINCTA_PACKAGE_VERSION
  version_method=explicit
  source_version=$(sed -n 's/^#define CINCTA_VERSION "\([^"]*\)"$/\1/p' include/cincta.h)
  if [ "$version" != "$source_version" ]; then
    echo 'explicit package version must match include/cincta.h' >&2
    exit 2
  fi
elif [ "$arch" = "$host_arch" ]; then
  version=$("$binary" --version | awk '{print $NF}')
  version_method=native-execution
else
  echo 'cross packaging requires CINCTA_PACKAGE_VERSION; foreign binaries are never executed' >&2
  exit 2
fi
case "$version" in
  ''|*[!0-9a-zA-Z._-]*) echo 'invalid version response' >&2; exit 2 ;;
esac
name="cincta-$version-linux-$arch"
mkdir -p dist
staging=$(mktemp -d)
trap 'rm -rf "$staging"' EXIT HUP INT TERM
mkdir "$staging/$name"
cp "$binary" "$staging/$name/cincta"
cp README.md LICENSE '实施计划.txt' "$staging/$name/"
cp -R docs examples reports "$staging/$name/"
if git rev-parse --verify HEAD > "$staging/$name/SOURCE_REVISION" 2>/dev/null; then
  git diff --stat > "$staging/$name/WORKTREE_DIFF"
  git status --porcelain > "$staging/$name/WORKTREE_STATUS"
else
  printf '%s\n' "${CINCTA_SOURCE_REVISION:?export CINCTA_SOURCE_REVISION for an exported source tree}" > "$staging/$name/SOURCE_REVISION"
  printf '%s\n' 'Exported source tree; verify SOURCE_SHA256 against the recorded revision.' > "$staging/$name/WORKTREE_STATUS"
fi
if [ -n "${CINCTA_BINARY_SOURCE_REVISION:-}" ]; then
  printf '%s\n' "$CINCTA_BINARY_SOURCE_REVISION" > "$staging/$name/BINARY_SOURCE_REVISION"
else
  cp "$staging/$name/SOURCE_REVISION" "$staging/$name/BINARY_SOURCE_REVISION"
fi
find src include tests scripts docs examples reports -type f ! -name '*.pyc' -print0 \
  | sort -z | xargs -0 sha256sum > "$staging/$name/SOURCE_SHA256"
sha256sum Makefile Dockerfile README.md LICENSE '实施计划.txt' >> "$staging/$name/SOURCE_SHA256"
file "$binary" > "$staging/$name/BINARY_INFO"
(cd "$staging/$name" && sha256sum cincta > BINARY_SHA256)
printf 'architecture=%s\nbuilder_architecture=%s\nversion=%s\nversion_source=%s\n' \
  "$arch" "$host_arch" "$version" "$version_method" > "$staging/$name/PACKAGE_INFO"
tar -C "$staging" -czf "dist/$name.tar.gz" "$name"
(cd dist && sha256sum "$name.tar.gz" > "$name.tar.gz.sha256")
printf '%s\n' "dist/$name.tar.gz" "dist/$name.tar.gz.sha256"
