#!/bin/sh
# Package public inputs only; runtime reports are separate CI/local artifacts.
set -eu
binary=${1:-build-static/cincta}
if [ ! -x "$binary" ]; then
  echo "executable missing: $binary" >&2
  exit 2
fi
if [ "$(uname -s)" != Linux ]; then
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
# Validate the actual ELF and reject dynamically linked release inputs.
binary_arch=$(python3 - "$binary" <<'PY'
import os,struct,sys
with open(sys.argv[1],"rb") as stream:
    header=stream.read(64)
    if len(header)!=64 or header[:6]!=b"\x7fELF\x02\x01":
        sys.exit("package input must be a little-endian ELF64 binary")
    machine=struct.unpack_from("<H",header,18)[0]
    architectures={62:"x86_64",183:"aarch64"}
    if machine not in architectures:
        sys.exit("unsupported ELF e_machine: "+str(machine))
    offset=struct.unpack_from("<Q",header,32)[0]
    entry_size,count=struct.unpack_from("<HH",header,54)
    if not count or entry_size<56 or offset+entry_size*count>os.fstat(stream.fileno()).st_size:
        sys.exit("invalid ELF program headers")
    for index in range(count):
        stream.seek(offset+entry_size*index)
        if struct.unpack("<I",stream.read(4))[0]==3:
            sys.exit("release input has an ELF interpreter; build with make STATIC=1")
print(architectures[machine])
PY
)
if [ "$arch" != "$binary_arch" ]; then
  echo "release architecture $arch does not match ELF architecture $binary_arch" >&2
  exit 2
fi
source_version=$(sed -n 's/^#define CINCTA_VERSION "\([^"]*\)"$/\1/p' include/cincta.h)
if [ -n "${CINCTA_PACKAGE_VERSION:-}" ]; then
  version=$CINCTA_PACKAGE_VERSION
  version_method=explicit
elif [ "$arch" = "$host_arch" ]; then
  version=$("$binary" --version | awk '{print $NF}')
  version_method=native-execution
else
  echo 'cross packaging requires CINCTA_PACKAGE_VERSION; foreign binaries are never executed' >&2
  exit 2
fi
case "$version" in
  ''|*[!0-9a-zA-Z._-]*) echo 'invalid package version' >&2; exit 2 ;;
esac
if [ "$version" != "$source_version" ]; then
  echo 'package version must match include/cincta.h' >&2
  exit 2
fi
name="cincta-$version-linux-$arch"
mkdir -p dist
staging=$(mktemp -d)
trap 'rm -rf "$staging"' EXIT HUP INT TERM
python3 - "$binary" "$staging/$name" "$arch" "$host_arch" "$version" "$version_method" <<'PY'
import hashlib,os,pathlib,re,shutil,subprocess,sys
binary,destination,arch,host_arch,version,version_method=sys.argv[1:]
destination=pathlib.Path(destination)
def revision(value,label):
    if not re.fullmatch(r"[0-9a-fA-F]{40}",value):
        sys.exit(label+" must be a full 40-character Git revision")
    return value.lower()
def git(*args):
    return subprocess.check_output(["git",*args],stderr=subprocess.DEVNULL)
try:
    git("rev-parse","--verify","HEAD")
except (OSError,subprocess.CalledProcessError):
    source=revision(os.environ.get("CINCTA_SOURCE_REVISION",""),"CINCTA_SOURCE_REVISION")
    source_method="export-declaration"
    tracked=None
else:
    status=git("status","--porcelain","--untracked-files=all")
    if status.strip():
        sys.exit("release packaging requires a clean Git worktree, including staged and untracked files")
    source=revision(git("rev-parse","HEAD").decode().strip(),"HEAD")
    source_method="clean-git-worktree"
    tracked={os.fsdecode(x) for x in git("ls-files","-z").split(b"\0") if x}
provided=os.environ.get("CINCTA_BINARY_SOURCE_REVISION","")
binary_source=revision(provided,"CINCTA_BINARY_SOURCE_REVISION") if provided else "unknown"
binary_method="caller-declaration" if provided else "unrecorded"
# The allowlist excludes local plans, .local, generated logs and raw reports.
roots=["README.md","LICENSE","SECURITY.md","CHANGELOG.md","AGENTS.md",
       "Makefile","Dockerfile",".gitignore",".dockerignore",
       "reports/README.md","reports/v02-summary.json"]
paths=[pathlib.Path(x) for x in roots if pathlib.Path(x).is_file()]
for directory in ("src","include","tests","scripts","docs","examples",".github"):
    for path in pathlib.Path(directory).rglob("*"):
        if "__pycache__" in path.parts or path.suffix==".pyc" or any(part.startswith(".") for part in path.parts[1:]):
            continue
        if path.is_file() or path.is_symlink(): paths.append(path)
paths=sorted(set(paths),key=lambda p:p.as_posix())
if tracked is not None: paths=[p for p in paths if p.as_posix() in tracked]
for path in paths:
    if path.is_symlink(): sys.exit("package source inputs must be regular files: "+str(path))
required={"README.md","LICENSE","SECURITY.md","include/cincta.h","Makefile","Dockerfile"}
if not required<={p.as_posix() for p in paths}: sys.exit("required public package inputs are missing")
destination.mkdir(parents=True)
shutil.copy2(binary,destination/"cincta")
manifest=[]
for path in paths:
    relative=path.as_posix()
    manifest.append(hashlib.sha256(path.read_bytes()).hexdigest()+"  "+relative)
    target=destination/path; target.parent.mkdir(parents=True,exist_ok=True); shutil.copy2(path,target)
(destination/"SOURCE_SHA256").write_text("\n".join(manifest)+"\n")
(destination/"SOURCE_REVISION").write_text(source+"\n")
(destination/"BINARY_SOURCE_REVISION").write_text(binary_source+"\n")
(destination/"BINARY_SHA256").write_text(hashlib.sha256(pathlib.Path(binary).read_bytes()).hexdigest()+"  cincta\n")
(destination/"BINARY_INFO").write_bytes(subprocess.check_output(["file",binary]))
(destination/"PACKAGE_INFO").write_text(
    "architecture="+arch+"\nbuilder_architecture="+host_arch+"\nversion="+version+
    "\nversion_source="+version_method+"\nsource_revision_method="+source_method+
    "\nbinary_source_revision_method="+binary_method+"\nelf_interpreter=none\n")
PY
tar -C "$staging" -czf "dist/$name.tar.gz" "$name"
(cd dist && sha256sum "$name.tar.gz" > "$name.tar.gz.sha256")
printf '%s\n' "dist/$name.tar.gz" "dist/$name.tar.gz.sha256"
