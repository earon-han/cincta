#!/bin/sh
# Run on a Linux builder with x86_64 cross GCC and qemu-system-x86_64.
# This boots an actual x86_64 Linux kernel (TCG full-system), never qemu-user.
set -eu
if [ "$(id -u)" -ne 0 ]; then
  echo 'Run this VM harness as root to unpack device nodes; cincta guest tests still run as uid 501.' >&2
  exit 2
fi
vm_dir=${CINCTA_X86_VM_DIR:-/tmp/cincta-x86-vm}
cc=${CINCTA_X86_CC:-x86_64-linux-gnu-gcc}
release=${CINCTA_X86_ALPINE_RELEASE:-v3.23}
base="https://dl-cdn.alpinelinux.org/alpine/$release/releases/x86_64/netboot"
mkdir -p "$vm_dir" reports
for name in vmlinuz-virt initramfs-virt; do
  if [ ! -s "$vm_dir/$name" ]; then
    curl -fL --connect-timeout 15 --max-time 180 "$base/$name" -o "$vm_dir/$name"
  fi
done
sha256sum "$vm_dir/vmlinuz-virt" "$vm_dir/initramfs-virt" > "$vm_dir/boot-sha256.txt"
root="$vm_dir/root"
if [ ! -d "$root/lib/modules" ]; then
  mkdir -p "$root"
  gzip -dc "$vm_dir/initramfs-virt" | (cd "$root" && cpio -idm --no-preserve-owner)
fi
make BUILD="$vm_dir/build" CC="$cc" STATIC=1
"$cc" -std=c17 -O2 -Wall -Wextra -Wpedantic -Werror -static tests/x86_vm_init.c -o "$vm_dir/init"
"$cc" -std=c17 -O2 -Wall -Wextra -Wpedantic -Werror -static tests/x86_kernel_smoke.c -o "$vm_dir/x86-smoke"
cp "$vm_dir/init" "$root/init"
cp "$vm_dir/x86-smoke" "$root/x86-smoke"
cp "$vm_dir/build/cincta" "$root/cincta"
cp "$vm_dir/build/adversary" "$root/adversary"
chmod 0755 "$root/init" "$root/x86-smoke" "$root/cincta" "$root/adversary"
(cd "$root" && find . -print0 | cpio --null -o --format=newc --owner=0:0 | gzip -1) > "$vm_dir/validation-initramfs.gz"
sha256sum src/*.c include/*.h tests/x86_vm_init.c tests/x86_kernel_smoke.c "$vm_dir/build/cincta" \
  > reports/v02-x86-source-sha256.txt
set +e
timeout --signal=TERM 300 qemu-system-x86_64 -accel tcg -cpu max -smp 2 -m 768 \
  -kernel "$vm_dir/vmlinuz-virt" -initrd "$vm_dir/validation-initramfs.gz" \
  -append 'console=ttyS0 rdinit=/init panic=-1 loglevel=4 lsm=landlock,yama' \
  -nographic -no-reboot -monitor none -nic none > reports/v02-x86-serial.log 2>&1
qemu_code=$?
set -e
python3 - "$qemu_code" "$vm_dir" <<'PY'
import hashlib,json,platform,sys
from pathlib import Path
code=int(sys.argv[1]);vm=Path(sys.argv[2]);serial=Path('reports/v02-x86-serial.log').read_text(errors='replace')
cases=[];env={};probe={};summary={}
for line in serial.splitlines():
    for prefix,destination in [('CINCTA_X86_ENV ',env),('CINCTA_X86_PROBE ',probe),('CINCTA_X86_SUMMARY ',summary)]:
        if prefix in line:
            try:destination.update(json.loads(line.split(prefix,1)[1]))
            except json.JSONDecodeError:pass
    if 'CINCTA_X86_CASE ' in line:
        try:cases.append(json.loads(line.split('CINCTA_X86_CASE ',1)[1]))
        except json.JSONDecodeError:pass
counts={key:sum(x['outcome']==key for x in cases) for key in ('PASS','FAIL','BLOCKED')}
if not summary:
    counts['BLOCKED']+=1
    cases.append({'name':'vm.completed-report','outcome':'BLOCKED','reason':'no complete guest summary; inspect serial log'})
report={'schema_version':1,'environment':'qemu-system-x86_64-tcg-full-system','host_architecture':platform.machine(),
        'guest':env,'probe':probe,'qemu_exit_code':code,'counts':counts,'summary':summary,'results':cases,
        'binary_sha256':hashlib.sha256((vm/'build/cincta').read_bytes()).hexdigest(),
        'kernel_sha256':hashlib.sha256((vm/'vmlinuz-virt').read_bytes()).hexdigest(),
        'initramfs_sha256':hashlib.sha256((vm/'initramfs-virt').read_bytes()).hexdigest(),
        'evidence_note':'Full-system TCG boots a real x86_64 kernel; this is neither native x86 hardware nor qemu-user. Smoke coverage is narrower than the ARM VM/Docker suites.'}
Path('reports/v02-x86-kernel.json').write_text(json.dumps(report,indent=2)+'\n')
print(json.dumps(counts))
sys.exit(1 if counts['FAIL'] else 2 if counts['BLOCKED'] or code else 0)
PY
