#!/usr/bin/env python3
"""Real TCP/UDP allowlist tests using only local deterministic echo servers."""
import argparse
import errno
import json
import os
from pathlib import Path
import platform
import socket
import subprocess
import tempfile
import threading
import time


class EchoServer:
    def __init__(self, family=socket.AF_INET, udp=False, wait_eof=False):
        self.udp = udp
        self.wait_eof = wait_eof
        self.socket = socket.socket(family, socket.SOCK_DGRAM if udp else socket.SOCK_STREAM)
        self.socket.settimeout(3)
        self.host = "127.0.0.1" if family == socket.AF_INET else "::1"
        self.socket.bind((self.host, 0))
        self.port = self.socket.getsockname()[1]
        self.messages = []
        self.eof = False
        self.error = None
        if not udp:
            self.socket.listen(5)
        self.thread = threading.Thread(target=self.run, daemon=True)

    def run(self):
        try:
            if self.udp:
                while True:
                    data, peer = self.socket.recvfrom(65536)
                    self.messages.append(data)
                    self.socket.sendto(data, peer)
            else:
                stream, _ = self.socket.accept()
                with stream:
                    stream.settimeout(3)
                    while True:
                        data = stream.recv(65536)
                        if not data:
                            self.eof = True
                            break
                        self.messages.append(data)
                        stream.sendall(data)
                        if not self.wait_eof:
                            break
        except (OSError, TimeoutError) as error:
            self.error = str(error)

    def __enter__(self):
        self.thread.start()
        return self

    def __exit__(self, *_):
        self.socket.close()
        self.thread.join(timeout=0.1)


class Suite:
    def __init__(self, args):
        self.args = args
        self.binary = str(Path(args.binary).resolve())
        self.runtime = []
        for path in sorted({str(Path(p).resolve()) for p in
                            ("/usr/bin", "/usr/lib", "/usr/lib64", "/bin", "/lib", "/lib64")
                            if Path(p).exists()}):
            self.runtime += ["--rx", path]
        self.records = []
        self.temp = tempfile.TemporaryDirectory(prefix="cincta-network-")
        self.root = Path(self.temp.name)
        self.index = 0

    def run(self, script, rules, expected=0, extra_grants=()):
        self.index += 1
        result = self.root / f"result-{self.index}.json"
        command = [self.binary, "run", *self.runtime, "--network", "allowlist",
                   "--timeout-ms", "8000", "--result", str(result)]
        if self.args.compat:
            command += ["--compat"]
        for path in extra_grants:
            command += ["--rx", str(path)]
        for rule in rules:
            command += ["--allow-net", rule]
        command += ["--", "/usr/bin/python3", "-c", script]
        proc = subprocess.run(command, capture_output=True, text=True, timeout=13)
        assert proc.returncode == expected, (proc.returncode, proc.stdout, proc.stderr)
        assert result.exists(), proc.stderr
        report = json.loads(result.read_text())
        assert report["cleanup_complete"] is True, report
        if expected == 0:
            assert report["status"] == "ok", report
        return {"result": report, "stdout": proc.stdout, "stderr": proc.stderr}

    def test(self, name, fn, blocked=None):
        record = {"name": name}
        if blocked:
            record.update(outcome="BLOCKED", reason=blocked)
        else:
            try:
                record.update(outcome="PASS", evidence=fn())
            except Exception as error:
                record.update(outcome="FAIL", reason=str(error))
        self.records.append(record)
        print(record["outcome"], name, record.get("reason", ""), flush=True)

    def tcp(self, rule_kind="ip", family=socket.AF_INET):
        with EchoServer(family) as server:
            host = server.host
            rule_host = {"ip": host, "cidr": "127.0.0.0/8", "domain": "localhost"}[rule_kind]
            if family == socket.AF_INET6:
                rule_host = f"[{host}]"
            code = (f"import socket; s=socket.socket({family},socket.SOCK_STREAM);"
                    f"s.connect(({host!r},{server.port}));s.sendall(b'hello');"
                    "assert s.recv(5)==b'hello';s.close()")
            report = self.run(code, [f"tcp:{rule_host}:{server.port}"])
            assert b"".join(server.messages) == b"hello", server.messages
            return report

    def tcp_denied(self, wrong_port=False):
        with EchoServer() as server:
            allowed_port = server.port + 1 if server.port < 65535 else server.port - 1
            rule = f"tcp:{server.host if wrong_port else '127.0.0.2'}:{allowed_port if wrong_port else server.port}"
            code = ("import socket,errno; s=socket.socket();\n"
                    f"try: s.connect(({server.host!r},{server.port}))\n"
                    "except OSError as e: assert e.errno==errno.EACCES,e\n"
                    "else: raise AssertionError('forbidden connection succeeded')\n")
            result = self.run(code, [rule])
            assert not server.messages, server.messages
            return result

    def udp(self, connected=False, sendmsg=False):
        with EchoServer(udp=True) as server:
            code = "import socket; s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM);s.settimeout(2);"
            if connected:
                code += f"s.connect(({server.host!r},{server.port}));s.send(b'hello');"
            elif sendmsg:
                code += f"s.sendmsg([b'he',b'llo'],[],0,({server.host!r},{server.port}));"
            else:
                code += f"s.sendto(b'hello',({server.host!r},{server.port}));"
            code += "assert s.recvfrom(5)[0]==b'hello';s.close()"
            result = self.run(code, [f"udp:{server.host}:{server.port}"])
            assert server.messages == [b"hello"], server.messages
            return result

    def udp_denied(self, sendmsg=False):
        with EchoServer(udp=True) as server:
            operation = (f"s.sendmsg([b'escape'],[],0,({server.host!r},{server.port}))" if sendmsg else
                         f"s.sendto(b'escape',({server.host!r},{server.port}))")
            code = ("import socket,errno;s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM);\n"
                    f"try: {operation}\n"
                    "except OSError as e: assert e.errno==errno.EACCES,e\n"
                    "else: raise AssertionError('forbidden datagram escaped')\n")
            result = self.run(code, [f"udp:127.0.0.2:{server.port}"])
            time.sleep(0.02)
            assert not server.messages, server.messages
            return result

    def ancillary_denied(self):
        with EchoServer(udp=True) as server:
            code = ("import socket,errno;s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM);\n"
                    f"try:s.sendmsg([b'x'],[(socket.SOL_IP,socket.IP_TTL,b'\\x40\\0\\0\\0')],0,({server.host!r},{server.port}))\n"
                    "except OSError as e:assert e.errno==errno.EOPNOTSUPP,e\n"
                    "else:raise AssertionError('ancillary data accepted')\n")
            return self.run(code, [f"udp:{server.host}:{server.port}"])

    def socket_restriction(self, operation):
        statements = {
            "unix": "socket.socket(socket.AF_UNIX,socket.SOCK_STREAM)",
            "raw": "socket.socket(socket.AF_INET,socket.SOCK_RAW,socket.IPPROTO_ICMP)",
            "socketpair": "socket.socketpair()",
            "bind": "socket.socket().bind(('127.0.0.1',0))",
            "route-option": "socket.socket().setsockopt(socket.SOL_IP,socket.IP_OPTIONS,b'\\0'*4)",
        }
        code = ("import socket,errno;\ntry:" + statements[operation] + "\n"
                "except OSError as e:assert e.errno==errno.EPERM,e\n"
                "else:raise AssertionError('forbidden network operation accepted')\n")
        return self.run(code, ["tcp:127.0.0.1:1"])

    def duplicated_socket(self):
        with EchoServer() as server:
            code = ("import socket,os;s=socket.socket();n=os.dup(s.fileno());t=socket.socket(fileno=n);"
                    f"t.connect(({server.host!r},{server.port}));t.sendall(b'hello');"
                    "assert t.recv(5)==b'hello';t.close();s.close()")
            return self.run(code, [f"tcp:{server.host}:{server.port}"])

    def fork_descendant(self, udp=False):
        with EchoServer(udp=udp) as server:
            child_code = ("s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM);s.settimeout(2);"
                          f"s.sendto(b'hello',({server.host!r},{server.port}));"
                          "assert s.recvfrom(5)[0]==b'hello'" if udp else
                          "s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);"
                          f"s.connect(({server.host!r},{server.port}));s.sendall(b'hello');"
                          "assert s.recv(5)==b'hello'")
            code = ("import os,socket,traceback\nchild=os.fork()\n"
                    "if child==0:\n try:\n  " + child_code + "\n"
                    " except BaseException:\n  traceback.print_exc();os._exit(81)\n"
                    " os._exit(0)\n"
                    "_,status=os.waitpid(child,0)\n"
                    "assert os.WIFEXITED(status) and os.WEXITSTATUS(status)==0,status\n")
            result = self.run(code, [f"{'udp' if udp else 'tcp'}:{server.host}:{server.port}"])
            assert server.messages == [b"hello"], server.messages
            return result

    def fd_retention(self):
        with EchoServer(wait_eof=True) as server:
            code = ("import socket,time;s=socket.socket();"
                    f"s.connect(({server.host!r},{server.port}));s.sendall(b'hello');"
                    "assert s.recv(5)==b'hello';s.close();time.sleep(0.5)")
            result = self.run(code, [f"tcp:{server.host}:{server.port}"])
            server.thread.join(timeout=1)
            assert server.eof, (server.messages, server.error)
            return result

    def sendmmsg(self):
        with EchoServer(udp=True) as server:
            code = r'''
import ctypes as c,socket
class Iov(c.Structure):_fields_=[('base',c.c_void_p),('size',c.c_size_t)]
class Msg(c.Structure):_fields_=[('name',c.c_void_p),('namelen',c.c_uint),('iov',c.POINTER(Iov)),('iovlen',c.c_size_t),('control',c.c_void_p),('controllen',c.c_size_t),('flags',c.c_int)]
class Mmsg(c.Structure):_fields_=[('msg',Msg),('size',c.c_uint)]
s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM)
s.settimeout(2)
s.connect(('127.0.0.1',PORT))
buf1=c.create_string_buffer(b'one');buf2=c.create_string_buffer(b'two')
iov1=Iov(c.cast(buf1,c.c_void_p),3);iov2=Iov(c.cast(buf2,c.c_void_p),3)
batch=(Mmsg*2)()
batch[0].msg.iov=c.pointer(iov1);batch[0].msg.iovlen=1
batch[1].msg.iov=c.pointer(iov2);batch[1].msg.iovlen=1
lib=c.CDLL(None,use_errno=True)
sent=lib.sendmmsg(s.fileno(),batch,2,0)
assert sent==2,(sent,c.get_errno())
assert [batch[i].size for i in range(2)]==[3,3]
assert {s.recv(8),s.recv(8)}=={b'one',b'two'}
'''.replace("PORT", str(server.port))
            return self.run(code, [f"udp:{server.host}:{server.port}"])

    def private_thread_fd_table(self):
        helper = self.root / "private-thread-fds"
        source = Path(__file__).with_name("network_thread_fds.c")
        compiler = subprocess.run([os.environ.get("CC", "cc"), "-std=c17", "-Wall", "-Wextra",
                                   "-Werror", str(source), "-o", str(helper)],
                                  capture_output=True, text=True, timeout=30)
        assert compiler.returncode == 0, compiler.stderr
        with EchoServer() as server:
            code = f"import os;os.execv({str(helper)!r},[{str(helper)!r},{str(server.port)!r}])"
            result = self.run(code, [f"tcp:{server.host}:{server.port}"], extra_grants=[helper])
            assert json.loads(result["stdout"])["private_thread_fd_errno"] == 0, result
            return result

    def legacy_numeric_denied(self, address):
        command = [self.binary, "run", *self.runtime, "--network", "allowlist",
                   "--allow-net", f"tcp:{address}:80"]
        if self.args.compat:
            command += ["--compat"]
        command += ["--", "/bin/sh", "-c", "echo unexpected-workload"]
        proc = subprocess.run(command, capture_output=True, text=True, timeout=10)
        assert proc.returncode == 125, (proc.returncode, proc.stdout, proc.stderr)
        assert "canonical" in proc.stderr, proc.stderr
        assert "unexpected-workload" not in proc.stdout, proc.stdout
        return {"returncode":proc.returncode,"stderr":proc.stderr}

    def execute(self):
        self.test("network.tcp-ip", self.tcp)
        self.test("network.tcp-cidr", lambda: self.tcp("cidr"))
        self.test("network.tcp-domain-snapshot", lambda: self.tcp("domain"))
        self.test("network.tcp-address-denied", self.tcp_denied)
        self.test("network.tcp-port-denied", lambda: self.tcp_denied(True))
        try:
            probe = socket.socket(socket.AF_INET6)
            probe.bind(("::1", 0));probe.close()
            ipv6 = None
        except OSError as error:
            ipv6 = str(error)
        self.test("network.tcp-ipv6", lambda: self.tcp(family=socket.AF_INET6), blocked=ipv6)
        self.test("network.udp-sendto", self.udp)
        self.test("network.udp-connected", lambda: self.udp(connected=True))
        self.test("network.udp-sendmsg", lambda: self.udp(sendmsg=True))
        self.test("network.udp-sendmmsg", self.sendmmsg)
        self.test("network.udp-sendto-denied", self.udp_denied)
        self.test("network.udp-sendmsg-denied", lambda: self.udp_denied(True))
        self.test("network.ancillary-routing-denied", self.ancillary_denied)
        for operation in ("unix", "raw", "socketpair", "bind", "route-option"):
            self.test("network." + operation + "-denied", lambda op=operation:self.socket_restriction(op))
        self.test("network.fd-dup", self.duplicated_socket)
        self.test("network.fork-child-tcp", self.fork_descendant)
        self.test("network.fork-child-udp", lambda: self.fork_descendant(True))
        self.test("network.close-produces-eof", self.fd_retention)
        self.test("network.thread-private-fd-table", self.private_thread_fd_table)
        for address in ("127.1", "2130706433", "0x7f000001"):
            self.test("network.legacy-numeric-denied-" + address,
                      lambda a=address:self.legacy_numeric_denied(a))
        counts = {status:sum(row["outcome"]==status for row in self.records)
                  for status in ("PASS","FAIL","BLOCKED")}
        report = {"schema_version":1,"environment":self.args.environment,
                  "architecture":platform.machine(),"kernel":platform.release(),
                  "mode":"compat" if self.args.compat else "strict",
                  "counts":counts,"results":self.records}
        if self.args.report:
            destination=Path(self.args.report);destination.parent.mkdir(parents=True,exist_ok=True)
            destination.write_text(json.dumps(report,indent=2)+"\n")
        print(json.dumps(counts))
        self.temp.cleanup()
        return int(counts["FAIL"]>0)


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary",default="build/cincta")
    parser.add_argument("--compat",action="store_true")
    parser.add_argument("--environment",default="network-native")
    parser.add_argument("--report")
    return Suite(parser.parse_args()).execute()


if __name__=="__main__":
    raise SystemExit(main())
