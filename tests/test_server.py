import base64
import hashlib
import ipaddress
import struct
import subprocess
import sys
import threading
import unittest
import dns.message
import dns.query
import dns.rcode
import dns.rdatatype as rr

PROTOCOL_VERSION = 0x00000502
_B32_TRANS = str.maketrans(
    "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567",
    "abcdefghijklmnopqrstuvwxyz012345",
)

if len(sys.argv) < 3:
    sys.stderr.write(f"Usage: {sys.argv[0]} <thin_server> <os>\n")
    sys.exit(1)

binary, target_os = sys.argv[1], sys.argv[2].lower()
dns_log = []


def b32_encode(data):
    return base64.b32encode(data).decode("ascii").rstrip("=").translate(_B32_TRANS)


def query_dns(ip, port, qname, rdtype):
    q = dns.message.make_query(qname, rdtype)
    return dns.query.udp(q, str(ip), port=port, timeout=2.0)


class ServerTestCase(unittest.TestCase):
    def __init__(self, methodName, ip, port):
        super().__init__(methodName)
        self.ip = ip
        self.port = port
        self.is_v4 = ip.version == 4

    def __str__(self):
        return f"{self._testMethodName} ({self.ip}:{self.port})"


class StandardDnsTest(ServerTestCase):

    def test_addr_records(self):
        addr_checks = [
            ("www", rr.A, "127.0.0.1"),
            ("www", rr.AAAA, "::1"),
        ]
        if target_os != "haiku":
            addr_checks.append(("ns", rr.A if self.is_v4 else rr.AAAA, str(self.ip)))
        for sub, rdtype, expected in addr_checks:
            resp = query_dns(self.ip, self.port, f"{sub}.{topdomain}", rdtype)
            self.assertEqual(resp.rcode(), dns.rcode.NOERROR)
            self.assertEqual(resp.answer[0][0].address, expected)

    def test_soa_records(self):
        for sub in ("ns", "www"):
            soa_types = [rr.MX, rr.SRV]
            if sub == "ns" and self.is_v4:
                soa_types.append(rr.AAAA)
            for rdtype in soa_types:
                resp = query_dns(self.ip, self.port, f"{sub}.{topdomain}", rdtype)
                self.assertEqual(resp.rcode(), dns.rcode.NOERROR)
                self.assertEqual(len(resp.answer), 0)
                self.assertEqual(resp.authority[0].rdtype, rr.SOA)

    def test_ns_record(self):
        resp = query_dns(self.ip, self.port, topdomain, rr.NS)
        self.assertEqual(resp.rcode(), dns.rcode.NOERROR)
        self.assertEqual(resp.answer[0][0].target.to_text(), f"ns.{topdomain}.")
        if self.is_v4 and target_os != "haiku":
            self.assertEqual(resp.additional[0][0].address, str(self.ip))
        else:
            self.assertEqual(len(resp.additional), 0)

    def test_qname_minimisation(self):
        resp = query_dns(self.ip, self.port, f"_.sub.{topdomain}", rr.A)
        self.assertEqual(resp.rcode(), dns.rcode.NXDOMAIN)
        self.assertEqual(resp.authority[0].rdtype, rr.SOA)


def login_hash(password, seed):
    padded = password.encode("ascii").ljust(32, b"\x00")[:32]
    words = struct.unpack("!8I", padded)
    xored = struct.pack("!8I", *(w ^ (seed & 0xFFFFFFFF) for w in words))
    return hashlib.md5(xored).digest()


class HandshakeTest(ServerTestCase):
    def send_version(self, version, cmc=1):
        payload = struct.pack("!IH", version, cmc)
        qname = f"v{b32_encode(payload)}.{topdomain}"
        resp = query_dns(self.ip, self.port, qname, rr.NULL)
        self.assertEqual(resp.rcode(), dns.rcode.NOERROR)
        rdata = resp.answer[0][0].data
        self.assertEqual(len(rdata), 9)
        return struct.unpack("!4sIB", rdata)

    def send_login(self, userid, password, seed, cmc=2):
        payload = struct.pack("!B16sH", userid, login_hash(password, seed), cmc)
        qname = f"l{b32_encode(payload)}.{topdomain}"
        resp = query_dns(self.ip, self.port, qname, rr.NULL)
        self.assertEqual(resp.rcode(), dns.rcode.NOERROR)
        return resp.answer[0][0].data

    def test_login(self):
        status, seed, userid = self.send_version(PROTOCOL_VERSION)
        self.assertEqual(status, b"VACK")
        self.assertLess(userid, 16)
        reply = self.send_login(userid, "testpass", seed).decode("ascii")
        server_ip, client_ip, mtu, netmask = reply.split("-")
        self.assertEqual(server_ip, "10.0.0.1")
        self.assertNotEqual(ipaddress.ip_address(client_ip), ipaddress.ip_address(server_ip))
        self.assertEqual(mtu, "1130")
        self.assertEqual(netmask, "27")

    def test_login_wrong_password(self):
        status, seed, userid = self.send_version(PROTOCOL_VERSION)
        self.assertEqual(status, b"VACK")
        self.assertLess(userid, 16)
        reply = self.send_login(userid, "wrongpass", seed)
        self.assertEqual(reply, b"LNAK")

    def test_version_nack(self):
        status, expected_ver, userid = self.send_version(PROTOCOL_VERSION - 1)
        self.assertEqual(status, b"VNAK")
        self.assertEqual(expected_ver, PROTOCOL_VERSION)
        self.assertEqual(userid, 0)


cmd = [binary]
print(f"[test] Launching {' '.join(cmd)}", flush=True)

process = subprocess.Popen(
    cmd,
    stdout=subprocess.PIPE,
    stderr=subprocess.STDOUT,
    text=True,
    bufsize=1,
)


def log_dns_bench(stream):
    for line in iter(stream.readline, ""):
        dns_log.append(f"[dns] {line}")
    stream.close()


output_thread = None
success = False
try:
    topdomain = ""
    ports = {}
    ips = []
    while True:
        line = process.stdout.readline()
        if not line:
            break
        print(f"[dns] {line.strip()}", flush=True)
        if line.startswith("ADDR "):
            ip = ipaddress.ip_address(line.split()[1])
            if ip not in ips:
                ips.append(ip)
        elif line.startswith("OPEN"):
            parts = line.split()
            topdomain = parts[1]
            for part in parts[2:]:
                if part.startswith("v4="):
                    ports[4] = int(part.split("=", 1)[1])
                elif part.startswith("v6="):
                    ports[6] = int(part.split("=", 1)[1])
            break

    if process.poll() is not None:
        print("[test] Failed to open")
        sys.exit(1)

    output_thread = threading.Thread(
        target=log_dns_bench,
        args=(process.stdout,),
        daemon=True,
    )
    output_thread.start()

    print(f"[test] Testing addresses " + ", ".join([str(ip) for ip in ips]), flush=True)
    suite = unittest.TestSuite()
    std_names = unittest.defaultTestLoader.getTestCaseNames(StandardDnsTest)
    handshake_target = None
    for ip in ips:
        port = ports.get(ip.version)
        if port and not (ip.version == 6 and target_os == "haiku"):
            suite.addTests(StandardDnsTest(name, ip, port) for name in std_names)
            if handshake_target is None:
                handshake_target = (ip, port)

    if handshake_target is not None:
        hs_ip, hs_port = handshake_target
        hs_names = unittest.defaultTestLoader.getTestCaseNames(HandshakeTest)
        suite.addTests(HandshakeTest(name, hs_ip, hs_port) for name in hs_names)

    if suite.countTestCases() == 0:
        print("[test] No local IP addresses found")
        sys.exit(1)
    success = unittest.TextTestRunner(verbosity=2).run(suite).wasSuccessful()
    if not success:
        sys.exit(1)

except KeyboardInterrupt:
    print("\n[test] Interrupted.")
    sys.exit(1)
finally:
    if process.poll() is None:
        process.terminate()
        try:
            process.wait(timeout=2)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait()
    if output_thread is not None:
        output_thread.join(timeout=1)
    if not success:
        sys.stdout.writelines(dns_log)
    print("[test] Exited\n")
