import base64
import contextlib
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
HANDSHAKE_TYPES = [rr.NULL, rr.CNAME, rr.MX]
_B32_ENC_TRANS = str.maketrans(
    "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567",
    "abcdefghijklmnopqrstuvwxyz012345",
)
_B32_DEC_TRANS = {v: k for k, v in _B32_ENC_TRANS.items()}

if len(sys.argv) < 3:
    sys.stderr.write(f"Usage: {sys.argv[0]} <thin_server> <os>\n")
    sys.exit(1)

binary, target_os = sys.argv[1], sys.argv[2].lower()


def b32_encode(data):
    return base64.b32encode(data).decode("ascii").rstrip("=").translate(_B32_ENC_TRANS)


def b32_decode(s):
    s = s.translate(_B32_DEC_TRANS)
    return base64.b32decode(s + "=" * ((-len(s)) % 8))


def query_dns(ip, port, qname, rdtype):
    q = dns.message.make_query(qname, rdtype)
    return dns.query.udp(q, str(ip), port=port, timeout=2.0)


class ThinServer:
    def __init__(self, ns_ip=None):
        self.ns_ip = ns_ip
        self.ns_addr = None
        self.topdomain = ""
        self.ports = {}
        self.ips = []
        self.dns_log = []
        self.success = True

        cmd = [binary]
        if self.ns_ip is not None:
            cmd.append(self.ns_ip)
        print(f"[test ns={ns_ip}] Launching {' '.join(cmd)}", flush=True)
        self.process = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            bufsize=1,
        )
        while True:
            line = self.process.stdout.readline()
            if not line:
                break
            print(f"[serv ns={self.ns_ip}] {line.strip()}", flush=True)
            if line.startswith("NSADDR "):
                self.ns_addr = str(ipaddress.IPv4Address(line.split()[1]))
            elif line.startswith("ADDR "):
                ip = ipaddress.ip_address(line.split()[1])
                if ip not in self.ips:
                    self.ips.append(ip)
            elif line.startswith("OPEN"):
                parts = line.split()
                self.topdomain = parts[1]
                for part in parts[2:]:
                    if part.startswith("v4="):
                        self.ports[4] = int(part.split("=", 1)[1])
                    elif part.startswith("v6="):
                        self.ports[6] = int(part.split("=", 1)[1])
                break

        if self.process.poll() is not None:
            print("[test] Failed to open")
            sys.exit(1)

        self.output_thread = threading.Thread(
            target=self._log_output,
            args=(self.process.stdout,),
            daemon=True,
        )
        self.output_thread.start()

    def _log_output(self, stream):
        for line in iter(stream.readline, ""):
            self.dns_log.append(f"[serv ns={self.ns_ip}] {line}")
        stream.close()

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        if self.process.poll() is None:
            self.process.terminate()
            try:
                self.process.wait(timeout=2)
            except subprocess.TimeoutExpired:
                self.process.kill()
                self.process.wait()
        self.output_thread.join(timeout=1)
        if not self.success:
            sys.stdout.writelines(self.dns_log)


class ServerTestCase(unittest.TestCase):
    def __init__(self, methodName, srv, ip):
        super().__init__(methodName)
        self.srv = srv
        self.topdomain = srv.topdomain
        self.ip = ip
        self.port = srv.ports[ip.version]
        self.is_v4 = ip.version == 4

    def __str__(self):
        ns_tag = f", ns={self.srv.ns_ip}" if self.srv.ns_ip else ""
        return f"{self._testMethodName} ({self.ip}:{self.port}{ns_tag})"


class StandardDnsTest(ServerTestCase):

    def test_addr_records(self):
        addr_checks = [
            ("www", rr.A, "127.0.0.1"),
            ("www", rr.AAAA, "::1"),
        ]
        if self.srv.ns_addr or (self.is_v4 and target_os != "haiku"):
            addr_checks.append(("ns", rr.A, self.srv.ns_addr or str(self.ip)))
        if not self.is_v4 and target_os != "haiku":
            addr_checks.append(("ns", rr.AAAA, str(self.ip)))
        for sub, rdtype, expected in addr_checks:
            resp = query_dns(self.ip, self.port, f"{sub}.{self.topdomain}", rdtype)
            self.assertEqual(resp.rcode(), dns.rcode.NOERROR)
            self.assertEqual(resp.answer[0][0].address, expected)

    def test_soa_records(self):
        for sub in ("ns", "www"):
            soa_types = [rr.MX, rr.SRV]
            if sub == "ns" and self.is_v4:
                soa_types.append(rr.AAAA)
            for rdtype in soa_types:
                resp = query_dns(self.ip, self.port, f"{sub}.{self.topdomain}", rdtype)
                self.assertEqual(resp.rcode(), dns.rcode.NOERROR)
                self.assertEqual(len(resp.answer), 0)
                self.assertEqual(resp.authority[0].rdtype, rr.SOA)

    def test_ns_record(self):
        resp = query_dns(self.ip, self.port, self.topdomain, rr.NS)
        self.assertEqual(resp.rcode(), dns.rcode.NOERROR)
        self.assertEqual(resp.answer[0][0].target.to_text(), f"ns.{self.topdomain}.")
        if self.srv.ns_addr or (self.is_v4 and target_os != "haiku"):
            self.assertEqual(resp.additional[0][0].address, self.srv.ns_addr or str(self.ip))
        else:
            self.assertEqual(len(resp.additional), 0)

    def test_qname_minimisation(self):
        resp = query_dns(self.ip, self.port, f"_.sub.{self.topdomain}", rr.A)
        self.assertEqual(resp.rcode(), dns.rcode.NXDOMAIN)
        self.assertEqual(resp.authority[0].rdtype, rr.SOA)


def login_hash(password, seed):
    padded = password.encode("ascii").ljust(32, b"\x00")[:32]
    words = struct.unpack("!8I", padded)
    xored = struct.pack("!8I", *(w ^ (seed & 0xFFFFFFFF) for w in words))
    return hashlib.md5(xored).digest()


class HandshakeTest(ServerTestCase):
    def __init__(self, methodName, srv, ip, rdtype):
        super().__init__(methodName, srv, ip)
        self.rdtype = rdtype

    def __str__(self):
        ns_tag = f", ns={self.srv.ns_ip}" if self.srv.ns_ip else ""
        return f"{self._testMethodName} ({self.ip}:{self.port}, {self.rdtype.name}{ns_tag})"

    def query_payload(self, qname):
        resp = query_dns(self.ip, self.port, qname, self.rdtype)
        self.assertEqual(resp.rcode(), dns.rcode.NOERROR)
        rrset = resp.answer[0]
        self.assertEqual(rrset.rdtype, self.rdtype)
        if self.rdtype == rr.NULL:
            return rrset[0].data
        if self.rdtype == rr.CNAME:
            name = rrset[0].target.to_text()
        else:
            name = rrset[0].exchange.to_text()
        encoded = name.replace(".", "")
        self.assertTrue(encoded.startswith("h"))
        return b32_decode(encoded[1:-2])

    def send_version(self, version, cmc=1):
        payload = struct.pack("!IH", version, cmc)
        qname = f"V{b32_encode(payload)}.{self.topdomain}"
        rdata = self.query_payload(qname)
        self.assertEqual(len(rdata), 9)
        return struct.unpack("!4sIB", rdata)

    def send_login(self, userid, password, seed, cmc=2):
        payload = struct.pack("!B16sH", userid, login_hash(password, seed), cmc)
        qname = f"L{b32_encode(payload)}.{self.topdomain}"
        return self.query_payload(qname)

    def send_ip_request(self, userid, cmc=3):
        payload = struct.pack("!BH", userid << 3, cmc)
        qname = f"I{b32_encode(payload)}.{self.topdomain}"
        return self.query_payload(qname)

    def test_login(self):
        status, seed, userid = self.send_version(PROTOCOL_VERSION)
        self.assertEqual(status, b"VACK")
        self.assertLess(userid, 16)

        login_reply = self.send_login(userid, "testpass", seed).decode("ascii")
        server_ip, client_ip, mtu, netmask = login_reply.split("-")
        self.assertEqual(server_ip, "10.0.0.1")
        self.assertNotEqual(ipaddress.ip_address(client_ip), ipaddress.ip_address(server_ip))
        self.assertEqual(mtu, "1130")
        self.assertEqual(netmask, "27")

        ip_reply = self.send_ip_request(userid)
        self.assertEqual(ip_reply[:1], b"I")
        actual_ip = str(ipaddress.ip_address(ip_reply[1:]))
        if not self.is_v4:
            self.assertEqual(actual_ip, str(self.ip))
        elif self.srv.ns_addr or target_os != "haiku":
            self.assertEqual(actual_ip, self.srv.ns_addr or str(self.ip))

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


def build_suite(srv):
    suite = unittest.TestSuite()
    std_names = unittest.defaultTestLoader.getTestCaseNames(StandardDnsTest)
    handshake_ips = {}
    for ip in srv.ips:
        if ip.version in srv.ports and not (ip.version == 6 and target_os == "haiku"):
            suite.addTests(StandardDnsTest(name, srv, ip) for name in std_names)
            handshake_ips.setdefault(ip.version, ip)

    hs_names = unittest.defaultTestLoader.getTestCaseNames(HandshakeTest)
    for hs_ip in handshake_ips.values():
        for rdtype in HANDSHAKE_TYPES:
            suite.addTests(
                HandshakeTest(name, srv, hs_ip, rdtype)
                for name in hs_names
            )
    return suite


try:
    with contextlib.ExitStack() as stack:
        srvs = [stack.enter_context(ThinServer(ns_ip)) for ns_ip in (None, "1.2.3.4", "auto")]
        print(f"[test] Testing addresses " + ", ".join([str(ip) for ip in srvs[0].ips]), flush=True)
        suite = unittest.TestSuite(build_suite(srv) for srv in srvs)
        if suite.countTestCases() == 0:
            print("[test] No local IP addresses found")
            sys.exit(1)
        result = unittest.TextTestRunner(verbosity=2).run(suite)
        for srv in {test.srv for test, _ in result.errors + result.failures}:
            srv.success = False
        if not result.wasSuccessful():
            sys.exit(1)
except KeyboardInterrupt:
    print("\n[test] Interrupted.")
    sys.exit(1)
