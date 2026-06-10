#!/usr/bin/env python3
"""
Spotify AP login smoke-test.
Runs the full DH handshake + Shannon-encrypted Login on the laptop so we can
iterate without reflashing the Wii U.

Usage:
    python3 tools/test_ap_login.py [--ap HOST:PORT] [--creds spotify_saved_creds.bin]

Defaults: ap-gue1.spotify.com:4070, reads spotify_saved_creds.bin from CWD.
"""

import argparse, hashlib, hmac, os, socket, struct, sys, time

# ─── DH prime (Spotify AP custom 96-byte / 768-bit prime) ────────────────────
DH_PRIME_BYTES = bytes([
    0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xc9,0x0f,0xda,0xa2,0x21,0x68,0xc2,0x34,
    0xc4,0xc6,0x62,0x8b,0x80,0xdc,0x1c,0xd1,0x29,0x02,0x4e,0x08,0x8a,0x67,0xcc,0x74,
    0x02,0x0b,0xbe,0xa6,0x3b,0x13,0x9b,0x22,0x51,0x4a,0x08,0x79,0x8e,0x34,0x04,0xdd,
    0xef,0x95,0x19,0xb3,0xcd,0x3a,0x43,0x1b,0x30,0x2b,0x0a,0x6d,0xf2,0x5f,0x14,0x37,
    0x4f,0xe1,0x35,0x6d,0x6d,0x51,0xc2,0x45,0xe4,0x85,0xb5,0x76,0x62,0x5e,0x7e,0xc6,
    0xf4,0x4c,0x42,0xe9,0xa6,0x3a,0x36,0x20,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,
])
DH_KEY_SIZE = len(DH_PRIME_BYTES)  # 96
DH_P = int.from_bytes(DH_PRIME_BYTES, 'big')
DH_G = 2

# ─── Shannon stream cipher ────────────────────────────────────────────────────
N         = 16
INITKONST = 0x6996c53a
KEYP      = 13
MASK32    = 0xFFFFFFFF

def rotl(x, n): return ((x << n) | (x >> (32 - n))) & MASK32

def sbox1(w):
    w ^= rotl(w, 5) | rotl(w, 7); w &= MASK32
    w ^= rotl(w,19) | rotl(w,22); w &= MASK32
    return w

def sbox2(w):
    w ^= rotl(w, 7) | rotl(w,22); w &= MASK32
    w ^= rotl(w, 5) | rotl(w,19); w &= MASK32
    return w

class Shannon:
    def __init__(self, key: bytes):
        self.R    = [0]*N
        self.CRC  = [0]*N
        self.initR= [0]*N
        self.konst= INITKONST
        self.sbuf = 0
        self.mbuf = 0
        self.nbuf = 0

        self.R[0] = 1; self.R[1] = 1
        for i in range(2, N):
            self.R[i] = (self.R[i-1] + self.R[i-2]) & MASK32
        self._loadkey(key)
        self._genkonst()
        self.initR = self.R[:]

    def _cycle(self):
        t = (self.R[12] ^ self.R[13] ^ self.konst) & MASK32
        t = (sbox1(t) ^ rotl(self.R[0], 1)) & MASK32
        for i in range(1, N): self.R[i-1] = self.R[i]
        self.R[N-1] = t
        t = sbox2((self.R[2] ^ self.R[N-1]) & MASK32)
        self.R[0] = (self.R[0] ^ t) & MASK32
        self.sbuf  = (t ^ self.R[8] ^ self.R[12]) & MASK32

    def _diffuse(self):
        for _ in range(N): self._cycle()

    def _crcfunc(self, i):
        t = (self.CRC[0] ^ self.CRC[2] ^ self.CRC[N-1] ^ i) & MASK32
        for j in range(1, N): self.CRC[j-1] = self.CRC[j]
        self.CRC[N-1] = t

    def _macfunc(self, i):
        self._crcfunc(i)
        self.R[KEYP] = (self.R[KEYP] ^ i) & MASK32

    def _loadkey(self, key: bytes):
        i = 0
        while i < len(key):
            chunk = key[i:i+4].ljust(4, b'\x00')
            w = struct.unpack_from('<I', chunk)[0]
            self.R[KEYP] = (self.R[KEYP] ^ w) & MASK32
            self._cycle()
            i += 4
        self.R[KEYP] = (self.R[KEYP] ^ len(key)) & MASK32
        self._cycle()
        # Save R into CRC before diffuse (matches Rust shannon crate: self.CRC = self.R)
        self.CRC = self.R[:]
        self._diffuse()
        for j in range(N): self.R[j] = (self.R[j] ^ self.CRC[j]) & MASK32

    def _genkonst(self): self.konst = self.R[0]

    def nonce(self, n: int):
        buf = struct.pack('>I', n)
        self.R     = self.initR[:]
        self.konst = INITKONST
        self._loadkey(buf)
        self._genkonst()
        self.sbuf = 0; self.nbuf = 0

    def encrypt(self, data: bytearray):
        for i in range(len(data)):
            if self.nbuf == 0: self._cycle(); self.nbuf = 32
            self.mbuf = (self.mbuf ^ ((data[i] << (32 - self.nbuf)) & MASK32)) & MASK32
            data[i]  ^= (self.sbuf >> (32 - self.nbuf)) & 0xFF
            self.nbuf -= 8
            if self.nbuf == 0: self._macfunc(self.mbuf); self.mbuf = 0

    def decrypt(self, data: bytearray):
        for i in range(len(data)):
            if self.nbuf == 0: self._cycle(); self.nbuf = 32
            data[i]  ^= (self.sbuf >> (32 - self.nbuf)) & 0xFF
            self.mbuf = (self.mbuf ^ ((data[i] << (32 - self.nbuf)) & MASK32)) & MASK32
            self.nbuf -= 8
            if self.nbuf == 0: self._macfunc(self.mbuf); self.mbuf = 0

    def finish(self) -> bytes:
        if self.nbuf != 0: self._macfunc(self.mbuf)
        self._cycle()
        self.R[KEYP] = (self.R[KEYP] ^ INITKONST ^ ((self.nbuf << 3) & MASK32)) & MASK32
        self.nbuf = 0; self.mbuf = 0
        for i in range(N): self.R[i] = (self.R[i] ^ self.CRC[i]) & MASK32
        self._diffuse()
        mac = bytearray(4)
        out_nbuf = 0
        for i in range(4):
            if out_nbuf == 0: self._cycle(); out_nbuf = 32
            mac[i] = (self.sbuf >> (32 - out_nbuf)) & 0xFF
            out_nbuf -= 8
        return bytes(mac)

# ─── Shannon self-test ────────────────────────────────────────────────────────
def shannon_selftest():
    key = bytes(range(1, 21))  # 0x01..0x14
    shn = Shannon(key)
    shn.nonce(0)
    buf = bytearray(8)
    shn.encrypt(buf)
    print(f"  Shannon self-test: {buf.hex().upper()}")

# ─── Protobuf helpers ─────────────────────────────────────────────────────────
def pb_varint(n: int) -> bytes:
    out = []
    while True:
        b = n & 0x7F; n >>= 7
        if n: out.append(b | 0x80)
        else: out.append(b); break
    return bytes(out)

def pb_tag(field: int, wtype: int) -> bytes:
    return pb_varint((field << 3) | wtype)

def pb_u32(field: int, val: int) -> bytes:
    return pb_tag(field, 0) + pb_varint(val)

def pb_str(field: int, s: str) -> bytes:
    b = s.encode()
    return pb_tag(field, 2) + pb_varint(len(b)) + b

def pb_bytes(field: int, data: bytes) -> bytes:
    return pb_tag(field, 2) + pb_varint(len(data)) + data

def pb_msg(field: int, data: bytes) -> bytes:
    return pb_tag(field, 2) + pb_varint(len(data)) + data

# ─── Handshake + Login ────────────────────────────────────────────────────────
HMAC_SHA1 = lambda key, msg: hmac.new(key, msg, hashlib.sha1).digest()

def compute_keys(shared: bytes, client_hello_raw: bytes, ap_raw: bytes):
    packets = client_hello_raw + ap_raw
    data = b''.join(
        HMAC_SHA1(shared, packets + bytes([i]))
        for i in range(1, 6)
    )  # 100 bytes
    challenge  = HMAC_SHA1(data[:20], packets)
    send_key   = data[20:52]
    recv_key   = data[52:84]
    return challenge, send_key, recv_key

def run(ap_host, ap_port, auth_type, auth_data, username, device_id):
    print(f"\n=== Connecting to {ap_host}:{ap_port} ===")
    sock = socket.create_connection((ap_host, ap_port), timeout=10)
    sock.settimeout(30)

    # ── DH key pair ───────────────────────────────────────────────────────────
    x = int.from_bytes(os.urandom(95), 'big') % (DH_P - 2) + 1
    pub = pow(DH_G, x, DH_P)
    pub_bytes = pub.to_bytes(DH_KEY_SIZE, 'big')

    # ── ClientHello proto (matches ap.cpp exactly) ────────────────────────────
    # BuildInfo { product=0, product_flags=0, platform=8, version=124200290 }
    build_info = (pb_u32(10, 0) + pb_u32(20, 0) + pb_u32(30, 8) +
                  pb_u32(40, 124200290))
    # LoginCryptoDiffieHellmanHello { gc=pub, server_keys_known=1 }
    dh_hello    = pb_bytes(10, pub_bytes) + pb_u32(20, 1)
    crypto_hello= pb_msg(10, dh_hello)
    client_nonce= os.urandom(16)
    padding     = bytes([0x1e])
    # ClientHello { build_info, fingerprints_supported, cryptosuites_supported,
    #               login_crypto_hello, client_nonce, padding }
    hello_proto = (pb_msg(10, build_info) + pb_u32(20, 0) + pb_u32(30, 0) +
                   pb_msg(50, crypto_hello) + pb_bytes(60, client_nonce) +
                   pb_bytes(70, padding))

    total = 2 + 4 + len(hello_proto)
    client_hello_raw = bytes([0x00, 0x04]) + struct.pack('>I', total) + hello_proto
    sock.sendall(client_hello_raw)
    print(f"  Sent ClientHello ({len(client_hello_raw)} bytes)")

    # ── APResponseMessage ─────────────────────────────────────────────────────
    ap_hdr = sock.recv(4)
    ap_total = struct.unpack('>I', ap_hdr)[0]
    ap_proto = b''
    while len(ap_proto) < ap_total - 4:
        chunk = sock.recv(ap_total - 4 - len(ap_proto))
        if not chunk: raise IOError("AP closed during APResponse")
        ap_proto += chunk
    ap_raw = ap_hdr + ap_proto
    print(f"  Received APResponse ({ap_total} bytes): {ap_proto[:16].hex()}")

    # Parse server public key and nonce from APResponseMessage
    # APResponseMessage.field10 = APChallenge
    #   APChallenge.field10 = LoginCryptoChallenge
    #     LCChallenge.field10 = DHChallenge
    #       DHChallenge.field10 = gs (server pub)
    #   APChallenge.field50 = server_nonce
    server_pub = None; server_nonce = None
    pos = 0
    while pos < len(ap_proto):
        tag_byte, n = 0, 0
        while True:
            b = ap_proto[pos]; pos += 1
            tag_byte |= (b & 0x7F) << (7*n); n += 1
            if not (b & 0x80): break
        field = tag_byte >> 3; wtype = tag_byte & 7
        if wtype == 2:
            ln = 0; n = 0
            while True:
                b = ap_proto[pos]; pos += 1
                ln |= (b & 0x7F) << (7*n); n += 1
                if not (b & 0x80): break
            val = ap_proto[pos:pos+ln]; pos += ln
            if field == 10:  # APChallenge
                # parse APChallenge
                ipos = 0
                while ipos < len(val):
                    itag, n2 = 0, 0
                    while True:
                        b = val[ipos]; ipos += 1
                        itag |= (b & 0x7F) << (7*n2); n2 += 1
                        if not (b & 0x80): break
                    if_ = itag >> 3; wt = itag & 7
                    if wt == 2:
                        iln = 0; n2 = 0
                        while True:
                            b = val[ipos]; ipos += 1
                            iln |= (b & 0x7F) << (7*n2); n2 += 1
                            if not (b & 0x80): break
                        ival = val[ipos:ipos+iln]; ipos += iln
                        if if_ == 10:  # LoginCryptoChallenge
                            # dig deeper for DH gs
                            jpos = 0
                            while jpos < len(ival):
                                jtag, n3 = 0, 0
                                while True:
                                    b = ival[jpos]; jpos += 1
                                    jtag |= (b & 0x7F) << (7*n3); n3 += 1
                                    if not (b & 0x80): break
                                jf = jtag >> 3; jwt = jtag & 7
                                if jwt == 2:
                                    jln = 0; n3 = 0
                                    while True:
                                        b = ival[jpos]; jpos += 1
                                        jln |= (b & 0x7F) << (7*n3); n3 += 1
                                        if not (b & 0x80): break
                                    jval = ival[jpos:jpos+jln]; jpos += jln
                                    if jf == 10:  # DH challenge
                                        kpos = 0
                                        while kpos < len(jval):
                                            ktag, n4 = 0, 0
                                            while True:
                                                b = jval[kpos]; kpos += 1
                                                ktag |= (b & 0x7F) << (7*n4); n4 += 1
                                                if not (b & 0x80): break
                                            kf = ktag >> 3; kwt = ktag & 7
                                            if kwt == 2:
                                                kln = 0; n4 = 0
                                                while True:
                                                    b = jval[kpos]; kpos += 1
                                                    kln |= (b & 0x7F) << (7*n4); n4 += 1
                                                    if not (b & 0x80): break
                                                kval = jval[kpos:kpos+kln]; kpos += kln
                                                if kf == 10:
                                                    server_pub = kval
                                            else:
                                                kpos += 1  # skip varint
                        elif if_ == 50:  # server_nonce
                            server_nonce = ival
                    else:
                        ipos += 1  # skip varint field
        elif wtype == 0:
            while True:
                b = ap_proto[pos]; pos += 1
                if not (b & 0x80): break

    if not server_pub or not server_nonce:
        raise ValueError(f"Missing server_pub or server_nonce in APResponse. server_pub={server_pub is not None} server_nonce={server_nonce}")

    print(f"  server_pub len={len(server_pub)} [0:4]={server_pub[:4].hex()}  server_nonce({len(server_nonce)}B)={server_nonce.hex()}")

    # ── DH shared secret ──────────────────────────────────────────────────────
    server_int = int.from_bytes(server_pub, 'big')
    shared_int = pow(server_int, x, DH_P)
    # Strip leading zeros — librespot does not pad the shared secret
    shared_bytes = shared_int.to_bytes(DH_KEY_SIZE, 'big').lstrip(b'\x00')

    # ── Key derivation ────────────────────────────────────────────────────────
    challenge, send_key, recv_key = compute_keys(shared_bytes, client_hello_raw, ap_raw)
    send_cipher = Shannon(send_key)
    recv_cipher = Shannon(recv_key)
    print(f"  send_key[0:8]={send_key[:8].hex()}  recv_key[0:8]={recv_key[:8].hex()}")
    print(f"  challenge={challenge[:8].hex()}...")

    # ── ClientResponsePlaintext ───────────────────────────────────────────────
    dh_resp     = pb_bytes(10, challenge)
    crypto_resp = pb_msg(10, dh_resp)
    pow_resp    = b''
    cry_resp    = b''
    hello_resp  = pb_msg(10, crypto_resp) + pb_msg(20, pow_resp) + pb_msg(30, cry_resp)
    resp_total  = 4 + len(hello_resp)
    plain_pkt   = struct.pack('>I', resp_total) + hello_resp
    sock.sendall(plain_pkt)
    print(f"  Sent ClientResponsePlaintext ({len(plain_pkt)} bytes)")

    # ── Build Login proto (ClientResponseEncrypted) ───────────────────────────
    # authentication.proto uses hex field numbers:
    # LoginCredentials: username=0xa=10, typ=0x14=20, auth_data=0x1e=30
    login_creds = (pb_str(10, username) +
                   pb_u32(20, auth_type) +
                   pb_bytes(30, auth_data))
    # SystemInfo: cpu_family=0xa=10, brand=0x28=40, os=0x3c=60,
    #             system_information_string=0x5a=90, device_id=0x64=100
    sys_info    = (pb_u32(10, 2) +   # cpu_family = CPU_X86_64
                   pb_u32(60, 5) +   # os = OS_LINUX
                   pb_str(90, "Linux;0.1;en;1.0.0-unknown") +
                   pb_bytes(100, device_id.encode()))
    login_proto = (pb_msg(10, login_creds) +
                   pb_msg(50, sys_info) +
                   pb_str(70, "libspotify-8.9.20-linux-x86_64-1"))  # version_string
    cmd = 0xAB
    print(f"  Login payload={len(login_proto)}B  auth_type={auth_type}  auth_data_len={len(auth_data)}")

    # ── Encrypt and send Login ────────────────────────────────────────────────
    send_seq = 0
    send_cipher.nonce(send_seq); send_seq += 1
    hdr = bytearray([cmd, len(login_proto) >> 8, len(login_proto) & 0xFF])
    send_cipher.encrypt(hdr)
    payload_enc = bytearray(login_proto)
    send_cipher.encrypt(payload_enc)
    mac = send_cipher.finish()
    wire = bytes(hdr) + bytes(payload_enc) + mac
    sock.sendall(wire)
    print(f"  Sent Login ({len(wire)} bytes): hdr_enc={bytes(hdr).hex()} mac={mac.hex()}")

    # ── Read response ─────────────────────────────────────────────────────────
    print("  Waiting for response...")
    try:
        resp_hdr = sock.recv(3)
    except socket.timeout:
        print("  TIMEOUT — no response in 30s")
        return
    if not resp_hdr:
        print("  Server closed connection without sending any data (FIN with no payload)")
        return
    if len(resp_hdr) < 3:
        print(f"  Only got {len(resp_hdr)} bytes: {resp_hdr.hex()}")
        return

    recv_seq = 0
    recv_cipher.nonce(recv_seq); recv_seq += 1
    hdr_dec = bytearray(resp_hdr)
    recv_cipher.decrypt(hdr_dec)
    resp_cmd = hdr_dec[0]
    resp_len = (hdr_dec[1] << 8) | hdr_dec[2]
    print(f"  Response: cmd=0x{resp_cmd:02X}  plen={resp_len}")

    resp_body = b''
    while len(resp_body) < resp_len:
        chunk = sock.recv(resp_len - len(resp_body))
        if not chunk: break
        resp_body += chunk
    resp_body = bytearray(resp_body)
    recv_cipher.decrypt(resp_body)

    mac_recv = sock.recv(4)
    expected_mac = recv_cipher.finish()
    mac_ok = mac_recv == expected_mac
    print(f"  MAC: recv={mac_recv.hex()} expected={expected_mac.hex()} {'OK' if mac_ok else 'MISMATCH'}")

    if resp_cmd == 0xAC:
        print("  *** APWelcome! ***")
        # parse canonical_username (field 10)
        pos = 0; body = bytes(resp_body)
        while pos < len(body):
            tag_byte, n = 0, 0
            while True:
                b = body[pos]; pos += 1
                tag_byte |= (b & 0x7F) << (7*n); n += 1
                if not (b & 0x80): break
            field = tag_byte >> 3; wtype = tag_byte & 7
            if wtype == 2:
                ln = 0; n = 0
                while True:
                    b = body[pos]; pos += 1
                    ln |= (b & 0x7F) << (7*n); n += 1
                    if not (b & 0x80): break
                val = body[pos:pos+ln]; pos += ln
                if field == 10:
                    print(f"  canonical_username = {val.decode()}")
                elif field == 40:
                    print(f"  reusable_credentials_type = {val}")
                elif field == 50:
                    print(f"  reusable_credentials_data = {len(val)} bytes")
            elif wtype == 0:
                v, n = 0, 0
                while True:
                    b = body[pos]; pos += 1
                    v |= (b & 0x7F) << (7*n); n += 1
                    if not (b & 0x80): break
                if field == 40: print(f"  reusable_credentials_type (u32) = {v}")
    elif resp_cmd == 0xAD:
        # parse error code (field 10 varint)
        pos = 0; body = bytes(resp_body); err_code = None
        while pos < len(body):
            tag_byte, n = 0, 0
            while True:
                b = body[pos]; pos += 1
                tag_byte |= (b & 0x7F) << (7*n); n += 1
                if not (b & 0x80): break
            field = tag_byte >> 3; wtype = tag_byte & 7
            if wtype == 0:
                v, n = 0, 0
                while True:
                    b = body[pos]; pos += 1
                    v |= (b & 0x7F) << (7*n); n += 1
                    if not (b & 0x80): break
                if field == 10: err_code = v
            elif wtype == 2:
                ln = 0; n = 0
                while True:
                    b = body[pos]; pos += 1
                    ln |= (b & 0x7F) << (7*n); n += 1
                    if not (b & 0x80): break
                pos += ln
        print(f"  *** AuthFailure error_code={err_code} ***")
        # Known codes: 12=BadCredentials, 9=PremiumRequired, 14=CouldNotValidateCredentials
    else:
        print(f"  Unknown response cmd=0x{resp_cmd:02X}: {bytes(resp_body)[:32].hex()}")

    sock.close()


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--ap', default='ap-gue1.spotify.com:4070')
    ap.add_argument('--creds', default='spotify_saved_creds.bin',
                    help='Binary creds file (1 byte auth_type + raw auth_data)')
    ap.add_argument('--username', default='')
    ap.add_argument('--password', default='')
    ap.add_argument('--device-id', default='0'*40)
    args = ap.parse_args()

    print("Shannon self-test:")
    shannon_selftest()

    host, port = args.ap.rsplit(':', 1)
    port = int(port)

    if args.password:
        auth_type = 0
        auth_data = args.password.encode()
        username  = args.username or 'test@example.com'
        print(f"\nUsing password auth: user={username}")
    elif os.path.exists(args.creds):
        with open(args.creds, 'rb') as f:
            raw = f.read()
        auth_type = raw[0]
        auth_data = raw[1:]
        username  = args.username or '31x6kzlr2bplislfgu44r63khffa'
        print(f"\nUsing saved creds: auth_type={auth_type} auth_data_len={len(auth_data)}")
    else:
        print(f"No creds found. Use --creds or --password.")
        sys.exit(1)

    run(host, port, auth_type, auth_data, username, args.device_id)

if __name__ == '__main__':
    main()
