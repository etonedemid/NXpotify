#!/usr/bin/env python3
"""
Full Spotify AP handshake test from laptop.
Usage: python3 test_ap.py [host] [port]
"""
import socket, struct, os, sys, hmac as hmaclib, hashlib

def pb_vi(v):
    b = b""
    while True:
        byte = v & 0x7F; v >>= 7
        b += bytes([byte | (0x80 if v else 0)])
        if not v: break
    return b

def pb_tag(f, w): return pb_vi((f << 3) | w)
def pb_u32(f, v): return pb_tag(f, 0) + pb_vi(v)
def pb_bytes(f, d): return pb_tag(f, 2) + pb_vi(len(d)) + d
def pb_msg(f, d): return pb_bytes(f, d)

def recvn(s, n):
    buf = b""
    while len(buf) < n:
        chunk = s.recv(n - len(buf))
        if not chunk: raise EOFError("connection closed")
        buf += chunk
    return buf

class PB:
    """Minimal protobuf reader."""
    def __init__(self, data):
        self.d = data; self.p = 0

    def vi(self):
        result = shift = 0
        while True:
            b = self.d[self.p]; self.p += 1
            result |= (b & 0x7F) << shift; shift += 7
            if not (b & 0x80): return result

    def tag(self):
        t = self.vi(); return t >> 3, t & 7

    def bytes_field(self):
        n = self.vi(); v = self.d[self.p:self.p+n]; self.p += n; return v

    def skip(self, w):
        if w == 0: self.vi()
        elif w == 2: self.bytes_field()
        elif w == 5: self.p += 4
        elif w == 1: self.p += 8

    def fields(self):
        while self.p < len(self.d):
            f, w = self.tag(); yield f, w

# RFC 2409 Group 1 768-bit prime
DH_PRIME = int.from_bytes(bytes([
    0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xc9,0x0f,0xda,0xa2,0x21,0x68,0xc2,0x34,
    0xc4,0xc6,0x62,0x8b,0x80,0xdc,0x1c,0xd1,0x29,0x02,0x4e,0x08,0x8a,0x67,0xcc,0x74,
    0x02,0x0b,0xbe,0xa6,0x3b,0x13,0x9b,0x22,0x51,0x4a,0x08,0x79,0x8e,0x34,0x04,0xdd,
    0xef,0x95,0x19,0xb3,0xcd,0x3a,0x43,0x1b,0x30,0x2b,0x0a,0x6d,0xf2,0x5f,0x14,0x37,
    0x4f,0xe1,0x35,0x6d,0x6d,0x51,0xc2,0x45,0xe4,0x85,0xb5,0x76,0x62,0x5e,0x7e,0xc6,
    0xf4,0x4c,0x42,0xe9,0xa6,0x3a,0x36,0x20,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,
]), 'big')
DH_GEN = 2

priv_key = int.from_bytes(os.urandom(95), 'big') % (DH_PRIME - 2) + 2
pub_key  = pow(DH_GEN, priv_key, DH_PRIME)
dh_pub   = pub_key.to_bytes(96, 'big')
print(f"DH pub[0..3]: {dh_pub[:4].hex()}")

build_info = (pb_u32(10, 0) + pb_u32(20, 0) + pb_u32(30, 8) + pb_u32(40, 124200290))
dh_hello     = pb_bytes(10, dh_pub) + pb_u32(20, 1)
crypto_hello = pb_msg(10, dh_hello)
nonce        = os.urandom(16)

client_hello = (pb_msg(10, build_info) +
                pb_u32(20, 0) +
                pb_u32(30, 0) +
                pb_msg(50, crypto_hello) +
                pb_bytes(60, nonce) +
                pb_bytes(70, b"\x1e"))

total  = 2 + 4 + len(client_hello)
packet = b"\x00\x04" + struct.pack(">I", total) + client_hello
client_hello_raw = packet

host = sys.argv[1] if len(sys.argv) > 1 else "ap-gew1.spotify.com"
port = int(sys.argv[2]) if len(sys.argv) > 2 else 4070

print(f"Sending {len(packet)}-byte ClientHello to {host}:{port}")
s = socket.socket()
s.settimeout(15)
s.connect((host, port))
print(f"  connected")
s.sendall(packet)

hdr    = recvn(s, 4)
total_ap = struct.unpack(">I", hdr)[0]
ap_proto = recvn(s, total_ap - 4)
ap_raw   = hdr + ap_proto
print(f"  APResponse: {total_ap} bytes, proto {len(ap_proto)} bytes")

# Parse: APResponseMessage → APChallenge(10) → login_crypto_challenge(10)
#        → diffie_hellman(10) → gs(10) = server pubkey (96 bytes)
server_pub = None
root = PB(ap_proto)
for f, w in root.fields():
    if f == 10 and w == 2:           # APChallenge
        ac = PB(root.bytes_field())
        for f2, w2 in ac.fields():
            if f2 == 10 and w2 == 2: # login_crypto_challenge
                lc = PB(ac.bytes_field())
                for f3, w3 in lc.fields():
                    if f3 == 10 and w3 == 2:  # diffie_hellman
                        dh = PB(lc.bytes_field())
                        for f4, w4 in dh.fields():
                            if f4 == 10 and w4 == 2:
                                server_pub = dh.bytes_field()
                            else:
                                dh.skip(w4)
                    else:
                        lc.skip(w3)
            else:
                ac.skip(w2)
    else:
        root.skip(w)

if not server_pub:
    print("ERROR: failed to parse server pubkey"); sys.exit(1)
print(f"  server_pub[0..3]: {server_pub[:4].hex()} ({len(server_pub)} bytes)")

# DH shared secret — always 96 bytes, zero-padded
srv_int    = int.from_bytes(server_pub, 'big')
shared_int = pow(srv_int, priv_key, DH_PRIME)
shared     = shared_int.to_bytes(96, 'big')
print(f"  shared[0..3]: {shared[:4].hex()}")

# Key derivation: HMAC-SHA1(key=shared, msg=client_hello_raw || ap_raw || [i])
# [i] is LAST — matches librespot (mac.update(packets); mac.update(&[i]))
key_data = b""
for i in range(1, 6):
    h = hmaclib.new(shared, digestmod=hashlib.sha1)
    h.update(client_hello_raw)
    h.update(ap_raw)
    h.update(bytes([i]))
    key_data += h.digest()

# From librespot compute_keys():
#   challenge = HMAC-SHA1(key=key_data[0..20],  msg=ch||ah)
#   send_key  = key_data[20..52]  (32 bytes)
#   recv_key  = key_data[52..84]  (32 bytes)
chal_key = key_data[0:20]
send_key = key_data[20:52]
recv_key = key_data[52:84]

# Challenge response: HMAC-SHA1(key=key_data[0..20], msg=client_hello_raw || ap_raw)
chal_mac = hmaclib.new(chal_key, digestmod=hashlib.sha1)
chal_mac.update(client_hello_raw)
chal_mac.update(ap_raw)
challenge = chal_mac.digest()

# Debug: print HMAC inputs
print(f"  ch_raw len={len(client_hello_raw)} [{client_hello_raw[:4].hex()}..{client_hello_raw[-4:].hex()}]")
print(f"  ap_raw len={len(ap_raw)} [{ap_raw[:4].hex()}..{ap_raw[-4:].hex()}]")
print(f"  shared  [{shared[:4].hex()}..{shared[-4:].hex()}]")
print(f"  chal_key: {chal_key.hex()}")
print(f"  challenge: {challenge.hex()}")

# Build and send ClientHelloResponse
# Include required pow_response (field 20, empty) and crypto_response (field 30, empty)
# as librespot does via mut_or_insert_default()
dh_resp    = pb_bytes(10, challenge)      # LoginCryptoDiffieHellmanResponse.hmac
crypto_rsp = pb_msg(10, dh_resp)          # LoginCryptoResponseUnion.diffie_hellman
hello_rsp  = (pb_msg(10, crypto_rsp) +   # login_crypto_response
              pb_bytes(20, b"") +         # pow_response (empty PoWResponseUnion, required)
              pb_bytes(30, b""))          # crypto_response (empty CryptoResponseUnion, required)
plain_pkt  = struct.pack(">I", 4 + len(hello_rsp)) + hello_rsp
s.sendall(plain_pkt)
print(f"  ClientHelloResponse sent ({len(plain_pkt)} bytes), challenge={challenge[:4].hex()}..")
print()
print("Derived keys (embed these in verify_dh.py for Wii U comparison):")
print(f'  send_key = bytes.fromhex("{send_key.hex()}")')
print(f'  recv_key = bytes.fromhex("{recv_key.hex()}")')
print(f'  send_key[0..7] = {send_key[:8].hex().upper()}')
print()

# Try to read server response (9 bytes to catch full APLoginFailed, or more for encrypted)
import select, time
time.sleep(0.5)
r, _, _ = select.select([s], [], [], 3.0)
if r:
    resp = s.recv(200)
    print(f"  Server sent {len(resp)} bytes: {resp.hex()}")
    if len(resp) >= 4:
        import struct as _s
        t = _s.unpack(">I", resp[:4])[0]
        if t == len(resp) and t < 20:
            print(f"  → Plain APLoginFailed! error_code={(resp[-1])}")
        else:
            print(f"  → Encrypted data (channel open!)")
else:
    print("  Server sent nothing (timeout) — channel accepted?")

s.close()
