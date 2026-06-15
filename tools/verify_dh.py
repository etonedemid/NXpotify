#!/usr/bin/env python3
"""
Run: python3 verify_dh.py
Data embedded from Wii U log attempt 1 (ap-gew4.spotify.com:443).
"""
import hmac as hmaclib, hashlib, struct

# ── DH prime (RFC 2409 Group 1, 768-bit) ─────────────────────────────────────
DH_PRIME = int.from_bytes(bytes([
    0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xc9,0x0f,0xda,0xa2,0x21,0x68,0xc2,0x34,
    0xc4,0xc6,0x62,0x8b,0x80,0xdc,0x1c,0xd1,0x29,0x02,0x4e,0x08,0x8a,0x67,0xcc,0x74,
    0x02,0x0b,0xbe,0xa6,0x3b,0x13,0x9b,0x22,0x51,0x4a,0x08,0x79,0x8e,0x34,0x04,0xdd,
    0xef,0x95,0x19,0xb3,0xcd,0x3a,0x43,0x1b,0x30,0x2b,0x0a,0x6d,0xf2,0x5f,0x14,0x37,
    0x4f,0xe1,0x35,0x6d,0x6d,0x51,0xc2,0x45,0xe4,0x85,0xb5,0x76,0x62,0x5e,0x7e,0xc6,
    0xf4,0x4c,0x42,0xe9,0xa6,0x3a,0x36,0x20,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,
]), 'big')

# ── Values from Wii U log, attempt 1 (ap-gew4:443) ──────────────────────────
priv_bytes = bytes.fromhex(
    "62AAD6CBDF063C0D3663CBEC636A706D"
    "42C363D90AFD9E29D250836B8AB64CFA"
    "AAF3E966AACD346D50E50E5BE84EE16E"
    "5A0DE5993B9ED7ED1B82E9EDA3762B14"
    "6E0703864A5DB09D934511DB24B1829B"
    "1CBC78A674835AF85EC94A891A1994"     # 95 bytes
)
srv_bytes = bytes.fromhex(
    "0F7648CA274AC79F83F18A4CDBB6D37A"
    "13461765D0277E800E4DA30C17CFD2D4"
    "7A730194164E6BD4D99EC47495A1BE77"
    "9F7009D8DB76DE069511E3F684EF5AC3"
    "60D840A737A2DDE873E33F3C240A5DB9"
    "A5DD173BBA6B16D84DEB97534AEEE723"  # 96 bytes
)
wiiu_shared = bytes.fromhex(
    "B5E0AA03378E18D215A2DF1DE921DE95"
    "12DB5797A68137E99BAD6FBE598A08E1"
    "5F62705C24E38328A11695AA38006860"
    "CB368D92E52B1A90D7A226D05A879E41"
    "6DF1A02E1BDFBE17017A1BA1449F128F"
    "D07E537F92FDD2866B147805C560C589"  # 96 bytes
)
wiiu_send_key_first8 = bytes.fromhex("4D0337B1DE10C11F")

# ── Shannon Python reference implementation ───────────────────────────────────
N = 16; KEYP = 13; INITKONST = 0x6996c53a

def rotl32(x, n): return ((x << n) | (x >> (32 - n))) & 0xFFFFFFFF
def sbox1(w):
    w ^= rotl32(w,5)|rotl32(w,7);   w ^= rotl32(w,19)|rotl32(w,22); return w&0xFFFFFFFF
def sbox2(w):
    w ^= rotl32(w,7)|rotl32(w,22);  w ^= rotl32(w,5)|rotl32(w,19);  return w&0xFFFFFFFF
def le32(b, i=0): return b[i]|(b[i+1]<<8)|(b[i+2]<<16)|(b[i+3]<<24)

class Shn:
    def __init__(self, key):
        self.CRC=[0]*N; self.R=[0]*N
        self.R[0]=1; self.R[1]=1
        for i in range(2,N): self.R[i]=(self.R[i-1]+self.R[i-2])&0xFFFFFFFF
        self.konst=INITKONST; self.sbuf=0; self.mbuf=0; self.nbuf=0
        self._loadkey(key); self.konst=self.R[0]; self.initR=self.R[:]
    def _cycle(self):
        t=(self.R[12]^self.R[13]^self.konst)&0xFFFFFFFF
        t=(sbox1(t)^rotl32(self.R[0],1))&0xFFFFFFFF
        for i in range(1,N): self.R[i-1]=self.R[i]
        self.R[N-1]=t
        t=sbox2((self.R[2]^self.R[N-1])&0xFFFFFFFF)
        self.R[0]=(self.R[0]^t)&0xFFFFFFFF
        self.sbuf=(t^self.R[8]^self.R[12])&0xFFFFFFFF
    def _diffuse(self):
        for _ in range(N): self._cycle()
    def _macfunc(self,i):
        t=(self.CRC[0]^self.CRC[2]^self.CRC[N-1]^i)&0xFFFFFFFF
        for j in range(1,N): self.CRC[j-1]=self.CRC[j]
        self.CRC[N-1]=t; self.R[KEYP]=(self.R[KEYP]^i)&0xFFFFFFFF
    def _loadkey(self, key):
        i=0
        while i<len(key):
            buf=[0,0,0,0]; chunk=min(len(key)-i,4)
            for j in range(chunk): buf[j]=key[i+j]
            self.R[KEYP]=(self.R[KEYP]^le32(buf))&0xFFFFFFFF; self._cycle(); i+=4
        self.R[KEYP]=(self.R[KEYP]^len(key))&0xFFFFFFFF; self._cycle()
        saved=self.R[:]; self._diffuse()
        for j in range(N): self.R[j]=(self.R[j]^saved[j])&0xFFFFFFFF
    def nonce(self, n):
        buf=[(n>>24)&0xFF,(n>>16)&0xFF,(n>>8)&0xFF,n&0xFF]
        self.R=self.initR[:]; self.konst=INITKONST; self._loadkey(buf)
        self.konst=self.R[0]; self.sbuf=0; self.nbuf=0
    def encrypt(self, data):
        result=[]
        for b in data:
            if self.nbuf==0: self._cycle(); self.nbuf=32
            self.mbuf=(self.mbuf^(b<<(32-self.nbuf)))&0xFFFFFFFF
            enc=(self.sbuf>>(32-self.nbuf))&0xFF; result.append(b^enc); self.nbuf-=8
            if self.nbuf==0: self._macfunc(self.mbuf); self.mbuf=0
        return bytes(result)

# ── Test 1: Shannon self-test ─────────────────────────────────────────────────
print("=" * 60)
shn_key = bytes(range(1, 21))  # 0x01..0x14
shn = Shn(shn_key)
shn.nonce(0)
shn_out = shn.encrypt(bytes(8))
WIIU_SHANNON = bytes.fromhex("4B6CA3FBC1ACCCE4")
print(f"Shannon self-test expected: {shn_out.hex().upper()}")
print(f"Shannon self-test Wii U:    {WIIU_SHANNON.hex().upper()}")
shannon_ok = (shn_out == WIIU_SHANNON)
print(f"Shannon match: {'YES ✓' if shannon_ok else 'NO ✗ -- cipher bug!'}")
print()

# ── Test 2: DH shared secret ──────────────────────────────────────────────────
priv_int = int.from_bytes(priv_bytes, 'big')
srv_int  = int.from_bytes(srv_bytes,  'big')
shared_int = pow(srv_int, priv_int, DH_PRIME)
shared_expected = shared_int.to_bytes(96, 'big').lstrip(b'\x00')

print(f"DH shared expected[0..7]:  {shared_expected[:8].hex().upper()}")
print(f"DH shared Wii U[0..7]:     {wiiu_shared[:8].hex().upper()}")
dh_ok = (shared_expected == wiiu_shared.lstrip(b'\x00'))
print(f"DH match: {'YES ✓' if dh_ok else 'NO ✗ -- exp_mod bug on PPC!'}")
print()

# ── Test 3: HMAC key derivation (needs ap_raw -- skip if not available) ────────
if dh_ok and shannon_ok:
    print("DH and Shannon both correct -- bug is in HMAC inputs.")
    print("Need full ap_raw (464 bytes) to verify. Add ap_raw logging.")
elif dh_ok and not shannon_ok:
    print("DH correct, Shannon wrong -- fix the Shannon cipher implementation.")
elif not dh_ok:
    print("DH wrong -- mbedtls_mpi_exp_mod gives wrong result on PPC!")
    print(f"Expected first 8: {shared_expected[:8].hex().upper()}")
    print(f"Got from Wii U:   {wiiu_shared[:8].hex().upper()}")
