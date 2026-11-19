"""Independent SLIP-10 reference (hardened paths only) for keyvault 0.6.0 golden values."""
import hashlib, hmac, struct
from cryptography.hazmat.primitives.asymmetric import ed25519, ec
from cryptography.hazmat.primitives import serialization

MNEMONIC = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
H = 0x80000000
N_P256 = 0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551
N_K1 = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141

def seed_of(m, p=""):
    return hashlib.pbkdf2_hmac("sha512", m.encode(), ("mnemonic" + p).encode(), 2048)

def mangle(s):
    return int.from_bytes(hashlib.sha256(s.encode()).digest()[:4], "big") & 0x7FFFFFFF

def derive(curve, seed, path):
    label, n = {"ed25519": (b"ed25519 seed", None), "p256": (b"Nist256p1 seed", N_P256), "k1": (b"Bitcoin seed", N_K1)}[curve]
    data = seed
    while True:
        I = hmac.new(label, data, hashlib.sha512).digest()
        k, c = I[:32], I[32:]
        if n is None or 0 < int.from_bytes(k, "big") < n:
            break
        data = I
    for i in path:
        assert i & H, "reference handles hardened only"
        I = hmac.new(c, b"\x00" + k + struct.pack(">I", i), hashlib.sha512).digest()
        while True:
            il, ir = I[:32], I[32:]
            if n is None:
                k, c = il, ir
                break
            v = int.from_bytes(il, "big")
            child = (v + int.from_bytes(k, "big")) % n
            if v < n and child != 0:
                k, c = child.to_bytes(32, "big"), ir
                break
            I = hmac.new(c, b"\x01" + ir + struct.pack(">I", i), hashlib.sha512).digest()
    return k, c

def pub(curve, k):
    if curve == "ed25519":
        return ed25519.Ed25519PrivateKey.from_private_bytes(k).public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    crv = ec.SECP256R1() if curve == "p256" else ec.SECP256K1()
    fmt = serialization.PublicFormat.UncompressedPoint if curve == "p256" else serialization.PublicFormat.CompressedPoint
    return ec.derive_private_key(int.from_bytes(k, "big"), crv).public_key().public_bytes(serialization.Encoding.X962, fmt)

seed = seed_of(MNEMONIC)
alice = mangle("alice@atlanta.com")
cases = [
    ("sshDefault", "ed25519", [44|H, 1238|H, 0|H, 0|H, 0|H]),
    ("sshAlice", "ed25519", [44|H, 1238|H, alice|H, 0|H, 0|H]),
    ("openpgpAliceCertification", "ed25519", [44|H, 1239|H, alice|H, 0|H, 0|H]),
    ("openpgpAliceSigning", "ed25519", [44|H, 1239|H, alice|H, 1|H, 0|H]),
    ("mlsAliceSigning", "ed25519", [44|H, 1242|H, alice|H, 0|H, 0|H]),
    ("x509AliceTlsClient", "p256", [44|H, 1240|H, alice|H, 2|H, 0|H]),
    ("nostrDefault", "k1", [44|H, 1237|H, 0|H, 0|H, 0|H]),
]
for name, curve, path in cases:
    k, c = derive(curve, seed, path)
    print(name, curve, k.hex(), pub(curve, k).hex(), c.hex())
