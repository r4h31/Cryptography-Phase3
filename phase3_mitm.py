from Crypto.PublicKey import ECC
from Crypto.Protocol.DH import key_agreement
from Crypto.Protocol.KDF import HKDF
from Crypto.Signature import eddsa
from Crypto.Hash import SHA256
from Crypto.Cipher import AES


def mentah(kunci_publik):
    return kunci_publik.export_key(format="raw")

def tanda_tangan(kunci_privat, data):
    return eddsa.new(kunci_privat, "rfc8032").sign(data)

def cek_tanda_tangan(kunci_publik, data, tt):
    try:
        eddsa.new(kunci_publik, "rfc8032").verify(data, tt)
        return True
    except ValueError:
        return False

def buat_sertifikat(kunci_ca, nama, kunci_identitas_publik):
    return tanda_tangan(kunci_ca, nama.encode() + mentah(kunci_identitas_publik))

def cek_sertifikat(ca_publik, nama, kunci_identitas_publik, sertifikat):
    return cek_tanda_tangan(ca_publik, nama.encode() + mentah(kunci_identitas_publik), sertifikat)

def hitung_rahasia(dh_privat, dh_publik_lawan):
    def tanpa_kdf(x):
        return x
    return key_agreement(static_priv=dh_privat, static_pub=dh_publik_lawan, kdf=tanpa_kdf)

def buat_kunci_sesi(rahasia, a_mentah, b_mentah):
    salt = SHA256.new(a_mentah + b_mentah).digest()
    return HKDF(rahasia, 32, salt, SHA256, context=b"secure-chat-v1")

def enkripsi(kunci_sesi, nomor, pesan):
    nonce = nomor.to_bytes(12, "big")
    mesin = AES.new(kunci_sesi, AES.MODE_GCM, nonce=nonce)
    return mesin.encrypt_and_digest(pesan.encode())

def dekripsi(kunci_sesi, nomor, ciphertext, tag):
    nonce = nomor.to_bytes(12, "big")
    mesin = AES.new(kunci_sesi, AES.MODE_GCM, nonce=nonce)
    try:
        return mesin.decrypt_and_verify(ciphertext, tag).decode()
    except ValueError:
        return None


# Persiapan: CA dan dua pengguna mendaftar
ca_kunci = ECC.generate(curve="Ed25519")
ca_publik = ca_kunci.public_key()          # tertanam di aplikasi

alice_id = ECC.generate(curve="Ed25519")
bob_id = ECC.generate(curve="Ed25519")
sertifikat_alice = buat_sertifikat(ca_kunci, "alice", alice_id.public_key())
sertifikat_bob = buat_sertifikat(ca_kunci, "bob", bob_id.public_key())

pesan_asli = "halo bob, ini rahasia"


# Percobaan 1: DH biasa tanpa autentikasi, dengan penyerang di tengah
print("Percobaan 1")
a_dh = ECC.generate(curve="Curve25519")
b_dh = ECC.generate(curve="Curve25519")
m1_dh = ECC.generate(curve="Curve25519")    # kunci penyerang untuk Bob
m2_dh = ECC.generate(curve="Curve25519")    # kunci penyerang untuk Alice

# Alice mengira m2 adalah milik Bob, Bob mengira m1 adalah milik Alice
kunci_alice = buat_kunci_sesi(hitung_rahasia(a_dh, m2_dh.public_key()), mentah(a_dh.public_key()), mentah(m2_dh.public_key()))
kunci_bob = buat_kunci_sesi(hitung_rahasia(b_dh, m1_dh.public_key()), mentah(m1_dh.public_key()), mentah(b_dh.public_key()))

# Penyerang menghitung kedua kunci itu juga
kunci_m_alice = buat_kunci_sesi(hitung_rahasia(m2_dh, a_dh.public_key()), mentah(a_dh.public_key()), mentah(m2_dh.public_key()))

ct, tag = enkripsi(kunci_alice, 1, pesan_asli)
terbaca = dekripsi(kunci_m_alice, 1, ct, tag)
print("Alice kirim pesan, penyerang membaca:", terbaca)


# Percobaan 2: rancangan kita, DH ditandatangani dan sertifikat dicek
print("\nPercobaan 2")
a_dh = ECC.generate(curve="Curve25519")
b_dh = ECC.generate(curve="Curve25519")
a_raw = mentah(a_dh.public_key())
b_raw = mentah(b_dh.public_key())

# pesan 2 dari Bob: b_dh, sertifikat_bob, tanda tangan atas (B + b_dh + a_dh)
tt_bob = tanda_tangan(bob_id, b"B" + b_raw + a_raw)

# serangan 1: penyerang mengganti b_dh dengan miliknya, tanda tangan Bob dibiarkan
m_dh = ECC.generate(curve="Curve25519")
m_raw = mentah(m_dh.public_key())
ok = cek_tanda_tangan(bob_id.public_key(), b"B" + m_raw + a_raw, tt_bob)
print("Serangan 1 (ganti kunci DH Bob), tanda tangan lolos?", ok)

# serangan 2: penyerang pakai kunci identitas sendiri dan mengaku sebagai bob
m_id = ECC.generate(curve="Ed25519")
sertifikat_palsu = tanda_tangan(m_id, b"bob" + mentah(m_id.public_key()))
ok = cek_sertifikat(ca_publik, "bob", m_id.public_key(), sertifikat_palsu)
print("Serangan 2 (sertifikat bob buatan sendiri), sertifikat lolos?", ok)

# serangan 3: penyerang pakai sertifikat asli miliknya, tapi namanya bukan bob
sertifikat_m = buat_sertifikat(ca_kunci, "mallory", m_id.public_key())
ok = cek_sertifikat(ca_publik, "bob", m_id.public_key(), sertifikat_m)
print("Serangan 3 (sertifikat asli atas nama mallory), lolos sebagai bob?", ok)

# tanpa gangguan: Alice mengecek pesan 2 dari Bob
ok_cert = cek_sertifikat(ca_publik, "bob", bob_id.public_key(), sertifikat_bob)
ok_tt = cek_tanda_tangan(bob_id.public_key(), b"B" + b_raw + a_raw, tt_bob)
print("Tanpa gangguan, sertifikat bob lolos?", ok_cert, "| tanda tangan bob lolos?", ok_tt)

# pesan 3 dari Alice: sertifikat_alice, tanda tangan atas (A + a_dh + b_dh)
tt_alice = tanda_tangan(alice_id, b"A" + a_raw + b_raw)
ok_cert = cek_sertifikat(ca_publik, "alice", alice_id.public_key(), sertifikat_alice)
ok_tt = cek_tanda_tangan(alice_id.public_key(), b"A" + a_raw + b_raw, tt_alice)
print("Bob mengecek alice, sertifikat lolos?", ok_cert, "| tanda tangan lolos?", ok_tt)

# kedua pihak menurunkan kunci sesi
kunci_alice = buat_kunci_sesi(hitung_rahasia(a_dh, b_dh.public_key()), a_raw, b_raw)
kunci_bob = buat_kunci_sesi(hitung_rahasia(b_dh, a_dh.public_key()), a_raw, b_raw)
print("Kunci sesi Alice dan Bob sama?", kunci_alice == kunci_bob)


# Percobaan 3: pesan setelah handshake
print("\nPercobaan 3")
ct, tag = enkripsi(kunci_alice, 1, pesan_asli)
print("Bob membaca:", dekripsi(kunci_bob, 1, ct, tag))

ct_rusak = bytearray(ct)
ct_rusak[0] = ct_rusak[0] ^ 1
print("Satu bit diubah di jalan, hasil dekripsi:", dekripsi(kunci_bob, 1, bytes(ct_rusak), tag))