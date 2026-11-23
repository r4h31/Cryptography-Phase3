import secrets
from math import gcd
from Crypto.PublicKey import RSA, ECC
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Signature import eddsa
from Crypto.Hash import SHA256


def hash_ke_angka(data):
    return int.from_bytes(SHA256.new(data).digest(), "big")

def tanda_tangan(kunci_privat, data):
    return eddsa.new(kunci_privat, "rfc8032").sign(data)

def cek_tanda_tangan(kunci_publik, data, tt):
    try:  
        eddsa.new(kunci_publik, "rfc8032").verify(data, tt)
        return True 
    except ValueError:
        return False


# Persiapan sebelum voting
ea_rsa = RSA.generate(2048)
N = ea_rsa.n 
e = ea_rsa.e 
d = ea_rsa.d 

ea_ed = ECC.generate(curve="Ed25519")
ea_ed_publik_di_aplikasi = ea_ed.public_key()

kunci_pemilu = RSA.generate(2048)
kunci_pemilu_publik = kunci_pemilu.publickey().export_key()
ttd_kunci_pemilu = tanda_tangan(ea_ed, kunci_pemilu_publik)

kunci_id = {}  
terdaftar = {} 
for nama in ["andi", "budi", "citra", "dewi", "eka"]:
    kunci_id[nama] = ECC.generate(curve="Ed25519")  
    terdaftar[nama] = kunci_id[nama].public_key() 

sudah_minta = {} 
log_ea = []  
kotak_suara = []  
papan_publik = []  


# Langkah protokol
def pemilih_siapkan_suara(nama, pilihan, kunci_pemilu_diterima, ttd_diterima, kunci_ea_di_aplikasi):
    if not cek_tanda_tangan(kunci_ea_di_aplikasi, kunci_pemilu_diterima, ttd_diterima):
        return None 
    nonce = secrets.token_hex(16)
    isi = (pilihan + "|" + nonce).encode() 
    kunci_pemilu_obj = RSA.import_key(kunci_pemilu_diterima)
    kunci_enkripsi = PKCS1_OAEP.new(kunci_pemilu_obj, hashAlgo=SHA256) 
    B = kunci_enkripsi.encrypt(isi)  
    h = hash_ke_angka(B) 
    k = secrets.randbelow(N - 2) + 2 
    while gcd(k, N) != 1: 
        k = secrets.randbelow(N - 2) + 2
    h_buta = (h * pow(k, e, N)) % N 
    data_ttd = h_buta.to_bytes(256, "big") 
    ttd_pemilih = tanda_tangan(kunci_id[nama], data_ttd)  
    return B, k, h_buta, ttd_pemilih

def ea_tanda_tangan_buta(nama, h_buta, ttd_pemilih):
    if nama not in terdaftar:  
        return None, "DITOLAK: pemilih tidak terdaftar"
    data_ttd = h_buta.to_bytes(256, "big") 
    if not cek_tanda_tangan(terdaftar[nama], data_ttd, ttd_pemilih):
        return None, "DITOLAK: tanda tangan pemilih tidak sah"
    if nama in sudah_minta: 
        return None, "DITOLAK: pemilih sudah pernah meminta"
    s_buta = pow(h_buta, d, N)  
    sudah_minta[nama] = True 
    log_ea.append(h_buta) 
    return s_buta, "DITERIMA"

def pemilih_buka_kebutaan(s_buta, k):
    return (s_buta * pow(k, -1, N)) % N  

def ballot_box_terima(B, s):
    if pow(s, e, N) != hash_ke_angka(B): 
        return "DITOLAK: tanda tangan EA tidak sah"
    if B in kotak_suara:  
        return "DITOLAK: suara kembar"
    kotak_suara.append(B) 
    papan_publik.append(SHA256.new(B).hexdigest()) 
    return "DITERIMA"

def tallier_hitung(kunci_pemilu_privat):
    hasil = {}  
    pembuka = PKCS1_OAEP.new(kunci_pemilu_privat, hashAlgo=SHA256)  
    for B in kotak_suara: 
        isi = pembuka.decrypt(B).decode()                                    
        pilihan = isi.split("|")[0] 
        if pilihan in hasil:
            hasil[pilihan] = hasil[pilihan] + 1  
        else:
            hasil[pilihan] = 1  
    return hasil


# Percobaan 1: pemilih terdaftar memberi suara
print("Percobaan 1")
pilihan_pemilih = {"andi": "Rina", "budi": "Dimas", "citra": "Rina", "dewi": "Rina", "eka": "Dimas"}
suara_terkirim = {}  
for nama in pilihan_pemilih:
    B, k, h_buta, ttd_pemilih = pemilih_siapkan_suara(nama, pilihan_pemilih[nama], kunci_pemilu_publik, ttd_kunci_pemilu, ea_ed_publik_di_aplikasi)
    s_buta, alasan = ea_tanda_tangan_buta(nama, h_buta, ttd_pemilih) 
    s = pemilih_buka_kebutaan(s_buta, k)  
    suara_terkirim[nama] = (B, s)
    print(nama, "-> EA:", alasan, "| Ballot Box:", ballot_box_terima(B, s)) 


# Percobaan 2: apakah EA bisa menghubungkan suara ke pemilih?
print("\nPercobaan 2")
cocok = 0
for h_buta_ea in log_ea: 
    for B in kotak_suara: 
        if hash_ke_angka(B) == h_buta_ea:  
            cocok = cocok + 1
print("Jumlah permintaan yang dilihat EA:", len(log_ea))
print("Jumlah suara di Ballot Box:", len(kotak_suara))
print("Jumlah kecocokan antara h_buta (EA) dan hash suara:", cocok)


# Percobaan 3: serangan Eve dan kasus penolakan
print("\nPercobaan 3")

# 3a. Eve mengganti kunci pemilu dengan miliknya, tanda tangan EA yang asli dibiarkan
kunci_eve = RSA.generate(2048)
hasil = pemilih_siapkan_suara("andi", "Rina", kunci_eve.publickey().export_key(), ttd_kunci_pemilu, ea_ed_publik_di_aplikasi)
print("3a. Kunci pemilu diganti Eve, pemilih lanjut memilih?", hasil is not None)

# 3b. Eve mengubah satu bit pada suara B
B_asli, s_asli = suara_terkirim["andi"]
B_rusak = bytes([B_asli[0] ^ 1]) + B_asli[1:] 
print("3b. Satu bit B diubah:", ballot_box_terima(B_rusak, s_asli))

# 3c. Pemilih yang sama meminta tanda tangan dua kali
B2, k2, h_buta2, ttd2 = pemilih_siapkan_suara("andi", "Dimas", kunci_pemilu_publik, ttd_kunci_pemilu, ea_ed_publik_di_aplikasi)
print("3c. Pemilih yang sama meminta lagi:", ea_tanda_tangan_buta("andi", h_buta2, ttd2)[1])

# 3d. Suara yang sama dikirim dua kali (replay)
print("3d. Suara yang sama dikirim lagi:", ballot_box_terima(B_asli, s_asli))

# 3e. Tanda tangan EA dipalsukan Eve dengan kunci RSA miliknya
eve_rsa = RSA.generate(2048)
B_palsu = secrets.token_bytes(64)
s_palsu = pow(hash_ke_angka(B_palsu), eve_rsa.d, eve_rsa.n)  
print("3e. Tanda tangan EA dipalsukan:", ballot_box_terima(B_palsu, s_palsu))

# 3f. Pemilih yang tidak terdaftar meminta tanda tangan
kunci_id["eve"] = ECC.generate(curve="Ed25519")
B3, k3, h_buta3, ttd3 = pemilih_siapkan_suara("eve", "Dimas", kunci_pemilu_publik, ttd_kunci_pemilu, ea_ed_publik_di_aplikasi)
print("3f. Pemilih tidak terdaftar meminta:", ea_tanda_tangan_buta("eve", h_buta3, ttd3)[1])


# Percobaan 4: voting ditutup, Tallier menghitung
print("\nPercobaan 4")
print("Hasil penghitungan:", tallier_hitung(kunci_pemilu))
print("Jumlah hash di papan publik:", len(papan_publik))


# Percobaan 5: batas jaminan, kunci publik EA di aplikasi diganti
print("\nPercobaan 5")
eve_ed = ECC.generate(curve="Ed25519")
ttd_eve = tanda_tangan(eve_ed, kunci_eve.publickey().export_key())
aplikasi_palsu = eve_ed.public_key()
hasil = pemilih_siapkan_suara("andi", "Rina", kunci_eve.publickey().export_key(), ttd_eve, aplikasi_palsu)
print("Aplikasi palsu, pemilih mengunci suara ke kunci Eve?", hasil is not None)
