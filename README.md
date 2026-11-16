# Cryptography-Phase3
## Output:
'''
Percobaan 1
Alice kirim pesan, penyerang membaca: halo bob, ini rahasia

Percobaan 2
Serangan 1 (ganti kunci DH Bob), tanda tangan lolos? False
Serangan 2 (sertifikat bob buatan sendiri), sertifikat lolos? False
Serangan 3 (sertifikat asli atas nama mallory), lolos sebagai bob? False
Tanpa gangguan, sertifikat bob lolos? True | tanda tangan bob lolos? True
Bob mengecek alice, sertifikat lolos? True | tanda tangan lolos? True
Kunci sesi Alice dan Bob sama? True

Percobaan 3
Bob membaca: halo bob, ini rahasia
Satu bit diubah di jalan, hasil dekripsi: None
'''
