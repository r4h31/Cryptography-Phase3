# Cryptography-Phase3 (MITM)
## Output:
```
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
```

# Cryptography-Phase3 (Voting)
## Output:
```
Percobaan 1
andi -> EA: DITERIMA | Ballot Box: DITERIMA
budi -> EA: DITERIMA | Ballot Box: DITERIMA
citra -> EA: DITERIMA | Ballot Box: DITERIMA
dewi -> EA: DITERIMA | Ballot Box: DITERIMA
eka -> EA: DITERIMA | Ballot Box: DITERIMA

Percobaan 2
Jumlah permintaan yang dilihat EA: 5
Jumlah suara di Ballot Box: 5
Jumlah kecocokan antara h_buta (EA) dan hash suara: 0

Percobaan 3
3a. Kunci pemilu diganti Eve, pemilih lanjut memilih? False
3b. Satu bit B diubah: DITOLAK: tanda tangan EA tidak sah
3c. Pemilih yang sama meminta lagi: DITOLAK: pemilih sudah pernah meminta
3d. Suara yang sama dikirim lagi: DITOLAK: suara kembar
3e. Tanda tangan EA dipalsukan: DITOLAK: tanda tangan EA tidak sah
3f. Pemilih tidak terdaftar meminta: DITOLAK: pemilih tidak terdaftar

Percobaan 4
Hasil penghitungan: {'Rina': 3, 'Dimas': 2}
Jumlah hash di papan publik: 5

Percobaan 5
Aplikasi palsu, pemilih mengunci suara ke kunci Eve? True
```
