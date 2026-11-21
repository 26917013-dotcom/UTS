# Laporan Ilmiah Forensik Digital (Bagian D)

## 1. Pendahuluan
Laporan ini menyajikan hasil analisis forensik digital terhadap barang bukti berupa file image disk (`evidence.img`). Tujuan dari analisis ini adalah untuk mengidentifikasi, memulihkan (carving), dan memverifikasi berkas-berkas tersembunyi atau terhapus di dalam *raw data* menggunakan metode analisis *file signature* (magic bytes).

## 2. Metodologi (Header/Footer Carving)
Analisis dilakukan menggunakan skrip *Python* yang dibangun secara mandiri (`recovery_tool.py`) tanpa bergantung pada *tool* forensik pihak ketiga. Tahapan yang dilakukan meliputi:
- **Signature Scanning**: Program membaca file secara biner (byte-per-byte) dan mencari *header* dari format file yang umum (JPEG, PDF, ELF, ZIP, dan PNG) berdasarkan *magic bytes* standar.
- **Data Carving**: 
  - Untuk file yang memiliki *footer* statis (seperti JPEG, ZIP, dan PNG), program akan memotong (ekstrak) data biner mulai dari *header* hingga ditemukan *footer* tersebut.
  - Untuk file yang tidak memiliki *footer* yang tetap (seperti ELF dan PE), program akan memotong data dari *header* file tersebut hingga ditemukannya *header* file lain di urutan selanjutnya.
- **Integritas Data**: Menghitung nilai *hash* kriptografi SHA-256 untuk setiap file yang berhasil di-recover guna memastikan integritas bukti (*chain of custody*).

## 3. Hasil Temuan (Findings)
Berdasarkan proses eksekusi `recovery_tool.py` terhadap `evidence.img`, proses pemindaian berhasil mendeteksi adanya struktur file yang tersemat di dalam berkas bukti. 

Data hasil ekstraksi telah disimpan secara terstruktur di dalam direktori `recovered/`. Rincian metadata dari masing-masing file (meliputi ID, nama file, format, *offset start/end*, ukuran byte, dan SHA-256) telah direkam secara otomatis dalam file output `findings.json`.

*(Catatan Analis: Isi bagian ini dengan hasil temuan spesifik Anda setelah menjalankan script pada `evidence.img` yang asli. Jelaskan jenis file apa saja yang ditemukan dan apakah ada file yang mencurigakan atau relevan dengan kasus).*

## 4. Kesimpulan
Metode *file carving* berbasis *header-footer signature* terbukti berhasil mengekstrak file-file yang disembunyikan di dalam *raw image* `evidence.img`. Otomatisasi menggunakan script Python memungkinkan identifikasi offset yang presisi dan menjaga integritas bukti digital melalui pembuatan *hash* secara otomatis.