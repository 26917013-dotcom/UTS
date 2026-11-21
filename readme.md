# Digital Forensics Recovery Tool

Tool ini adalah program *file carver* sederhana yang dibuat menggunakan Python 3.x tanpa menggunakan *library* forensik pihak ketiga (seperti Foremost, Scalpel, dll). Tool ini memindai file *image* (contoh: `evidence.img`) untuk mencari *magic bytes* (file signature) dan mengekstrak file yang ditemukan ke dalam direktori `recovered/`.

## Prasyarat
- Python 3.x (disarankan 3.6 ke atas).
- Tidak memerlukan instalasi package tambahan (hanya menggunakan standard library bawaan Python: `os`, `sys`, `hashlib`, `json`, `datetime`).

## Cara Menjalankan Tool
1. Buka terminal atau command prompt.
2. Pastikan Anda berada di direktori yang sama dengan `recovery_tool.py` dan file `evidence.img`.
3. Jalankan perintah berikut:
   ```bash
   python3 recovery_tool.py evidence.img