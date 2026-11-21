import os
import sys
import hashlib
import json
from datetime import datetime

# Definisi signature (magic bytes) untuk file-file yang dicari
# Menggunakan struktur: format_name -> {header, footer, extension}
SIGNATURES = {
    "JPEG": {
        "header": b"\xFF\xD8\xFF",
        "footer": b"\xFF\xD9",
        "ext": ".jpg"
    },
    "PDF": {
        "header": b"\x25\x50\x44\x46",
        "footer": b"\x25\x25\x45\x4F\x46", # %%EOF
        "ext": ".pdf"
    },
    "ELF": {
        "header": b"\x7F\x45\x4C\x46",
        "footer": None, # ELF tidak memiliki footer yang pasti
        "ext": ".elf"
    },
    "ZIP": {
        "header": b"\x50\x4B\x03\x04",
        "footer": b"\x50\x4B\x05\x06", # End of central directory signature
        "ext": ".zip"
    },
    "PNG": {
        "header": b"\x89\x50\x4E\x47",
        "footer": b"\x49\x45\x4E\x44\xAE\x42\x60\x82", # IEND chunk
        "ext": ".png"
    },
    "PE/MZ": {
        "header": b"\x4D\x5A",
        "footer": None, # PE/MZ bergantung pada struktur internal, tidak ada footer statis
        "ext": ".exe"
    }
}

def scan_file(data):
    """
    Memindai data biner untuk menemukan lokasi (offset) dari file signature.
    
    Args:
        data (bytes): Konten biner dari file image.
        
    Returns:
        list: Daftar dictionary yang berisi informasi signature yang ditemukan, 
              diurutkan berdasarkan offset dari awal hingga akhir.
    """
    findings = []
    
    for fmt, sig_info in SIGNATURES.items():
        header = sig_info["header"]
        offset = data.find(header)
        
        while offset != -1:
            findings.append({
                "format": fmt,
                "offset": offset,
                "header": header
            })
            # Lanjut mencari signature yang sama di offset berikutnya
            offset = data.find(header, offset + 1)
            
    # Mengurutkan hasil temuan berdasarkan offset (dari offset terkecil/awal file)
    findings.sort(key=lambda x: x["offset"])
    return findings

def print_scan_results(findings, data):
    """
    Mencetak hasil pemindaian signature ke layar sesuai dengan format contoh soal.
    
    Args:
        findings (list): Daftar temuan signature.
        data (bytes): Konten biner asli untuk mengekstrak byte hex.
    """
    print("=== FILE SIGNATURE SCAN RESULTS ===")
    print(f"{'Offset':<12} {'Hex Signature':<20} {'Format':<10} {'Confidence'}")
    
    for f in findings:
        offset = f['offset']
        # Mengambil 4 byte dari file image untuk ditampilkan di kolom Hex Signature
        sig_bytes = data[offset:offset+4]
        hex_sig = ' '.join([f"{b:02X}" for b in sig_bytes])
        
        print(f"0x{offset:08X}  {hex_sig:<20} {f['format']:<10} HIGH")
        
    print("...")
    print(f"Total ditemukan: {len(findings)} signature(s)")

def carve_files(data, findings, output_dir="recovered"):
    """
    Mengekstrak (carving) file dari data image berdasarkan header dan footer.
    Jika tidak memiliki footer, akan dipotong hingga header file berikutnya.
    
    Args:
        data (bytes): Konten biner dari file image.
        findings (list): Daftar temuan signature yang sudah diurutkan.
        output_dir (str): Folder tujuan penyimpanan file hasil ekstraksi.
        
    Returns:
        list: List berisi metadata file yang berhasil diekstrak (untuk JSON).
    """
    if not os.path.exists(output_dir):
        os.makedirs(output_dir)
        
    carved_files_info = []
    
    for i, finding in enumerate(findings):
        fmt = finding['format']
        start_offset = finding['offset']
        footer = SIGNATURES[fmt]["footer"]
        ext = SIGNATURES[fmt]["ext"]
        
        # Batas pencarian maksimal untuk footer (mulai dari file ini hingga awal file selanjutnya)
        next_offset = findings[i+1]['offset'] if i + 1 < len(findings) else len(data)
        end_offset = -1
        
        if footer:
            # Cari footer di antara start_offset dan next_offset
            footer_idx = data.find(footer, start_offset + len(SIGNATURES[fmt]["header"]), next_offset)
            
            if footer_idx != -1:
                if fmt == "ZIP":
                    # Khusus ZIP, End of Central Directory record panjang minimalnya 22 bytes
                    end_offset = footer_idx + 22 
                else:
                    end_offset = footer_idx + len(footer)
            else:
                # Jika tidak ditemukan footernya, carve sampai header berikutnya
                end_offset = next_offset
        else:
            # File tipe tanpa footer statis (contoh: ELF, PE) dipotong pada awal file selanjutnya
            end_offset = next_offset
                
        file_size = end_offset - start_offset
        file_data = data[start_offset:end_offset]
        
        filename = f"file_{i+1:03d}{ext}"
        filepath_sys = os.path.join(output_dir, filename)
        filepath_json = f"{output_dir}/{filename}" # Format string untuk JSON (menggunakan slash biasa)
        
        # Simpan file ke direktori recovered/
        with open(filepath_sys, "wb") as f:
            f.write(file_data)
            
        # Hitung Hash SHA256 dari file yang diekstrak
        sha256_hash = hashlib.sha256(file_data).hexdigest()
        
        carved_files_info.append({
            "id": i + 1,
            "filename": filepath_json,
            "format": fmt,
            "offset_start": start_offset,
            "offset_end": end_offset,
            "size_bytes": file_size,
            "sha256": sha256_hash,
            "status": "OK"
        })
        
    return carved_files_info

def generate_json_report(image_path, image_size, carved_files_info):
    """
    Menghasilkan file log berformat JSON sesuai dengan struktur pada soal.
    
    Args:
        image_path (str): Path file image bukti.
        image_size (int): Ukuran file image asli.
        carved_files_info (list): Data log file yang di-carving.
    """
    report = {
        "scan_info": {
            "image_path": image_path,
            "image_size": image_size,
            "scan_timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "tool_version": "1.0"
        },
        "carved_files": carved_files_info
    }
    
    with open("findings.json", "w") as f:
        json.dump(report, f, indent=4)
    print("\n[+] Laporan JSON berhasil dibuat di findings.json")

def main():
    """
    Fungsi utama (entry point) untuk menjalankan tool forensik secara programatik.
    """
    # Validasi argument saat eksekusi CLI
    if len(sys.argv) < 2:
        print("Penggunaan: python3 recovery_tool.py <evidence.img>")
        sys.exit(1)
        
    image_path = sys.argv[1]
    
    if not os.path.exists(image_path):
        print(f"Error: File '{image_path}' tidak ditemukan.")
        sys.exit(1)
        
    print(f"[*] Membaca file image: {image_path}...")
    with open(image_path, "rb") as f:
        data = f.read()
    image_size = len(data)
    
    print("[*] Memulai pemindaian file signature...\n")
    findings = scan_file(data)
    
    if not findings:
        print("[-] Tidak ditemukan file signature yang dikenali.")
        sys.exit(0)
        
    # [Tugas 4] Cetak hasil scanner
    print_scan_results(findings, data)
    
    # [Tugas 5] Lakukan carving 
    print("\n[*] Memulai proses data carving...")
    carved_files_info = carve_files(data, findings)
    print(f"[+] Berhasil mengekstrak {len(carved_files_info)} file ke folder 'recovered/'.")
    
    # [Tugas Bonus] Buat findings.json
    generate_json_report(image_path, image_size, carved_files_info)
    print("[*] Proses recovery selesai.")

if __name__ == "__main__":
    main()