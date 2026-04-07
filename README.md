# PQC Nagagold Input (Tambah Barang)

Demo website untuk input barang dengan:
- Enkripsi ala NAGAGOLD
- PQC KEM (ML-KEM-768) untuk wrapping
- PQC Signature (ML-DSA-65) untuk integritas

## Struktur
- `server/` Express API
- `client/` Vite + React

## Prasyarat
- Node.js **22.x** (dibutuhkan oleh `@oqs/liboqs-js`)
- MongoDB accessible
- `MASTER_KEY` base64 32 bytes untuk melindungi keystore

## Menjalankan

### 1) Backend
```bash
cd /Users/aandiyanti/Documents/RnD/pqc/pqc-nagagold-input/server
npm install
npm run dev
```

Pastikan `.env` sudah terisi. Contoh ada di `.env.example`.
`MASTER_KEY` wajib diisi (base64 32 bytes).

### 2) Frontend
```bash
cd /Users/aandiyanti/Documents/RnD/pqc/pqc-nagagold-input/client
npm install
npm run dev
```

Buka `http://localhost:5173`.

## Output
Setelah submit, UI akan menampilkan dokumen yang tersimpan, termasuk:
- `payload_ng` (terenkripsi ala NAGAGOLD)
- `payload_pqc` (AES-GCM + shared secret KEM)
- `kem` dan `signature` metadata

## Endpoint Tambahan
- `GET /api/items/:id/decrypt` → menampilkan payload plaintext (admin/demo)
- `PATCH /api/items/:id` → update field, server decrypt → edit → encrypt ulang

## Catatan
- Kunci PQC masih in-memory (demo).
- Data disimpan ke koleksi `items_encrypted`.
# wip-pqc
