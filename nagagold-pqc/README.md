# nagagold-pqc

Library helper untuk enkripsi per-field menggunakan PQC (ML-KEM-768) + AES-GCM.

## Instalasi (lokal)
Di project lain:
```bash
npm install /path/ke/nagagold-pqc
```

## Instalasi (publish ke npm)
```bash
npm install nagagold-pqc
```

## API Node.js
```js
import { createNodePqc } from "nagagold-pqc";

const pqc = await createNodePqc({
  masterKey: process.env.MASTER_KEY, // base64 32 bytes
  keystorePath: "keys/keystore.enc.json",
  kid: "pqc-default"
});

const encValue = pqc.encryptFieldValue("ABC");
const decValue = pqc.decryptFieldValue(encValue);

const { combined } = pqc.encryptText("hello");
const decText = pqc.decryptText({ combined });
```

## API Browser
```js
import { createWebPqc } from "nagagold-pqc";

// keystore harus disediakan dari server (public & secret key base64)
const pqc = await createWebPqc({
  kid: "pqc-default",
  keystore: {
    kemPublicKey: "...",
    kemSecretKey: "..."
  }
});

const encValue = await pqc.encryptFieldValue("ABC");
const decValue = await pqc.decryptFieldValue(encValue);
```

## Format Data Per-Field
Setiap field disimpan sebagai:
```
kem||payload_pqc
```

`kem`:
```
alg|kid|public|kemcipher
```

`payload_pqc`:
```
iv|tag|cipher
```

## Catatan
- Library ini tidak memakai signature.
- Untuk browser, pastikan bundler bisa memuat WASM dari `@oqs/liboqs-js`.
- `MASTER_KEY` wajib base64 32 bytes (gunakan `openssl rand -base64 32`).
- Disarankan Node.js >= 22 untuk kompatibilitas `@oqs/liboqs-js`.
