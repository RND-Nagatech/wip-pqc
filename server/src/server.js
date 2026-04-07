import express from "express";
import cors from "cors";
import dotenv from "dotenv";
import crypto from "crypto";
import fs from "fs";
import path from "path";
import { MongoClient, ObjectId } from "mongodb";

dotenv.config();

const PORT = Number(process.env.PORT || 5174);
const MONGODB_URI = process.env.MONGODB_URI;
const NG_ENC_KEY = process.env.NG_ENC_KEY;
const PQC_KID = process.env.PQC_KID;
const KEYSTORE_PATH = process.env.KEYSTORE_PATH || "keys/keystore.enc.json";
const MASTER_KEY = process.env.MASTER_KEY || "";

if (!MONGODB_URI) {
  throw new Error("MONGODB_URI is required in server/.env");
}

const app = express();
app.use(cors());
app.use(express.json({ limit: "2mb" }));

const FIELDS_ENCRYPTED = ["kode_group", "kode_jenis", "nama_barang", "berat", "nama_atribut", "berat_atribut"];
const FIELDS_PLAIN = [];

let mongoClient;
let mongoDb;
let pqcInitPromise;
let keystoreCache = null;

function encryptAscii(str, key) {
  const dataKey = {};
  for (let i = 0; i < key.length; i++) {
    dataKey[i] = key.substr(i, 1);
  }

  let strEnc = "";
  let nkey = 0;
  const jml = str.length;

  for (let i = 0; i < parseInt(jml, 10); i++) {
    const code = str.charCodeAt(i) + dataKey[nkey].charCodeAt(0);
    strEnc = strEnc + code.toString(16);
    if (nkey === Object.keys(dataKey).length - 1) {
      nkey = 0;
    }
    nkey = nkey + 1;
  }

  return strEnc.toUpperCase();
}

function decryptAscii(str, key) {
  if (!str) return "";
  const dataKey = {};
  for (let i = 0; i < key.length; i++) {
    dataKey[i] = key.substr(i, 1);
  }

  let strDec = "";
  let nkey = 0;
  let i = 0;
  while (i < str.length) {
    const hex = str.substr(i, 2);
    const code = parseInt(hex, 16) - dataKey[nkey].charCodeAt(0);
    strDec = strDec + String.fromCharCode(code);
    if (nkey === Object.keys(dataKey).length - 1) {
      nkey = 0;
    }
    nkey = nkey + 1;
    i = i + 2;
  }
  return strDec;
}

function encryptNagagoldPayload(payload, key) {
  const result = {};
  for (const [k, v] of Object.entries(payload)) {
    const str = v === null || v === undefined ? "" : String(v);
    result[k] = encryptAscii(str, key);
  }
  return result;
}

function toUint8(value) {
  if (value instanceof Uint8Array && value.constructor?.name === "Uint8Array") return value;
  if (Buffer.isBuffer(value)) return Uint8Array.from(value);
  if (value instanceof ArrayBuffer) return new Uint8Array(value);
  if (Array.isArray(value)) return Uint8Array.from(value);
  return Uint8Array.from(value || []);
}

function decryptNagagoldPayload(payload, key) {
  const result = {};
  for (const [k, v] of Object.entries(payload || {})) {
    result[k] = decryptAscii(String(v || ""), key);
  }
  return result;
}

function isHexLike(value) {
  if (typeof value !== "string" || value.length === 0) return false;
  if (value.length % 2 !== 0) return false;
  return /^[0-9A-F]+$/.test(value);
}

function shouldNagagoldDecrypt(obj) {
  if (!obj || typeof obj !== "object") return false;
  const values = Object.values(obj);
  if (values.length === 0) return false;
  return values.every((v) => isHexLike(String(v || "")));
}

function ensureDir(filePath) {
  const dir = path.dirname(filePath);
  if (!fs.existsSync(dir)) {
    fs.mkdirSync(dir, { recursive: true });
  }
}

function loadMasterKey() {
  if (!MASTER_KEY) {
    throw new Error("MASTER_KEY is required in server/.env to protect keystore");
  }
  const key = Buffer.from(MASTER_KEY, "base64");
  if (key.length !== 32) {
    throw new Error("MASTER_KEY must be base64 of 32 bytes");
  }
  return key;
}

function encryptKeystore(data, key) {
  const iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv("aes-256-gcm", key, iv);
  const plaintext = Buffer.from(JSON.stringify(data), "utf8");
  const ciphertext = Buffer.concat([cipher.update(plaintext), cipher.final()]);
  const tag = cipher.getAuthTag();
  return {
    iv: iv.toString("base64"),
    tag: tag.toString("base64"),
    ciphertext: ciphertext.toString("base64")
  };
}

function decryptKeystore(payload, key) {
  const iv = Buffer.from(payload.iv, "base64");
  const tag = Buffer.from(payload.tag, "base64");
  const ciphertext = Buffer.from(payload.ciphertext, "base64");
  const decipher = crypto.createDecipheriv("aes-256-gcm", key, iv);
  decipher.setAuthTag(tag);
  const plaintext = Buffer.concat([decipher.update(ciphertext), decipher.final()]);
  return JSON.parse(plaintext.toString("utf8"));
}

function normalizeKeystore(store) {
  if (!store) return null;
  if (store.keys && store.currentKid) return store;
  if (store.pqc) {
    const kid = store.kid || PQC_KID || "pqc-default";
    return {
      version: 1,
      currentKid: kid,
      keys: {
        [kid]: {
          createdAt: store.createdAt || new Date().toISOString(),
          ngKey: store.ngKey || NG_ENC_KEY,
          kemPublicKey: store.pqc.kemPublicKey,
          kemSecretKey: store.pqc.kemSecretKey,
          sigPublicKey: store.pqc.sigPublicKey,
          sigSecretKey: store.pqc.sigSecretKey
        }
      }
    };
  }
  return null;
}

function readKeystore() {
  if (keystoreCache) return keystoreCache;
  if (!fs.existsSync(KEYSTORE_PATH)) return null;
  const key = loadMasterKey();
  const raw = JSON.parse(fs.readFileSync(KEYSTORE_PATH, "utf8"));
  const decrypted = decryptKeystore(raw, key);
  const normalized = normalizeKeystore(decrypted);
  if (normalized && JSON.stringify(normalized) !== JSON.stringify(decrypted)) {
    writeKeystore(normalized);
  }
  keystoreCache = normalized;
  return keystoreCache;
}

function writeKeystore(data) {
  const key = loadMasterKey();
  const encrypted = encryptKeystore(data, key);
  ensureDir(KEYSTORE_PATH);
  fs.writeFileSync(KEYSTORE_PATH, JSON.stringify(encrypted, null, 2), "utf8");
  keystoreCache = data;
}

function getKeyEntry(store, kid) {
  if (!store?.keys) return null;
  return store.keys[kid] || null;
}

function getCurrentKid(store) {
  if (store?.currentKid) return store.currentKid;
  if (PQC_KID) return PQC_KID;
  const first = store?.keys ? Object.keys(store.keys)[0] : null;
  return first || "pqc-default";
}

async function initMongo() {
  if (mongoDb) return mongoDb;
  mongoClient = new MongoClient(MONGODB_URI);
  await mongoClient.connect();
  mongoDb = mongoClient.db();
  return mongoDb;
}

async function initPqc() {
  if (!pqcInitPromise) {
    pqcInitPromise = (async () => {
      const { createMLKEM768, createMLDSA65 } = await import("@oqs/liboqs-js");
      const kem = await createMLKEM768();
      const sig = await createMLDSA65();
      const store = readKeystore();

      if (store) {
        let currentKid = getCurrentKid(store);
        let entry = getKeyEntry(store, currentKid);
        if (!entry) {
          const firstKid = store.keys ? Object.keys(store.keys)[0] : null;
          if (firstKid) {
            currentKid = firstKid;
            store.currentKid = currentKid;
            entry = getKeyEntry(store, currentKid);
            writeKeystore(store);
          }
        }
        if (entry) {
          const kemKeys = {
            publicKey: toUint8(Buffer.from(entry.kemPublicKey, "base64")),
            secretKey: toUint8(Buffer.from(entry.kemSecretKey, "base64"))
          };
          const sigKeys = {
            publicKey: toUint8(Buffer.from(entry.sigPublicKey, "base64")),
            secretKey: toUint8(Buffer.from(entry.sigSecretKey, "base64"))
          };
          return { kem, sig, kemKeys, sigKeys, ngKey: entry.ngKey || NG_ENC_KEY, kid: currentKid, store };
        }
      }

      const kemKeys = kem.generateKeyPair();
      const sigKeys = sig.generateKeyPair();

      const newKid = PQC_KID || `pqc-${Date.now()}`;
      const newStore = {
        version: 1,
        currentKid: newKid,
        keys: {
          [newKid]: {
            createdAt: new Date().toISOString(),
            ngKey: NG_ENC_KEY,
            kemPublicKey: Buffer.from(toUint8(kemKeys.publicKey)).toString("base64"),
            kemSecretKey: Buffer.from(toUint8(kemKeys.secretKey)).toString("base64"),
            sigPublicKey: Buffer.from(toUint8(sigKeys.publicKey)).toString("base64"),
            sigSecretKey: Buffer.from(toUint8(sigKeys.secretKey)).toString("base64")
          }
        }
      };
      writeKeystore(newStore);

      return {
        kem,
        sig,
        kemKeys: {
          publicKey: toUint8(kemKeys.publicKey),
          secretKey: toUint8(kemKeys.secretKey)
        },
        sigKeys: {
          publicKey: toUint8(sigKeys.publicKey),
          secretKey: toUint8(sigKeys.secretKey)
        },
        ngKey: NG_ENC_KEY,
        kid: newKid,
        store: newStore
      };
    })();
  }
  return pqcInitPromise;
}

function aesGcmEncrypt(plainText, keyBytes) {
  const iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv("aes-256-gcm", keyBytes, iv);
  const ciphertext = Buffer.concat([cipher.update(plainText), cipher.final()]);
  const tag = cipher.getAuthTag();
  return {
    ciphertext: ciphertext.toString("base64"),
    iv: iv.toString("base64"),
    tag: tag.toString("base64")
  };
}

function aesGcmDecrypt(payload, keyBytes) {
  const iv = Buffer.from(payload.iv, "base64");
  const tag = Buffer.from(payload.tag, "base64");
  const ciphertext = Buffer.from(payload.ciphertext, "base64");
  const decipher = crypto.createDecipheriv("aes-256-gcm", keyBytes, iv);
  decipher.setAuthTag(tag);
  const plaintext = Buffer.concat([decipher.update(ciphertext), decipher.final()]);
  return plaintext.toString("utf8");
}

function encodePayloadPqc(payload) {
  return `${payload.iv}|${payload.tag}|${payload.ciphertext}`;
}

function decodePayloadPqc(value) {
  const parts = String(value || "").split("|");
  if (parts.length !== 3) throw new Error("Invalid payload_pqc format");
  return { iv: parts[0], tag: parts[1], ciphertext: parts[2] };
}

function encodeKem(alg, kid, publicKeyB64, ciphertextB64) {
  return `${alg}|${kid}|${publicKeyB64}|${ciphertextB64}`;
}

function decodeKem(value) {
  const parts = String(value || "").split("|");
  if (parts.length !== 4) throw new Error("Invalid kem format");
  return { alg: parts[0], kid: parts[1], publicKey: parts[2], ciphertext: parts[3] };
}

function encodeFieldValue(kemStr, payloadPqcStr) {
  return `${kemStr}||${payloadPqcStr}`;
}

function decodeFieldValue(value) {
  const [kemPart, payloadPart] = String(value || "").split("||");
  if (!kemPart || !payloadPart) {
    throw new Error("Invalid field format");
  }
  return { kemPart, payloadPart };
}

function pickPatchPayload(body) {
  return {
    ...(body.kode_group !== undefined ? { kode_group: body.kode_group } : {}),
    ...(body.kode_jenis !== undefined ? { kode_jenis: body.kode_jenis } : {}),
    ...(body.nama_barang !== undefined ? { nama_barang: body.nama_barang } : {}),
    ...(body.berat !== undefined ? { berat: body.berat } : {}),
    ...(body.nama_atribut !== undefined ? { nama_atribut: body.nama_atribut } : {}),
    ...(body.berat_atribut !== undefined ? { berat_atribut: body.berat_atribut } : {})
  };
}

async function decryptFieldValue(fieldValue, kem, store) {
  const { kemPart, payloadPart } = decodeFieldValue(fieldValue);
  const kemParsed = decodeKem(kemPart);
  const entry = getKeyEntry(store, kemParsed.kid) || getKeyEntry(store, getCurrentKid(store));
  if (!entry) throw new Error(`Key not found for kid: ${kemParsed.kid}`);
  const kemCiphertext = toUint8(Buffer.from(kemParsed.ciphertext, "base64"));
  const kemSecretKey = toUint8(Buffer.from(entry.kemSecretKey, "base64"));
  const sharedSecret = kem.decapsulate(kemCiphertext, kemSecretKey);
  const payloadPqc = decodePayloadPqc(payloadPart);
  const valueNg = aesGcmDecrypt(payloadPqc, sharedSecret);
  const valuePlain = decryptAscii(valueNg, entry.ngKey || NG_ENC_KEY);
  return valuePlain;
}

async function decryptDocFields(doc, kem, store, fields) {
  const result = {};
  for (const field of fields) {
    if (doc[field] === undefined) continue;
    if (FIELDS_PLAIN.includes(field) && !String(doc[field]).includes("||")) {
      result[field] = doc[field];
      continue;
    }
    result[field] = await decryptFieldValue(doc[field], kem, store);
  }
  return result;
}

app.post("/api/items", async (req, res) => {
  try {
    const body = req.body || {};
    const payload = {
      kode_group: body.kode_group ?? "",
      kode_jenis: body.kode_jenis ?? "",
      nama_barang: body.nama_barang ?? "",
      berat: body.berat ?? "",
      nama_atribut: body.nama_atribut ?? "",
      berat_atribut: body.berat_atribut ?? ""
    };

    const { kem, kemKeys, ngKey, kid } = await initPqc();
    const doc = {
      createdAt: new Date().toISOString()
    };

    for (const [field, value] of Object.entries(payload)) {
      if (FIELDS_PLAIN.includes(field)) {
        doc[field] = value;
        continue;
      }
      const valueNg = encryptAscii(String(value ?? ""), ngKey);
      const kemEnc = kem.encapsulate(toUint8(kemKeys.publicKey));
      const sharedSecret = kemEnc.sharedSecret;
      const kemCiphertext = kemEnc.ciphertext;
      const payloadPqc = aesGcmEncrypt(valueNg, sharedSecret);
      const kemStr = encodeKem(
        "ML-KEM-768",
        kid,
        Buffer.from(kemKeys.publicKey).toString("base64"),
        Buffer.from(kemCiphertext).toString("base64")
      );
      const payloadStr = encodePayloadPqc(payloadPqc);
      doc[field] = encodeFieldValue(kemStr, payloadStr);
    }

    const db = await initMongo();
    const result = await db.collection("items_encrypted").insertOne(doc);

    res.json({
      id: result.insertedId,
      stored: doc
    });
  } catch (err) {
    res.status(500).json({ error: String(err) });
  }
});

app.get("/api/items", async (req, res) => {
  try {
    const limit = Math.min(parseInt(req.query.limit || "20", 10), 100);
    const db = await initMongo();
    const items = await db
      .collection("items_encrypted")
      .find({}, { projection: { kode_group: 1, kode_jenis: 1, nama_barang: 1, berat: 1, nama_atribut: 1, berat_atribut: 1, createdAt: 1 } })
      .sort({ createdAt: -1 })
      .limit(limit)
      .toArray();

    if (String(req.query.view || "") === "plain") {
      const { kem, store } = await initPqc();
      const fields = ["kode_group", "kode_jenis", "nama_barang", "berat", "nama_atribut", "berat_atribut"];
      const result = [];
      for (const item of items) {
        try {
          const payloadPlain = await decryptDocFields(item, kem, store, fields);
          result.push({ id: item._id, createdAt: item.createdAt, payload_plain: payloadPlain });
        } catch (err) {
          result.push({ id: item._id, createdAt: item.createdAt, error: String(err) });
        }
      }
      return res.json(result);
    }

    res.json(
      items.map((item) => ({
        id: item._id,
        createdAt: item.createdAt
      }))
    );
  } catch (err) {
    res.status(500).json({ error: String(err) });
  }
});

app.get("/api/items/:id", async (req, res) => {
  try {
    const db = await initMongo();
    const item = await db.collection("items_encrypted").findOne({ _id: new ObjectId(req.params.id) });
    if (!item) return res.status(404).json({ error: "Not found" });
    res.json(item);
  } catch (err) {
    res.status(500).json({ error: String(err) });
  }
});

app.get("/api/items/:id/decrypt", async (req, res) => {
  try {
    const db = await initMongo();
    const item = await db.collection("items_encrypted").findOne({ _id: new ObjectId(req.params.id) });
    if (!item) return res.status(404).json({ error: "Not found" });

    const { kem, store } = await initPqc();
    const fields = ["kode_group", "kode_jenis", "nama_barang", "berat", "nama_atribut", "berat_atribut"];
    const payloadPlain = await decryptDocFields(item, kem, store, fields);

    res.json({
      id: item._id,
      payload_plain: payloadPlain
    });
  } catch (err) {
    res.status(500).json({ error: String(err) });
  }
});

app.patch("/api/items/:id", async (req, res) => {
  try {
    const patch = pickPatchPayload(req.body || {});
    if (Object.keys(patch).length === 0) {
      return res.status(400).json({ error: "No fields to update" });
    }

    const db = await initMongo();
    const item = await db.collection("items_encrypted").findOne({ _id: new ObjectId(req.params.id) });
    if (!item) return res.status(404).json({ error: "Not found" });

    const { kem, kemKeys, ngKey, kid, store } = await initPqc();
    const fields = ["kode_group", "kode_jenis", "nama_barang", "berat", "nama_atribut", "berat_atribut"];
    const payloadPlain = await decryptDocFields(item, kem, store, fields);

    const updatedPlain = { ...payloadPlain, ...patch };
    const updateDoc = { updatedAt: new Date().toISOString() };

    for (const field of fields) {
      if (FIELDS_PLAIN.includes(field)) {
        updateDoc[field] = updatedPlain[field];
        continue;
      }
      const valueNg = encryptAscii(String(updatedPlain[field] ?? ""), ngKey);
      const kemEnc = kem.encapsulate(toUint8(kemKeys.publicKey));
      const sharedSecret = kemEnc.sharedSecret;
      const kemCiphertext = kemEnc.ciphertext;
      const payloadPqc = aesGcmEncrypt(valueNg, sharedSecret);
      const kemStr = encodeKem(
        "ML-KEM-768",
        kid,
        Buffer.from(kemKeys.publicKey).toString("base64"),
        Buffer.from(kemCiphertext).toString("base64")
      );
      const payloadStr = encodePayloadPqc(payloadPqc);
      updateDoc[field] = encodeFieldValue(kemStr, payloadStr);
    }

    await db.collection("items_encrypted").updateOne(
      { _id: new ObjectId(req.params.id) },
      { $set: updateDoc }
    );

    res.json({
      id: item._id,
      updated: updateDoc
    });
  } catch (err) {
    res.status(500).json({ error: String(err) });
  }
});

app.post("/api/tools/encrypt-text", async (req, res) => {
  try {
    const text = String(req.body?.text || "");
    const { kem, kemKeys, kid } = await initPqc();

    const kemEnc = kem.encapsulate(toUint8(kemKeys.publicKey));
    const sharedSecret = kemEnc.sharedSecret;
    const kemCiphertext = kemEnc.ciphertext;

    const payloadPqc = aesGcmEncrypt(text, sharedSecret);

    const kemStr = encodeKem(
      "ML-KEM-768",
      kid,
      Buffer.from(kemKeys.publicKey).toString("base64"),
      Buffer.from(kemCiphertext).toString("base64")
    );
    const payloadStr = encodePayloadPqc(payloadPqc);
    const combined = encodeFieldValue(kemStr, payloadStr);

    res.json({
      combined,
      kem: kemStr,
      payload_pqc: payloadStr
    });
  } catch (err) {
    res.status(500).json({ error: String(err) });
  }
});

app.post("/api/tools/decrypt-text", async (req, res) => {
  try {
    const combinedRaw = req.body?.combined;
    const combined =
      typeof combinedRaw === "string" ? combinedRaw.trim() : combinedRaw;
    const payload_pqc = req.body?.payload_pqc;
    const kemStr = req.body?.kem;
    const autoNagagold =
      req.body?.auto_nagagold === undefined ? true : Boolean(req.body?.auto_nagagold);
    let kemParsed;
    let payloadPqc;
    if (combined) {
      const parts = decodeFieldValue(combined);
      kemParsed = decodeKem(parts.kemPart);
      payloadPqc = decodePayloadPqc(parts.payloadPart);
    } else {
      if (!payload_pqc || !kemStr) {
        return res.status(400).json({ error: "payload_pqc and kem are required" });
      }
      kemParsed = decodeKem(kemStr);
      payloadPqc = decodePayloadPqc(payload_pqc);
    }

    const { kem, store } = await initPqc();
    const entry = getKeyEntry(store, kemParsed.kid) || getKeyEntry(store, getCurrentKid(store));
    if (!entry) throw new Error(`Key not found for kid: ${kemParsed.kid}`);

    const kemCiphertext = toUint8(Buffer.from(kemParsed.ciphertext, "base64"));
    const kemSecretKey = toUint8(Buffer.from(entry.kemSecretKey, "base64"));
    const sharedSecret = kem.decapsulate(kemCiphertext, kemSecretKey);

    const text = aesGcmDecrypt(payloadPqc, sharedSecret);

    let payload_plain = null;
    if (autoNagagold) {
      try {
        const parsed = JSON.parse(text);
        if (shouldNagagoldDecrypt(parsed)) {
          payload_plain = decryptNagagoldPayload(parsed, entry.ngKey || NG_ENC_KEY);
        } else {
          payload_plain = parsed;
        }
      } catch (err) {
        payload_plain = null;
      }
      if (payload_plain === null && isHexLike(text)) {
        payload_plain = decryptAscii(text, entry.ngKey || NG_ENC_KEY);
      }
    }

    res.json({ text, payload_plain });
  } catch (err) {
    res.status(500).json({ error: String(err) });
  }
});

app.get("/api/health", (_req, res) => {
  res.json({ ok: true, time: new Date().toISOString() });
});

app.listen(PORT, () => {
  console.log(`Server running on http://localhost:${PORT}`);
});
