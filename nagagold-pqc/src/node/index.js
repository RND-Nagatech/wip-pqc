import crypto from "crypto";
import fs from "fs";
import path from "path";
import { createMLKEM768 } from "@oqs/liboqs-js";
import {
  encodePayloadPqc,
  decodePayloadPqc,
  encodeKem,
  decodeKem,
  encodeFieldValue,
  decodeFieldValue,
  toUint8,
  b64ToBytes,
  bytesToB64
} from "../shared/format.js";

function ensureDir(filePath) {
  const dir = path.dirname(filePath);
  if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });
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

function loadMasterKey(masterKeyB64) {
  if (!masterKeyB64) throw new Error("MASTER_KEY is required");
  const key = Buffer.from(masterKeyB64, "base64");
  if (key.length !== 32) throw new Error("MASTER_KEY must be base64 of 32 bytes");
  return key;
}

export class NagagoldPqcNode {
  constructor({ masterKey, keystorePath = "keys/keystore.enc.json", kid = "pqc-default" }) {
    this.masterKey = masterKey;
    this.keystorePath = keystorePath;
    this.kid = kid;
    this._initialized = false;
    this._store = null;
    this._kem = null;
  }

  async init() {
    if (this._initialized) return;
    this._kem = await createMLKEM768();
    const store = this._readKeystore();
    if (store) {
      this._store = store;
      this._initialized = true;
      return;
    }
    const kemKeys = this._kem.generateKeyPair();
    const now = new Date().toISOString();
    this._store = {
      version: 1,
      currentKid: this.kid,
      keys: {
        [this.kid]: {
          createdAt: now,
          kemPublicKey: bytesToB64(toUint8(kemKeys.publicKey)),
          kemSecretKey: bytesToB64(toUint8(kemKeys.secretKey))
        }
      }
    };
    this._writeKeystore(this._store);
    this._initialized = true;
  }

  getStore() {
    return this._store;
  }

  _readKeystore() {
    if (!fs.existsSync(this.keystorePath)) return null;
    const key = loadMasterKey(this.masterKey);
    const raw = JSON.parse(fs.readFileSync(this.keystorePath, "utf8"));
    return decryptKeystore(raw, key);
  }

  _writeKeystore(store) {
    const key = loadMasterKey(this.masterKey);
    const encrypted = encryptKeystore(store, key);
    ensureDir(this.keystorePath);
    fs.writeFileSync(this.keystorePath, JSON.stringify(encrypted, null, 2), "utf8");
  }

  _getEntry(kid) {
    if (!this._store?.keys) return null;
    return this._store.keys[kid] || null;
  }

  _currentKid() {
    return this._store?.currentKid || this.kid;
  }

  encryptFieldValue(plainText) {
    const kid = this._currentKid();
    const entry = this._getEntry(kid);
    if (!entry) throw new Error(`Key not found for kid: ${kid}`);
    const kemEnc = this._kem.encapsulate(toUint8(b64ToBytes(entry.kemPublicKey)));
    const payloadPqc = aesGcmEncrypt(String(plainText ?? ""), kemEnc.sharedSecret);
    const kemStr = encodeKem("ML-KEM-768", kid, entry.kemPublicKey, bytesToB64(kemEnc.ciphertext));
    const payloadStr = encodePayloadPqc(payloadPqc);
    return encodeFieldValue(kemStr, payloadStr);
  }

  decryptFieldValue(fieldValue) {
    const { kemPart, payloadPart } = decodeFieldValue(fieldValue);
    const kemParsed = decodeKem(kemPart);
    const entry = this._getEntry(kemParsed.kid) || this._getEntry(this._currentKid());
    if (!entry) throw new Error(`Key not found for kid: ${kemParsed.kid}`);
    const sharedSecret = this._kem.decapsulate(
      toUint8(b64ToBytes(kemParsed.ciphertext)),
      toUint8(b64ToBytes(entry.kemSecretKey))
    );
    const payloadPqc = decodePayloadPqc(payloadPart);
    const valuePlain = aesGcmDecrypt(payloadPqc, sharedSecret);
    return valuePlain;
  }

  encryptText(text) {
    const kid = this._currentKid();
    const entry = this._getEntry(kid);
    if (!entry) throw new Error(`Key not found for kid: ${kid}`);
    const kemEnc = this._kem.encapsulate(toUint8(b64ToBytes(entry.kemPublicKey)));
    const payloadPqc = aesGcmEncrypt(String(text ?? ""), kemEnc.sharedSecret);
    const kemStr = encodeKem("ML-KEM-768", kid, entry.kemPublicKey, bytesToB64(kemEnc.ciphertext));
    const payloadStr = encodePayloadPqc(payloadPqc);
    return {
      combined: encodeFieldValue(kemStr, payloadStr),
      kem: kemStr,
      payload_pqc: payloadStr
    };
  }

  decryptText({ combined, kem, payload_pqc }) {
    let kemParsed;
    let payloadPqc;
    if (combined) {
      const parts = decodeFieldValue(combined);
      kemParsed = decodeKem(parts.kemPart);
      payloadPqc = decodePayloadPqc(parts.payloadPart);
    } else {
      if (!kem || !payload_pqc) throw new Error("kem and payload_pqc are required");
      kemParsed = decodeKem(kem);
      payloadPqc = decodePayloadPqc(payload_pqc);
    }
    const entry = this._getEntry(kemParsed.kid) || this._getEntry(this._currentKid());
    if (!entry) throw new Error(`Key not found for kid: ${kemParsed.kid}`);
    const sharedSecret = this._kem.decapsulate(
      toUint8(b64ToBytes(kemParsed.ciphertext)),
      toUint8(b64ToBytes(entry.kemSecretKey))
    );
    const text = aesGcmDecrypt(payloadPqc, sharedSecret);
    return { text, payload_plain: null };
  }
}

export async function createNodePqc(options) {
  const client = new NagagoldPqcNode(options);
  await client.init();
  return client;
}
