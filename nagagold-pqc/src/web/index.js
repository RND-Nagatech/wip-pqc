import { init as oqsInit, createMLKEM768 } from "@oqs/liboqs-js";
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
import { encryptAscii, decryptAscii, isHexLike } from "../shared/nagagold.js";

const enc = new TextEncoder();
const dec = new TextDecoder();

async function aesGcmEncrypt(plainText, keyBytes) {
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const key = await crypto.subtle.importKey("raw", keyBytes, { name: "AES-GCM" }, false, ["encrypt"]);
  const ciphertext = await crypto.subtle.encrypt(
    { name: "AES-GCM", iv },
    key,
    enc.encode(plainText)
  );
  const buf = new Uint8Array(ciphertext);
  const tag = buf.slice(buf.length - 16);
  const ct = buf.slice(0, buf.length - 16);
  return {
    iv: bytesToB64(iv),
    tag: bytesToB64(tag),
    ciphertext: bytesToB64(ct)
  };
}

async function aesGcmDecrypt(payload, keyBytes) {
  const iv = b64ToBytes(payload.iv);
  const tag = b64ToBytes(payload.tag);
  const ciphertext = b64ToBytes(payload.ciphertext);
  const merged = new Uint8Array(ciphertext.length + tag.length);
  merged.set(ciphertext, 0);
  merged.set(tag, ciphertext.length);
  const key = await crypto.subtle.importKey("raw", keyBytes, { name: "AES-GCM" }, false, ["decrypt"]);
  const plaintext = await crypto.subtle.decrypt({ name: "AES-GCM", iv }, key, merged);
  return dec.decode(plaintext);
}

function normalizeKeystore(input, kid) {
  if (!input) return null;
  if (input.keys && input.currentKid) return input;
  if (input.kemPublicKey && input.kemSecretKey) {
    const useKid = kid || "pqc-default";
    return {
      version: 1,
      currentKid: useKid,
      keys: {
        [useKid]: {
          createdAt: new Date().toISOString(),
          ngKey: input.ngKey,
          kemPublicKey: input.kemPublicKey,
          kemSecretKey: input.kemSecretKey
        }
      }
    };
  }
  return null;
}

export class NagagoldPqcWeb {
  constructor({ ngKey, keystore, kid = "pqc-default" }) {
    this.ngKey = ngKey;
    this.kid = kid;
    this._store = normalizeKeystore(keystore, kid);
    this._kem = null;
    this._initialized = false;
  }

  async init() {
    if (this._initialized) return;
    await oqsInit();
    this._kem = await createMLKEM768();
    if (!this._store) {
      throw new Error("Keystore is required for web usage");
    }
    this._initialized = true;
  }

  getStore() {
    return this._store;
  }

  _getEntry(kid) {
    return this._store?.keys?.[kid] || null;
  }

  _currentKid() {
    return this._store?.currentKid || this.kid;
  }

  async encryptFieldValue(plainText) {
    const kid = this._currentKid();
    const entry = this._getEntry(kid);
    if (!entry) throw new Error(`Key not found for kid: ${kid}`);
    const kemEnc = this._kem.encapsulate(toUint8(b64ToBytes(entry.kemPublicKey)));
    const payloadPqc = await aesGcmEncrypt(encryptAscii(String(plainText ?? ""), entry.ngKey), kemEnc.sharedSecret);
    const kemStr = encodeKem("ML-KEM-768", kid, entry.kemPublicKey, bytesToB64(kemEnc.ciphertext));
    const payloadStr = encodePayloadPqc(payloadPqc);
    return encodeFieldValue(kemStr, payloadStr);
  }

  async decryptFieldValue(fieldValue) {
    const { kemPart, payloadPart } = decodeFieldValue(fieldValue);
    const kemParsed = decodeKem(kemPart);
    const entry = this._getEntry(kemParsed.kid) || this._getEntry(this._currentKid());
    if (!entry) throw new Error(`Key not found for kid: ${kemParsed.kid}`);
    const sharedSecret = this._kem.decapsulate(
      toUint8(b64ToBytes(kemParsed.ciphertext)),
      toUint8(b64ToBytes(entry.kemSecretKey))
    );
    const payloadPqc = decodePayloadPqc(payloadPart);
    const valueNg = await aesGcmDecrypt(payloadPqc, sharedSecret);
    return decryptAscii(valueNg, entry.ngKey);
  }

  async encryptText(text) {
    const kid = this._currentKid();
    const entry = this._getEntry(kid);
    if (!entry) throw new Error(`Key not found for kid: ${kid}`);
    const kemEnc = this._kem.encapsulate(toUint8(b64ToBytes(entry.kemPublicKey)));
    const payloadPqc = await aesGcmEncrypt(String(text ?? ""), kemEnc.sharedSecret);
    const kemStr = encodeKem("ML-KEM-768", kid, entry.kemPublicKey, bytesToB64(kemEnc.ciphertext));
    const payloadStr = encodePayloadPqc(payloadPqc);
    return {
      combined: encodeFieldValue(kemStr, payloadStr),
      kem: kemStr,
      payload_pqc: payloadStr
    };
  }

  async decryptText({ combined, kem, payload_pqc, autoNagagold = true }) {
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
    const text = await aesGcmDecrypt(payloadPqc, sharedSecret);
    let payload_plain = null;
    if (autoNagagold && isHexLike(text)) {
      payload_plain = decryptAscii(text, entry.ngKey);
    }
    return { text, payload_plain };
  }
}

export async function createWebPqc(options) {
  const client = new NagagoldPqcWeb(options);
  await client.init();
  return client;
}
