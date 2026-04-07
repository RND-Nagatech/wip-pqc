export function encodePayloadPqc({ iv, tag, ciphertext }) {
  return `${iv}|${tag}|${ciphertext}`;
}

export function decodePayloadPqc(value) {
  const parts = String(value || "").split("|");
  if (parts.length !== 3) throw new Error("Invalid payload_pqc format");
  return { iv: parts[0], tag: parts[1], ciphertext: parts[2] };
}

export function encodeKem(alg, kid, publicKeyB64, ciphertextB64) {
  return `${alg}|${kid}|${publicKeyB64}|${ciphertextB64}`;
}

export function decodeKem(value) {
  const parts = String(value || "").split("|");
  if (parts.length !== 4) throw new Error("Invalid kem format");
  return { alg: parts[0], kid: parts[1], publicKey: parts[2], ciphertext: parts[3] };
}

export function encodeFieldValue(kemStr, payloadPqcStr) {
  return `${kemStr}||${payloadPqcStr}`;
}

export function decodeFieldValue(value) {
  const [kemPart, payloadPart] = String(value || "").split("||");
  if (!kemPart || !payloadPart) throw new Error("Invalid field format");
  return { kemPart, payloadPart };
}

export function toUint8(value) {
  if (value instanceof Uint8Array) return value;
  if (value instanceof ArrayBuffer) return new Uint8Array(value);
  if (Array.isArray(value)) return Uint8Array.from(value);
  return new Uint8Array(value || []);
}

export function b64ToBytes(b64) {
  const bin = typeof atob === "function" ? atob(b64) : Buffer.from(b64, "base64").toString("binary");
  const arr = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) arr[i] = bin.charCodeAt(i);
  return arr;
}

export function bytesToB64(bytes) {
  if (typeof Buffer !== "undefined") {
    return Buffer.from(bytes).toString("base64");
  }
  let bin = "";
  bytes.forEach((b) => (bin += String.fromCharCode(b)));
  return btoa(bin);
}
