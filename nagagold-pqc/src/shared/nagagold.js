export function encryptAscii(str, key) {
  const dataKey = {};
  for (let i = 0; i < key.length; i++) dataKey[i] = key.substr(i, 1);

  let strEnc = "";
  let nkey = 0;
  const jml = str.length;

  for (let i = 0; i < parseInt(jml, 10); i++) {
    const code = str.charCodeAt(i) + dataKey[nkey].charCodeAt(0);
    strEnc = strEnc + code.toString(16);
    if (nkey === Object.keys(dataKey).length - 1) nkey = 0;
    nkey = nkey + 1;
  }

  return strEnc.toUpperCase();
}

export function decryptAscii(str, key) {
  if (!str) return "";
  const dataKey = {};
  for (let i = 0; i < key.length; i++) dataKey[i] = key.substr(i, 1);

  let strDec = "";
  let nkey = 0;
  let i = 0;
  while (i < str.length) {
    const hex = str.substr(i, 2);
    const code = parseInt(hex, 16) - dataKey[nkey].charCodeAt(0);
    strDec = strDec + String.fromCharCode(code);
    if (nkey === Object.keys(dataKey).length - 1) nkey = 0;
    nkey = nkey + 1;
    i = i + 2;
  }
  return strDec;
}

export function isHexLike(value) {
  if (typeof value !== "string" || value.length === 0) return false;
  if (value.length % 2 !== 0) return false;
  return /^[0-9A-F]+$/.test(value);
}
