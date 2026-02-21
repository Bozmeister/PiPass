import CryptoJS from "crypto-js";

export function encryptData(plaintext: string, key: string): string {
  const iv = CryptoJS.lib.WordArray.random(16);

  const keyWordArray = CryptoJS.enc.Hex.parse(key);

  const encrypted = CryptoJS.AES.encrypt(plaintext, keyWordArray, {
    iv: iv,
    mode: CryptoJS.mode.CBC,
    padding: CryptoJS.pad.Pkcs7,
  });

  const ivHex = iv.toString(CryptoJS.enc.Hex);
  const cipherHex = encrypted.ciphertext.toString(CryptoJS.enc.Hex);

  return ivHex + ":" + cipherHex;
}

export function decryptData(ciphertext: string, key: string): string {
  const parts = ciphertext.split(":");
  if (parts.length !== 2) {
    throw new Error("Invalid ciphertext format");
  }

  const iv = CryptoJS.enc.Hex.parse(parts[0]);
  const encryptedHex = parts[1];

  const keyWordArray = CryptoJS.enc.Hex.parse(key);

  const cipherParams = CryptoJS.lib.CipherParams.create({
    ciphertext: CryptoJS.enc.Hex.parse(encryptedHex),
  });

  const decrypted = CryptoJS.AES.decrypt(cipherParams, keyWordArray, {
    iv: iv,
    mode: CryptoJS.mode.CBC,
    padding: CryptoJS.pad.Pkcs7,
  });

  const result = decrypted.toString(CryptoJS.enc.Utf8);
  if (!result) {
    throw new Error("Decryption failed - invalid key or corrupted data");
  }

  return result;
}
