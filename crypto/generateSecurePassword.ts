import * as ExpoCrypto from "expo-crypto";

export function generateSecurePassword(length: number = 16): string {
  const upper = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
  const lower = "abcdefghijklmnopqrstuvwxyz";
  const digits = "0123456789";
  const symbols = "!@#$%^&*_+-=?";
  const all = upper + lower + digits + symbols;

  const bytes = ExpoCrypto.getRandomBytes(length);
  const chars: string[] = [
    upper[bytes[0] % upper.length],
    lower[bytes[1] % lower.length],
    digits[bytes[2] % digits.length],
    symbols[bytes[3] % symbols.length],
  ];

  for (let i = 4; i < length; i++) {
    chars.push(all[bytes[i] % all.length]);
  }

  const shuffleBytes = ExpoCrypto.getRandomBytes(length);
  for (let i = chars.length - 1; i > 0; i--) {
    const j = shuffleBytes[i] % (i + 1);
    [chars[i], chars[j]] = [chars[j], chars[i]];
  }

  return chars.join("");
}
