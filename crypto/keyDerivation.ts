import CryptoJS from "crypto-js";
import { extractPiDigits, piDigitsToSeed } from "./pi";
import { mandelbrotSequence } from "./mandelbrot";

export function deriveKey(
  masterPassword: string,
  salt: string = "pipass-default-salt",
  piStartIndex: number = 0,
  piDigitCount: number = 64,
  mandelbrotIterations: number = 100
): string {
  const piDigits = extractPiDigits(piStartIndex, piDigitCount);

  const seed = piDigitsToSeed(piDigits);

  const mandelbrotInput = piDigits.map((d) => (d + seed) % 10);

  const mandelbrotOutput = mandelbrotSequence(mandelbrotInput, mandelbrotIterations);

  const combinedData = [
    masterPassword,
    salt,
    piDigits.join(""),
    mandelbrotOutput.join(","),
    seed.toString(),
  ].join("|");

  const hash = CryptoJS.SHA256(combinedData).toString(CryptoJS.enc.Hex);

  return hash;
}

export function deriveKeyWithRounds(
  masterPassword: string,
  salt: string = "pipass-default-salt",
  rounds: number = 3
): string {
  let currentKey = masterPassword;

  for (let i = 0; i < rounds; i++) {
    currentKey = deriveKey(
      currentKey,
      salt + i.toString(),
      i * 17,
      64,
      100 + i * 50
    );
  }

  return currentKey;
}
