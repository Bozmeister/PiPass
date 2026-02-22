let piDigitsCache: string | null = null;
let cachedDigitCount = 0;

const MAX_PI_DIGITS = 1000;

function computePiChudnovsky(numDigits: number): string {
  const EXTRA = 20;
  const N = numDigits + EXTRA;
  const ONE = 10n ** BigInt(N);
  const C3_OVER_24 = 10939058860032000n;

  function binarySplit(
    a: number,
    b: number
  ): { P: bigint; Q: bigint; T: bigint } {
    if (b - a === 1) {
      const k = BigInt(a);
      let Pab: bigint, Qab: bigint;
      if (a === 0) {
        Pab = 1n;
        Qab = 1n;
      } else {
        Pab = (6n * k - 5n) * (2n * k - 1n) * (6n * k - 1n);
        Qab = k * k * k * C3_OVER_24;
      }
      const Tab = Pab * (13591409n + 545140134n * k);
      if (a & 1) {
        return { P: Pab, Q: Qab, T: -Tab };
      }
      return { P: Pab, Q: Qab, T: Tab };
    }

    const m = (a + b) >> 1;
    const left = binarySplit(a, m);
    const right = binarySplit(m, b);

    return {
      P: left.P * right.P,
      Q: left.Q * right.Q,
      T: left.T * right.Q + left.P * right.T,
    };
  }

  const terms = Math.ceil(N / 14) + 2;
  const { Q, T } = binarySplit(0, terms);

  const sqrtInput = 10005n * ONE * ONE;
  let x = sqrtInput;
  let y = (x + 1n) / 2n;
  while (y < x) {
    x = y;
    y = (x + sqrtInput / x) / 2n;
  }

  const pi = (Q * 426880n * x) / T;
  return pi.toString().substring(0, numDigits);
}

export function getPiDigits(minDigits: number): string {
  const capped = Math.min(minDigits, MAX_PI_DIGITS);
  if (piDigitsCache && cachedDigitCount >= capped) {
    return piDigitsCache;
  }

  const target = Math.max(capped, MAX_PI_DIGITS);
  piDigitsCache = computePiChudnovsky(target);
  cachedDigitCount = target;
  return piDigitsCache;
}

export function extractPiDigits(startIndex: number, count: number): number[] {
  const piString = getPiDigits(MAX_PI_DIGITS);
  const len = piString.length;

  const digits: number[] = [];
  for (let i = 0; i < count; i++) {
    const idx = (startIndex + i) % len;
    digits.push(parseInt(piString[idx], 10));
  }
  return digits;
}

export interface PiCoordinates {
  x: number;
  y: number;
  zoomFactor: number;
  jitterDigits: number[];
}

export function mapDigitsToCoordinates(digits30: number[]): PiCoordinates {
  const xDigits = digits30.slice(0, 10);
  const yDigits = digits30.slice(10, 20);
  const zoomDigits = digits30.slice(20, 25);
  const jitterDigits = digits30.slice(25, 30);

  const xRaw = parseInt(xDigits.join(""), 10);
  const yRaw = parseInt(yDigits.join(""), 10);
  const zoomRaw = parseInt(zoomDigits.join(""), 10);

  const x = (xRaw / 9999999999) * 4.0 - 2.0;
  const y = (yRaw / 9999999999) * 4.0 - 2.0;

  const zoomExponent = 1 + (zoomRaw / 99999) * 11;
  const zoomFactor = Math.pow(10, zoomExponent);

  return { x, y, zoomFactor, jitterDigits };
}
