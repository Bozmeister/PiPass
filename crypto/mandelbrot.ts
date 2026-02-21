export interface MandelbrotResult {
  iterations: number;
  escaped: boolean;
  finalReal: number;
  finalImag: number;
}

export function mandelbrotIterate(
  cReal: number,
  cImag: number,
  maxIterations: number
): MandelbrotResult {
  let zReal = 0;
  let zImag = 0;
  let iterations = 0;

  for (let i = 0; i < maxIterations; i++) {
    const zRealSquared = zReal * zReal;
    const zImagSquared = zImag * zImag;

    if (zRealSquared + zImagSquared > 4) {
      return { iterations: i, escaped: true, finalReal: zReal, finalImag: zImag };
    }

    const newReal = zRealSquared - zImagSquared + cReal;
    const newImag = 2 * zReal * zImag + cImag;

    zReal = newReal;
    zImag = newImag;
    iterations = i + 1;
  }

  return { iterations, escaped: false, finalReal: zReal, finalImag: zImag };
}

export function mandelbrotSequence(
  seeds: number[],
  maxIterations: number = 100
): number[] {
  const results: number[] = [];

  for (let i = 0; i < seeds.length - 1; i += 2) {
    const cReal = (seeds[i] / 10) * 3 - 2;
    const cImag = (seeds[i + 1] / 10) * 2 - 1;

    const result = mandelbrotIterate(cReal, cImag, maxIterations);
    results.push(result.iterations);
    results.push(Math.abs(Math.round(result.finalReal * 1000)) % 256);
    results.push(Math.abs(Math.round(result.finalImag * 1000)) % 256);
  }

  return results;
}
