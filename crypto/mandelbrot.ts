export const MAX_ITERATIONS = 2000;

export interface OrbitResult {
  iterations: number;
  escaped: boolean;
  orbit: { re: number; im: number }[];
}

export function mandelbrotOrbit(
  cReal: number,
  cImag: number,
  maxIter: number = MAX_ITERATIONS
): OrbitResult {
  let zReal = 0;
  let zImag = 0;
  const orbit: { re: number; im: number }[] = [{ re: 0, im: 0 }];

  for (let i = 0; i < maxIter; i++) {
    const zr2 = zReal * zReal;
    const zi2 = zImag * zImag;

    if (zr2 + zi2 > 4) {
      return { iterations: i, escaped: true, orbit };
    }

    const newReal = zr2 - zi2 + cReal;
    const newImag = 2 * zReal * zImag + cImag;

    zReal = newReal;
    zImag = newImag;
    orbit.push({ re: zReal, im: zImag });
  }

  return { iterations: maxIter, escaped: false, orbit };
}

export interface GridPoint {
  row: number;
  col: number;
  cReal: number;
  cImag: number;
  result: OrbitResult;
}

export function compute3x3Grid(
  centerX: number,
  centerY: number,
  zoomFactor: number
): GridPoint[] {
  const spacing = 1.0 / zoomFactor;
  const points: GridPoint[] = [];

  for (let row = -1; row <= 1; row++) {
    for (let col = -1; col <= 1; col++) {
      const cReal = centerX + col * spacing;
      const cImag = centerY + row * spacing;
      const result = mandelbrotOrbit(cReal, cImag, MAX_ITERATIONS);
      points.push({ row, col, cReal, cImag, result });
    }
  }

  return points;
}

export function applyDeterministicJitter(
  grid: GridPoint[],
  jitterDigits: number[]
): GridPoint[] {
  const centerIdx = 4;
  const center = grid[centerIdx];

  if (center.result.iterations < MAX_ITERATIONS) {
    return grid;
  }

  const jitteredGrid = [...grid];
  let currentCenter = center;
  let attempt = 0;

  while (currentCenter.result.iterations >= MAX_ITERATIONS && attempt < 50) {
    const d1 = jitterDigits[attempt % jitterDigits.length];
    const d2 = jitterDigits[(attempt + 1) % jitterDigits.length];

    const offsetReal = (d1 - 4.5) * 1e-10 * (attempt + 1);
    const offsetImag = (d2 - 4.5) * 1e-10 * (attempt + 1);

    const newCReal = center.cReal + offsetReal;
    const newCImag = center.cImag + offsetImag;
    const newResult = mandelbrotOrbit(newCReal, newCImag, MAX_ITERATIONS);

    currentCenter = {
      row: 0,
      col: 0,
      cReal: newCReal,
      cImag: newCImag,
      result: newResult,
    };

    attempt++;
  }

  jitteredGrid[centerIdx] = currentCenter;
  return jitteredGrid;
}

export function computeFullPipeline(
  centerX: number,
  centerY: number,
  zoomFactor: number,
  jitterDigits: number[]
): GridPoint[] {
  const grid = compute3x3Grid(centerX, centerY, zoomFactor);
  return applyDeterministicJitter(grid, jitterDigits);
}
