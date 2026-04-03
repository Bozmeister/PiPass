import { extractPiDigits, mapDigitsToCoordinates } from "./pi";
import { FractalParams } from "../crypto/hkdf";

const THUMBNAIL_RESOLUTION = 48;
const THUMBNAIL_MAX_ITER = 300;
const VIEWER_RESOLUTION = 96;

export interface FractalGridData {
  width: number;
  height: number;
  escapeGrid: number[][];
  maxIter: number;
  centerX: number;
  centerY: number;
  zoomFactor: number;
}

function mandelbrotEscape(cReal: number, cImag: number, maxIter: number): number {
  let zr = 0, zi = 0;
  for (let i = 0; i < maxIter; i++) {
    const zr2 = zr * zr;
    const zi2 = zi * zi;
    if (zr2 + zi2 > 4) return i;
    zi = 2 * zr * zi + cImag;
    zr = zr2 - zi2 + cReal;
  }
  return maxIter;
}

const FRACTAL_PALETTE = [
  [0x00, 0x11, 0x00],
  [0x00, 0x22, 0x00],
  [0x00, 0x33, 0x00],
  [0x00, 0x44, 0x00],
  [0x00, 0x66, 0x00],
  [0x00, 0xaa, 0x55],
  [0x00, 0xff, 0x88],
  [0x66, 0xff, 0xcc],
  [0xcc, 0xff, 0xee],
  [0xff, 0xff, 0xff],
];

function escapeToColor(t: number, maxIter: number): string {
  if (t >= maxIter) return "#000000";

  const norm = t / maxIter;
  const scaled = Math.pow(norm, 0.35) * (FRACTAL_PALETTE.length - 1);
  const idx = Math.min(Math.floor(scaled), FRACTAL_PALETTE.length - 2);
  const frac = scaled - idx;

  const c0 = FRACTAL_PALETTE[idx];
  const c1 = FRACTAL_PALETTE[idx + 1];
  const r = Math.floor(c0[0] + (c1[0] - c0[0]) * frac);
  const g = Math.floor(c0[1] + (c1[1] - c0[1]) * frac);
  const b = Math.floor(c0[2] + (c1[2] - c0[2]) * frac);

  return `#${r.toString(16).padStart(2, "0")}${g.toString(16).padStart(2, "0")}${b.toString(16).padStart(2, "0")}`;
}

export function computeFractalGrid(
  piSeed: number,
  resolution: number = THUMBNAIL_RESOLUTION,
  maxIter: number = THUMBNAIL_MAX_ITER,
  fractalParams?: FractalParams
): FractalGridData {
  let centerX: number, centerY: number, zoomFactor: number;
  if (fractalParams) {
    centerX = fractalParams.cx;
    centerY = fractalParams.cy;
    zoomFactor = fractalParams.zoom;
    maxIter = fractalParams.maxIterations;
  } else {
    const digits30 = extractPiDigits(piSeed, 30);
    const coords = mapDigitsToCoordinates(digits30);
    centerX = coords.x;
    centerY = coords.y;
    zoomFactor = coords.zoomFactor;
  }

  const viewSize = 4.0 / Math.pow(zoomFactor, 0.15);
  const step = viewSize / resolution;
  const startX = centerX - viewSize / 2;
  const startY = centerY - viewSize / 2;

  const escapeGrid: number[][] = [];
  for (let row = 0; row < resolution; row++) {
    const rowData: number[] = [];
    for (let col = 0; col < resolution; col++) {
      const cr = startX + col * step;
      const ci = startY + row * step;
      rowData.push(mandelbrotEscape(cr, ci, maxIter));
    }
    escapeGrid.push(rowData);
  }

  return { width: resolution, height: resolution, escapeGrid, maxIter, centerX, centerY, zoomFactor };
}

export function generateFractalSvg(
  piSeed: number,
  size: number = 96,
  resolution: number = THUMBNAIL_RESOLUTION,
  maxIter: number = THUMBNAIL_MAX_ITER,
  fractalParams?: FractalParams
): string {
  const grid = computeFractalGrid(piSeed, resolution, maxIter, fractalParams);
  const cellSize = size / resolution;

  let rects = "";
  for (let row = 0; row < resolution; row++) {
    for (let col = 0; col < resolution; col++) {
      const color = escapeToColor(grid.escapeGrid[row][col], maxIter);
      if (color !== "#000000") {
        rects += `<rect x="${(col * cellSize).toFixed(1)}" y="${(row * cellSize).toFixed(1)}" width="${(cellSize + 0.5).toFixed(1)}" height="${(cellSize + 0.5).toFixed(1)}" fill="${color}"/>`;
      }
    }
  }

  return `<svg xmlns="http://www.w3.org/2000/svg" width="${size}" height="${size}" viewBox="0 0 ${size} ${size}"><rect width="${size}" height="${size}" fill="#000000"/>${rects}</svg>`;
}

export function generateFractalDataUri(
  piSeed: number,
  size: number = 96,
  resolution: number = THUMBNAIL_RESOLUTION,
  maxIter: number = THUMBNAIL_MAX_ITER,
  fractalParams?: FractalParams
): string {
  const svg = generateFractalSvg(piSeed, size, resolution, maxIter, fractalParams);
  return `data:image/svg+xml;utf8,${encodeURIComponent(svg)}`;
}

export function getGridPointData(piSeed: number) {
  const digits30 = extractPiDigits(piSeed, 30);
  const coords = mapDigitsToCoordinates(digits30);

  const spacing = 1.0 / coords.zoomFactor;
  const points: {
    row: number;
    col: number;
    cReal: number;
    cImag: number;
    escapeTime: number;
    escaped: boolean;
  }[] = [];

  for (let row = -1; row <= 1; row++) {
    for (let col = -1; col <= 1; col++) {
      const cReal = coords.x + col * spacing;
      const cImag = coords.y + row * spacing;
      const maxIter = 2000;
      const escape = mandelbrotEscape(cReal, cImag, maxIter);
      points.push({
        row,
        col,
        cReal,
        cImag,
        escapeTime: escape,
        escaped: escape < maxIter,
      });
    }
  }

  return {
    coordinates: { x: coords.x, y: coords.y, zoomFactor: coords.zoomFactor },
    points,
  };
}

export { THUMBNAIL_RESOLUTION, THUMBNAIL_MAX_ITER, VIEWER_RESOLUTION };