import { extractPiDigits, mapDigitsToCoordinates } from "./pi";
import { FractalParams } from "../crypto/hkdf";

const THUMBNAIL_RESOLUTION = 48;
const THUMBNAIL_MAX_ITER = 300;
const VIEWER_RESOLUTION = 96;

const ZOOM_MULTIPLIER = 2.5;
const COORD_MULTIPLIER = 1.8;
const ITERATION_MULTIPLIER = 1.5;
const RESOLUTION_SCALE = 1.5;

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

// 🔥 ULTRA-BRIGHT CYAN + PURPLE NEON VERSION
function escapeToColor(t: number, maxIter: number): string {
  if (t >= maxIter) return "#0a0a0a"; // slightly lighter black background for more pop

  const norm = t / maxIter;
  const intensity = Math.pow(norm, 0.22); // extremely bright early escapes

  // Base = electric cyan
  let r = Math.floor(intensity * 40);
  let g = Math.floor(180 + intensity * 75);
  let b = Math.floor(255);

  // Purple/magenta accent bands (every 6th escape time gets a vibrant pop)
  if (Math.floor(t) % 6 === 0) {
    r = Math.floor(220 + intensity * 35);
    g = Math.floor(60 + intensity * 80);
    b = Math.floor(255);
  }

  const rh = r.toString(16).padStart(2, "0");
  const gh = g.toString(16).padStart(2, "0");
  const bh = b.toString(16).padStart(2, "0");
  return `#${rh}${gh}${bh}`;
}

export function computeFractalGrid(
  piSeed: number,
  resolution: number = THUMBNAIL_RESOLUTION,
  maxIter: number = THUMBNAIL_MAX_ITER,
  fractalParams?: FractalParams
): FractalGridData {
  let centerX: number, centerY: number, zoomFactor: number;
  if (fractalParams) {
    centerX = fractalParams.cx * COORD_MULTIPLIER;
    centerY = fractalParams.cy * COORD_MULTIPLIER;
    zoomFactor = fractalParams.zoom * ZOOM_MULTIPLIER;
    maxIter = Math.min(Math.floor(fractalParams.maxIterations * ITERATION_MULTIPLIER), 2000);
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
  const scaledResolution = fractalParams ? Math.floor(resolution * RESOLUTION_SCALE) : resolution;
  const grid = computeFractalGrid(piSeed, scaledResolution, maxIter, fractalParams);
  const cellSize = size / scaledResolution;

  let rects = "";
  for (let row = 0; row < scaledResolution; row++) {
    for (let col = 0; col < scaledResolution; col++) {
      const color = escapeToColor(grid.escapeGrid[row][col], grid.maxIter);
      if (color !== "#0a0a0a") {
        rects += `<rect x="${(col * cellSize).toFixed(1)}" y="${(row * cellSize).toFixed(1)}" width="${(cellSize + 0.5).toFixed(1)}" height="${(cellSize + 0.5).toFixed(1)}" fill="${color}"/>`;
      }
    }
  }

  return `<svg xmlns="http://www.w3.org/2000/svg" width="${size}" height="${size}" viewBox="0 0 ${size} ${size}"><rect width="${size}" height="${size}" fill="#0a0a0a"/>${rects}</svg>`;
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