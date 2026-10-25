/**
 * Chunked ciphertext storage for the local search index.
 * The header records only a version and a chunk count. Searchable fields
 * stay inside the ciphertext chunks.
 */

import {
  deletePlatformItem,
  readPlatformItem,
  writePlatformItem,
} from "./platformStorage";
import { SEARCH_INDEX_CHUNK_CHARS, SEARCH_INDEX_STORAGE_KEY } from "./vaultSearchKey";

interface SearchIndexHeader {
  v: 1;
  chunks: number;
}

function chunkKey(index: number): string {
  return `${SEARCH_INDEX_STORAGE_KEY}_${index}`;
}

function parseHeader(raw: string | null): SearchIndexHeader | null {
  if (!raw) return null;
  try {
    const parsed = JSON.parse(raw) as { v?: unknown; chunks?: unknown };
    if (
      parsed?.v === 1 &&
      typeof parsed.chunks === "number" &&
      Number.isSafeInteger(parsed.chunks) &&
      parsed.chunks >= 1 &&
      parsed.chunks <= 10_000
    ) {
      return { v: 1, chunks: parsed.chunks };
    }
  } catch {
    return null;
  }
  return null;
}

export async function writeChunkedCiphertext(ciphertext: string): Promise<void> {
  if (typeof ciphertext !== "string" || !ciphertext.startsWith("v4:")) {
    throw new Error("Search index must be ciphertext");
  }
  const previous = parseHeader(await readPlatformItem(SEARCH_INDEX_STORAGE_KEY));
  const parts: string[] = [];
  for (let offset = 0; offset < ciphertext.length; offset += SEARCH_INDEX_CHUNK_CHARS) {
    parts.push(ciphertext.slice(offset, offset + SEARCH_INDEX_CHUNK_CHARS));
  }
  for (let i = 0; i < parts.length; i++) {
    await writePlatformItem(chunkKey(i), parts[i]);
  }
  const previousChunks = previous?.chunks ?? 0;
  for (let i = parts.length; i < previousChunks; i++) {
    await deletePlatformItem(chunkKey(i));
  }
  await writePlatformItem(
    SEARCH_INDEX_STORAGE_KEY,
    JSON.stringify({ v: 1, chunks: parts.length }),
  );
}

export async function readChunkedCiphertext(): Promise<string | null> {
  const header = parseHeader(await readPlatformItem(SEARCH_INDEX_STORAGE_KEY));
  if (!header) return null;
  let ciphertext = "";
  for (let i = 0; i < header.chunks; i++) {
    const part = await readPlatformItem(chunkKey(i));
    if (typeof part !== "string" || part.length === 0) return null;
    ciphertext += part;
  }
  return ciphertext.startsWith("v4:") ? ciphertext : null;
}

export async function clearChunkedCiphertext(): Promise<void> {
  const header = parseHeader(await readPlatformItem(SEARCH_INDEX_STORAGE_KEY));
  const chunks = header?.chunks ?? 0;
  for (let i = 0; i < chunks; i++) {
    await deletePlatformItem(chunkKey(i));
  }
  await deletePlatformItem(SEARCH_INDEX_STORAGE_KEY);
}
