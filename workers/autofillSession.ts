import { wipeBuffer } from "../crypto/secureMemory";

const SESSION_TIMEOUT_MS = 30_000;

let sessionStart = 0;
let sessionTimer: ReturnType<typeof setTimeout> | null = null;
let decryptedBuffer: Uint8Array | null = null;

export function startAutofillSession(): void {
  wipeAutofillSession();
  sessionStart = Date.now();
  sessionTimer = setTimeout(() => {
    wipeAutofillSession();
  }, SESSION_TIMEOUT_MS);
}

export function isAutofillSessionValid(): boolean {
  if (sessionStart === 0) return false;
  return Date.now() - sessionStart < SESSION_TIMEOUT_MS;
}

export function setDecryptedBuffer(data: Uint8Array): void {
  if (decryptedBuffer) {
    wipeBuffer(decryptedBuffer);
  }
  decryptedBuffer = data;
}

export function getDecryptedBuffer(): Uint8Array | null {
  if (!isAutofillSessionValid()) {
    wipeAutofillSession();
    return null;
  }
  return decryptedBuffer;
}

export function consumeDecryptedBuffer(): Uint8Array | null {
  if (!isAutofillSessionValid()) {
    wipeAutofillSession();
    return null;
  }
  const buf = decryptedBuffer;
  decryptedBuffer = null;
  sessionStart = 0;
  if (sessionTimer) {
    clearTimeout(sessionTimer);
    sessionTimer = null;
  }
  return buf;
}

export function wipeAutofillSession(): void {
  if (sessionTimer) {
    clearTimeout(sessionTimer);
    sessionTimer = null;
  }
  sessionStart = 0;
  if (decryptedBuffer) {
    wipeBuffer(decryptedBuffer);
    decryptedBuffer = null;
  }
}
