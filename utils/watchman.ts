const DANGEROUS_CHARS = /[<>{}\[\]\\\/]/g;

const MAX_LENGTHS: Record<string, number> = {
  title: 64,
  username: 64,
  url: 2048,
  notes: 5000,
  password: 256,
};

export function sanitizeInput(text: string, field?: string): string {
  let sanitized = text.replace(DANGEROUS_CHARS, "");
  const maxLen = field ? (MAX_LENGTHS[field] || 256) : 256;
  if (sanitized.length > maxLen) {
    sanitized = sanitized.slice(0, maxLen);
  }
  return sanitized;
}

const RAPID_INPUT_THRESHOLD = 5;
const RAPID_INPUT_WINDOW_MS = 1000;
const PASTE_LENGTH_THRESHOLD = 20;
const LOCKOUT_DURATION_MS = 30000;

export interface HeuristicState {
  timestamps: number[];
  lockedUntil: number | null;
}

export function createHeuristicState(): HeuristicState {
  return { timestamps: [], lockedUntil: null };
}

export function checkHeuristicLockout(
  state: HeuristicState,
  newText: string,
  previousText: string
): { blocked: boolean; lockTriggered: boolean; state: HeuristicState } {
  const now = Date.now();

  if (state.lockedUntil && now < state.lockedUntil) {
    return { blocked: true, lockTriggered: false, state };
  }

  if (state.lockedUntil && now >= state.lockedUntil) {
    state.lockedUntil = null;
  }

  const lengthDiff = newText.length - previousText.length;
  if (lengthDiff >= PASTE_LENGTH_THRESHOLD) {
    state.lockedUntil = now + LOCKOUT_DURATION_MS;
    return { blocked: true, lockTriggered: true, state };
  }

  state.timestamps.push(now);
  state.timestamps = state.timestamps.filter((t) => now - t < RAPID_INPUT_WINDOW_MS);

  if (state.timestamps.length > RAPID_INPUT_THRESHOLD) {
    state.lockedUntil = now + LOCKOUT_DURATION_MS;
    state.timestamps = [];
    return { blocked: true, lockTriggered: true, state };
  }

  return { blocked: false, lockTriggered: false, state };
}

export function getLockoutRemaining(state: HeuristicState): number {
  if (!state.lockedUntil) return 0;
  const remaining = state.lockedUntil - Date.now();
  return remaining > 0 ? remaining : 0;
}
