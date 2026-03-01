const FORBIDDEN_CHARS = /[<>{}\[\]\\\/]/g;
const NON_PRINTABLE = /[\x00-\x08\x0B\x0C\x0E-\x1F\x7F-\x9F]/g;

const FIELD_LIMITS: Record<string, number> = {
  title: 64,
  username: 64,
  password: 256,
  url: 2048,
  notes: 5000,
};

const DEFAULT_LIMIT = 64;

export interface SanitizationResult {
  clean: string;
  ok: boolean;
  error?: string;
}

export function hyperbaricSanitize(
  raw: string,
  field?: string
): SanitizationResult {
  if (raw === null || raw === undefined) {
    return { clean: "", ok: false, error: "Input is null or undefined" };
  }

  if (typeof raw !== "string") {
    return { clean: "", ok: false, error: "Input is not a string" };
  }

  let scrubbed = raw.replace(NON_PRINTABLE, "");
  scrubbed = scrubbed.replace(FORBIDDEN_CHARS, "");

  const limit = field ? (FIELD_LIMITS[field] || DEFAULT_LIMIT) : DEFAULT_LIMIT;
  if (scrubbed.length > limit) {
    scrubbed = scrubbed.slice(0, limit);
  }

  return { clean: scrubbed, ok: true };
}

export interface EntryFields {
  title: string;
  username: string;
  password: string;
  url?: string;
  notes?: string;
}

export function sanitizeEntryFields(
  entry: EntryFields
): { sanitized: EntryFields; ok: boolean; error?: string } {
  const titleResult = hyperbaricSanitize(entry.title, "title");
  if (!titleResult.ok) {
    return { sanitized: entry, ok: false, error: `Title: ${titleResult.error}` };
  }

  const usernameResult = hyperbaricSanitize(entry.username, "username");
  if (!usernameResult.ok) {
    return { sanitized: entry, ok: false, error: `Username: ${usernameResult.error}` };
  }

  const passwordResult = hyperbaricSanitize(entry.password, "password");
  if (!passwordResult.ok) {
    return { sanitized: entry, ok: false, error: `Password: ${passwordResult.error}` };
  }

  let cleanUrl: string | undefined;
  if (entry.url) {
    const urlResult = hyperbaricSanitize(entry.url, "url");
    if (!urlResult.ok) {
      return { sanitized: entry, ok: false, error: `URL: ${urlResult.error}` };
    }
    cleanUrl = urlResult.clean || undefined;
  }

  let cleanNotes: string | undefined;
  if (entry.notes) {
    const notesResult = hyperbaricSanitize(entry.notes, "notes");
    if (!notesResult.ok) {
      return { sanitized: entry, ok: false, error: `Notes: ${notesResult.error}` };
    }
    cleanNotes = notesResult.clean || undefined;
  }

  return {
    sanitized: {
      title: titleResult.clean,
      username: usernameResult.clean,
      password: passwordResult.clean,
      url: cleanUrl,
      notes: cleanNotes,
    },
    ok: true,
  };
}
