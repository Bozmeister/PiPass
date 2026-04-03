export function normalizeDomain(input: string): string {
  try {
    let url = input.trim().toLowerCase();

    url = url.replace(/^https?:\/\//, '');
    url = url.split('/')[0];
    url = url.split(':')[0];
    url = url.replace(/^www\./, '');

    const parts = url.split('.');

    if (parts.length <= 2) return url;

    const tld = parts.slice(-2).join('.');

    if (['co.uk', 'com.au'].includes(tld)) {
      return parts.slice(-3).join('.');
    }

    return parts.slice(-2).join('.');
  } catch {
    return input;
  }
}

export function matchDomain(
  input: string,
  candidates: string[]
): string[] {
  const normalizedInput = normalizeDomain(input);

  return candidates
    .map((c) => ({
      original: c,
      normalized: normalizeDomain(c),
    }))
    .filter((c) => {
      return (
        c.normalized === normalizedInput ||
        c.normalized.endsWith(normalizedInput) ||
        normalizedInput.endsWith(c.normalized)
      );
    })
    .map((c) => c.original);
}
