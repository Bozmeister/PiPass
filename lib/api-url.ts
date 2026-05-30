/**
 * Gets the base URL for the Express API server.
 */
export function getApiUrl(): string {
  const explicitUrl = process.env.EXPO_PUBLIC_API_URL?.trim();

  if (explicitUrl) {
    if (/^https?:\/\/https?:\/\//i.test(explicitUrl)) {
      throw new Error("EXPO_PUBLIC_API_URL must be a valid http or https URL");
    }

    const url = new URL(explicitUrl);
    if (url.protocol !== "http:" && url.protocol !== "https:") {
      throw new Error("EXPO_PUBLIC_API_URL must use http or https");
    }
    return url.href;
  }

  const domain = process.env.EXPO_PUBLIC_DOMAIN?.trim();

  if (!domain) {
    throw new Error("EXPO_PUBLIC_API_URL or EXPO_PUBLIC_DOMAIN is not set");
  }

  const host = domain.replace(/^https?:\/\//i, "");
  const url = new URL(`https://${host}`);

  return url.href;
}
