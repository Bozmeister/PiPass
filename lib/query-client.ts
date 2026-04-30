import { fetch } from "expo/fetch";
import { QueryClient, QueryFunction } from "@tanstack/react-query";
import { clearCredentials, getCredentials } from "./credentials";

/**
 * Gets the base URL for the Express API server (e.g., "http://localhost:3000")
 * @returns {string} The API base URL
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

async function throwIfResNotOk(res: Response) {
  if (!res.ok) {
    const text = (await res.text()) || res.statusText;
    throw new Error(`${res.status}: ${text}`);
  }
}

export async function apiRequest(
  method: string,
  route: string,
  data?: unknown | undefined,
): Promise<Response> {
  const baseUrl = getApiUrl();
  const url = new URL(route, baseUrl);

  const res = await fetch(url.toString(), {
    method,
    headers: data ? { "Content-Type": "application/json" } : {},
    body: data ? JSON.stringify(data) : undefined,
    credentials: "include",
  });

  await throwIfResNotOk(res);
  return res;
}

/**
 * Thrown by `authedApiRequest` whenever the request cannot be authenticated:
 *   - no credentials in SecureStore (caller must run the login flow)
 *   - server returned 401 (credentials invalid; SecureStore is wiped before
 *     this error is thrown so the caller can navigate to the login flow
 *     without first having to clean up).
 *
 * Callers should catch this specifically and route the user to re-auth.
 */
export class AuthRequiredError extends Error {
  constructor(message = "Authentication required") {
    super(message);
    this.name = "AuthRequiredError";
  }
}

/**
 * Authenticated request helper for endpoints that require `x-user-id` +
 * `x-auth-hash`.
 *
 * Contract:
 *   - Reads credentials from `expo-secure-store` (Keychain/Keystore on native,
 *     localStorage on web) on EVERY call. Never caches in memory or React
 *     state — `expo-secure-store` is the only trusted credential source.
 *   - If no credentials are present, throws `AuthRequiredError` BEFORE any
 *     network request is made. The server never sees the call.
 *   - Headers are guaranteed to be plain strings: `getCredentials` rejects
 *     anything that isn't a UUID + hex string, so the helper cannot send an
 *     array, object, or undefined.
 *   - On 401 from the server, clears stored credentials and throws
 *     `AuthRequiredError`. Caller is responsible for navigating to re-auth.
 *   - Never logs credentials. Errors thrown from this function include the
 *     server's response body but never the request headers.
 */
export async function authedApiRequest(
  method: string,
  route: string,
  data?: unknown | undefined,
): Promise<Response> {
  const creds = await getCredentials();
  if (!creds) {
    throw new AuthRequiredError(
      "Authentication required: no credentials in secure storage",
    );
  }

  const baseUrl = getApiUrl();
  const url = new URL(route, baseUrl);

  const headers: Record<string, string> = {
    "x-user-id": creds.userId,
    "x-auth-hash": creds.authHash,
  };
  if (data !== undefined) {
    headers["Content-Type"] = "application/json";
  }

  const res = await fetch(url.toString(), {
    method,
    headers,
    body: data !== undefined ? JSON.stringify(data) : undefined,
    // Defense-in-depth: explicitly omit cookies. The server is sessionless
    // and the only trusted credential source is SecureStore, so we must not
    // accidentally send any other credential material on the request.
    credentials: "omit",
  });

  if (res.status === 401) {
    await clearCredentials();
    throw new AuthRequiredError();
  }

  await throwIfResNotOk(res);
  return res;
}

type UnauthorizedBehavior = "returnNull" | "throw";
export const getQueryFn: <T>(options: {
  on401: UnauthorizedBehavior;
}) => QueryFunction<T> =
  ({ on401: unauthorizedBehavior }) =>
  async ({ queryKey }) => {
    const baseUrl = getApiUrl();
    const url = new URL(queryKey.join("/") as string, baseUrl);

    const res = await fetch(url.toString(), {
      credentials: "include",
    });

    if (unauthorizedBehavior === "returnNull" && res.status === 401) {
      return null;
    }

    await throwIfResNotOk(res);
    return await res.json();
  };

export const queryClient = new QueryClient({
  defaultOptions: {
    queries: {
      queryFn: getQueryFn({ on401: "throw" }),
      refetchInterval: false,
      refetchOnWindowFocus: false,
      staleTime: Infinity,
      retry: false,
    },
    mutations: {
      retry: false,
    },
  },
});
