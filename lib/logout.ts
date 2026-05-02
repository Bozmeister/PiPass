import { clearCredentials } from "./credentials";
import { getApiUrl } from "./api-url";

export type LogoutResult = {
  localCleared: true;
  serverLogoutAttempted: boolean;
  serverLogoutSucceeded?: boolean;
  serverLogoutStatus?: number;
};

type FetchLike = (
  input: string,
  init: {
    method: "POST";
    headers: Record<string, string>;
    credentials: "omit";
  },
) => Promise<{ ok: boolean; status: number }>;

export type LogoutOptions = {
  sessionToken?: string | null;
  apiBaseUrl?: string;
  fetchImpl?: FetchLike;
};

async function tryServerLogout(options: LogoutOptions): Promise<{
  attempted: boolean;
  succeeded?: boolean;
  status?: number;
}> {
  const sessionToken = options.sessionToken?.trim();
  if (!sessionToken) {
    return { attempted: false };
  }

  try {
    const fetchImpl = options.fetchImpl ?? globalThis.fetch;
    if (!fetchImpl) {
      return { attempted: false };
    }

    const baseUrl = options.apiBaseUrl ?? getApiUrl();
    const url = new URL("/api/auth/logout", baseUrl);
    const res = await fetchImpl(url.toString(), {
      method: "POST",
      headers: { "x-session-token": sessionToken },
      credentials: "omit",
    });

    return {
      attempted: true,
      succeeded: res.ok,
      status: res.status,
    };
  } catch {
    return {
      attempted: true,
      succeeded: false,
    };
  }
}

export async function logoutCurrentSession(
  options: LogoutOptions = {},
): Promise<LogoutResult> {
  const serverLogout = await tryServerLogout(options);

  // Local logout is authoritative for this app install. Server logout is
  // best-effort because the current client does not persist session tokens.
  await clearCredentials();

  return {
    localCleared: true,
    serverLogoutAttempted: serverLogout.attempted,
    serverLogoutSucceeded: serverLogout.succeeded,
    serverLogoutStatus: serverLogout.status,
  };
}
