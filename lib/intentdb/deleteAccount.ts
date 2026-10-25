/**
 * Optional account deletion followed by the local nuclear reset.
 *
 * Default is off. Set EXPO_PUBLIC_PIPASS_ACCOUNT_DELETE=1, or pass
 * enabled: true. The request sends only x-session-token. It does not
 * send the auth hash or a vault key proof.
 *
 * Nuclear reset runs only after the server returns 204. A disabled flag,
 * a network failure, or a non-204 response leaves local data unchanged.
 */

import { getApiUrl } from "../api-url";

export const PIPASS_ACCOUNT_DELETE_ENV = "EXPO_PUBLIC_PIPASS_ACCOUNT_DELETE";

export type AccountDeleteResult =
  | { deleted: false; reason: "disabled" | "network" | "rejected"; status?: number }
  | { deleted: true };

export type AccountDeleteRequest = {
  sessionToken: string;
  /** Overrides the env flag. Omit it to read EXPO_PUBLIC_PIPASS_ACCOUNT_DELETE. */
  enabled?: boolean;
  apiBaseUrl?: string;
  fetchImpl?: (
    url: string,
    init: { method: string; headers: Record<string, string> },
  ) => Promise<{ ok: boolean; status: number; text: () => Promise<string> }>;
  /** Defaults to the existing destroyAllData nuclear reset. */
  resetLocal?: () => Promise<void>;
};

export function pipassAccountDeleteEnabled(override: boolean | undefined): boolean {
  if (typeof override === "boolean") return override;
  return process.env[PIPASS_ACCOUNT_DELETE_ENV] === "1";
}

async function defaultNuclearReset(): Promise<void> {
  const { destroyAllData } = await import("../../workers/storageWorker");
  await destroyAllData();
}

/**
 * Delete the server account, then wipe local vault state.
 * Failure does not call the local reset.
 */
export async function deleteAccountAndResetLocal(
  input: AccountDeleteRequest,
): Promise<AccountDeleteResult> {
  if (!pipassAccountDeleteEnabled(input.enabled)) {
    return { deleted: false, reason: "disabled" };
  }
  if (typeof input.sessionToken !== "string" || input.sessionToken.length === 0) {
    return { deleted: false, reason: "rejected" };
  }

  try {
    const base = input.apiBaseUrl ?? getApiUrl();
    const url = new URL("/api/account", base);
    const request = {
      method: "DELETE",
      headers: {
        "x-session-token": input.sessionToken,
      },
    };
    const doFetch = input.fetchImpl;
    const response = doFetch
      ? await doFetch(url.toString(), request)
      : await fetch(url.toString(), request);
    await response.text().catch(() => "");
    if (response.status !== 204) {
      return { deleted: false, reason: "rejected", status: response.status };
    }
  } catch {
    return { deleted: false, reason: "network" };
  }

  const reset = input.resetLocal ?? defaultNuclearReset;
  await reset();
  return { deleted: true };
}
