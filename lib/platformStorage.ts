export type PlatformStorageOptions = {
  keychainService?: string;
  requireAuthentication?: boolean;
};

type MaybePromise<T> = T | Promise<T>;

export type PlatformStorageDriver = {
  getItem: (
    key: string,
    options?: PlatformStorageOptions,
  ) => MaybePromise<string | null>;
  setItem: (
    key: string,
    value: string,
    options?: PlatformStorageOptions,
  ) => MaybePromise<void>;
  deleteItem: (
    key: string,
    options?: PlatformStorageOptions,
  ) => MaybePromise<void>;
  isWeb?: () => MaybePromise<boolean>;
};

let testStorageDriver: PlatformStorageDriver | null = null;

export function setPlatformStorageDriverForTests(
  driver: PlatformStorageDriver | null,
): void {
  testStorageDriver = driver;
}

export async function isWebStoragePlatform(): Promise<boolean> {
  if (testStorageDriver) {
    return testStorageDriver.isWeb ? await testStorageDriver.isWeb() : false;
  }

  const { Platform } = await import("react-native");
  return Platform.OS === "web";
}

export async function readPlatformItem(
  key: string,
  options?: PlatformStorageOptions,
): Promise<string | null> {
  if (testStorageDriver) {
    return await testStorageDriver.getItem(key, options);
  }

  if (await isWebStoragePlatform()) {
    try {
      return localStorage.getItem(key);
    } catch {
      return null;
    }
  }

  const SecureStore = await import("expo-secure-store");
  return await SecureStore.getItemAsync(key, options);
}

export async function writePlatformItem(
  key: string,
  value: string,
  options?: PlatformStorageOptions,
): Promise<void> {
  if (testStorageDriver) {
    await testStorageDriver.setItem(key, value, options);
    return;
  }

  if (await isWebStoragePlatform()) {
    localStorage.setItem(key, value);
    return;
  }

  const SecureStore = await import("expo-secure-store");
  await SecureStore.setItemAsync(key, value, options);
}

export async function deletePlatformItem(
  key: string,
  options?: PlatformStorageOptions,
): Promise<void> {
  if (testStorageDriver) {
    await testStorageDriver.deleteItem(key, options);
    return;
  }

  if (await isWebStoragePlatform()) {
    localStorage.removeItem(key);
    return;
  }

  const SecureStore = await import("expo-secure-store");
  await SecureStore.deleteItemAsync(key, options);
}
