import React, { useState, useEffect } from "react";
import { Image, View, Platform } from "react-native";
import { Ionicons } from "@expo/vector-icons";
import * as FileSystem from "expo-file-system";
import { getLogoUrl, extractDomain } from "../lib/logoUrl";

interface FaviconImageProps {
  url?: string;
  size?: number;
}

const CACHE_DIR = FileSystem.cacheDirectory + "favicons/";

function sanitizeFilename(domain: string): string {
  return domain.replace(/[^a-zA-Z0-9.-]/g, "_");
}

async function ensureCacheDir(): Promise<void> {
  const info = await FileSystem.getInfoAsync(CACHE_DIR);
  if (!info.exists) {
    await FileSystem.makeDirectoryAsync(CACHE_DIR, { intermediates: true });
  }
}

async function getCachedFavicon(domain: string): Promise<string | null> {
  if (Platform.OS === "web") return null;

  try {
    const filename = sanitizeFilename(domain) + ".png";
    const filePath = CACHE_DIR + filename;
    const info = await FileSystem.getInfoAsync(filePath);
    if (info.exists) {
      return filePath;
    }
  } catch {}
  return null;
}

async function downloadAndCacheFavicon(
  url: string,
  domain: string
): Promise<string | null> {
  if (Platform.OS === "web") return null;

  try {
    await ensureCacheDir();
    const filename = sanitizeFilename(domain) + ".png";
    const filePath = CACHE_DIR + filename;
    const download = await FileSystem.downloadAsync(url, filePath);
    if (download.status === 200) {
      return filePath;
    }
  } catch {}
  return null;
}

export default function FaviconImage({ url, size = 28 }: FaviconImageProps) {
  const [imageUri, setImageUri] = useState<string | null>(null);
  const [failed, setFailed] = useState(false);

  useEffect(() => {
    if (!url) {
      setImageUri(null);
      return;
    }

    const domain = extractDomain(url);
    if (!domain) {
      setImageUri(null);
      return;
    }

    const logoUrl = getLogoUrl(url);

    if (Platform.OS === "web") {
      setImageUri(logoUrl);
      return;
    }

    let cancelled = false;

    (async () => {
      const cached = await getCachedFavicon(domain);
      if (cancelled) return;

      if (cached) {
        setImageUri(cached);
        return;
      }

      const downloaded = await downloadAndCacheFavicon(logoUrl, domain);
      if (cancelled) return;

      if (downloaded) {
        setImageUri(downloaded);
      } else {
        setImageUri(logoUrl);
      }
    })();

    return () => {
      cancelled = true;
    };
  }, [url]);

  if (!url || failed || !imageUri) {
    return (
      <View
        style={{
          width: size,
          height: size,
          borderRadius: 6,
          backgroundColor: "#222",
          justifyContent: "center",
          alignItems: "center",
        }}
      >
        <Ionicons name="globe-outline" size={size * 0.6} color="#666" />
      </View>
    );
  }

  return (
    <Image
      source={{ uri: imageUri }}
      style={{
        width: size,
        height: size,
        borderRadius: 6,
        backgroundColor: "#222",
      }}
      onError={() => setFailed(true)}
    />
  );
}
