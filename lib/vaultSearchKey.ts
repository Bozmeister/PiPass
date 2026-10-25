/** SecureStore key for the encrypted local search index. Chunks use `${key}_${n}`. */
export const SEARCH_INDEX_STORAGE_KEY = "pipass_search_index";

/** Stay under the platform SecureStore value limit. */
export const SEARCH_INDEX_CHUNK_CHARS = 1500;
