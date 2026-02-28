// crypto/sanitizer.ts
export const MiddleVaultWatchman = {
  // TOXIC VENTING: Strips potential injection characters
  scrub(input: string): string {
    if (!input) return "";
    // Remove common script/HTML tags and structural injection chars
    let clean = input.replace(/<[^>]*>?/gm, '');
    clean = clean.replace(/[<>{}[]\\\/]/gi, '');
    
    // Enforce "Military-Grade" length limits (e.g., 512KB for notes)
    return clean.substring(0, 512000);
  },

  // MEMORY PURGE: Syncs with your existing wipeBuffer [cite: 195]
  purge(buffer: Uint8Array) {
    for (let i = 0; i < buffer.length; i++) {
      buffer[i] = 0;
    }
  }
};