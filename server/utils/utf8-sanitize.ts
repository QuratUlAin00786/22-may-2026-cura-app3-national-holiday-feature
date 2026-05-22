/** PostgreSQL SQLSTATE for invalid_text_representation (bad UTF-8 in text columns). */
export function isInvalidUtf8DatabaseError(error: unknown): boolean {
  return (error as { code?: string })?.code === "22021";
}

/**
 * Re-decode a string read with client_encoding LATIN1 into clean UTF-8.
 * Strips replacement characters from invalid byte sequences (e.g. lone 0x9c).
 */
export function sanitizeUtf8FromLatin1Bytes(value: unknown): string | null {
  if (value == null) return null;
  if (typeof value !== "string") return String(value);
  const buf = Buffer.from(value, "latin1");
  return new TextDecoder("utf-8", { fatal: false }).decode(buf).replace(/\uFFFD/g, "");
}
