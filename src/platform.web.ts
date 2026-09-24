// Browser counterpart of ./platform.ts, bundled instead of it by the web build.

export function homeDir(): string | undefined {
  return undefined
}

export async function sha256Hex(body: Uint8Array): Promise<string> {
  const digest = await globalThis.crypto.subtle.digest('SHA-256', body)
  return Array.from(new Uint8Array(digest), (b) => b.toString(16).padStart(2, '0')).join('')
}
