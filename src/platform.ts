import * as crypto from 'crypto'
import * as os from 'os'

// The only Node specific code in the extension. The web build (vscode.dev,
// github.dev) swaps this file for ./platform.web.ts at bundle time, see
// esbuild.js. Both files must export the same functions.

/** Home directory, or undefined where there is none (the browser). */
export function homeDir(): string | undefined {
  return os.homedir()
}

/** Hex SHA-256. Async to match the browser version, which has no sync digest. */
export async function sha256Hex(body: Uint8Array): Promise<string> {
  return crypto.createHash('sha256').update(body).digest('hex')
}
