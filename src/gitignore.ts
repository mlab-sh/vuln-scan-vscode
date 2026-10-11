import * as vscode from 'vscode'

// Asks the built in Git extension which files are ignored, so nested
// .gitignore files, .git/info/exclude and the global excludes file all count
// exactly as git sees them. No Git extension (vscode.dev, git disabled) or no
// repository: nothing is considered ignored and every file is kept.

interface GitRepo {
  checkIgnore(paths: string[]): Promise<Set<string>>
}
interface GitApi {
  getRepository(uri: vscode.Uri): GitRepo | null
}

// git may echo paths back with other separators or casing on Windows.
const norm = (p: string) => p.replace(/\\/g, '/').toLowerCase()

async function gitApi(): Promise<GitApi | undefined> {
  const ext = vscode.extensions.getExtension<{ getAPI(v: 1): GitApi }>('vscode.git')
  if (!ext) return undefined
  try {
    const exports = ext.isActive ? ext.exports : await ext.activate()
    return exports.getAPI(1)
  } catch {
    return undefined // git disabled or not installed
  }
}

/** `uris` minus the ones git ignores. */
export async function dropGitIgnored(uris: vscode.Uri[]): Promise<vscode.Uri[]> {
  const api = await gitApi()
  if (!api) return uris
  const ignored = new Set<string>()
  const byRepo = new Map<GitRepo, string[]>()
  for (const uri of uris) {
    const repo = api.getRepository(uri)
    if (repo) byRepo.set(repo, [...(byRepo.get(repo) ?? []), uri.fsPath])
  }
  for (const [repo, paths] of byRepo) {
    try {
      for (const p of await repo.checkIgnore(paths)) ignored.add(norm(p))
    } catch {
      // git failed for this repo: keep its files rather than hide a lockfile
    }
  }
  return uris.filter((u) => !ignored.has(norm(u.fsPath)))
}
