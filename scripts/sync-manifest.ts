// Writes the parts of package.json that are derived from src/detect.ts.
//
// package.json cannot import TypeScript, so the lockfile list would otherwise be
// duplicated into the menu `when` clauses and the welcome text by hand. This
// script regenerates them from LOCKFILES, and test/manifest.test.ts fails the
// build if the manifest ever drifts from the source again.
//
//   npm run sync:manifest          write the derived values
//   npm run sync:manifest -- --check   report drift without writing (CI)

import { readFileSync, writeFileSync } from 'node:fs'
import { join } from 'node:path'
import { whenClause, supportedSentence, lockfileGlob } from '../src/detect'

const MANIFEST = join(process.cwd(), 'package.json')

/** Menus whose entries are gated on "this file is a lockfile". */
const GATED_MENUS = ['explorer/context', 'editor/context'] as const

interface MenuEntry {
  command: string
  when?: string
  group?: string
}

/** Apply the derived values, returning what changed. */
export function applyDerived(manifest: any): string[] {
  const changes: string[] = []
  const want = whenClause()

  for (const menu of GATED_MENUS) {
    const entries: MenuEntry[] = manifest.contributes?.menus?.[menu] ?? []
    entries.forEach((entry, i) => {
      // Only the lockfile-gated entries; leave any other `when` alone.
      if (!entry.when?.startsWith('resourceFilename =~')) return
      if (entry.when === want) return
      changes.push(`menus.${menu}[${i}].when (${entry.command})`)
      entry.when = want
    })
  }

  // The activation glob is derived too: the extension must wake up for exactly
  // the lockfiles it claims to support, no more and no less.
  const wantEvent = `workspaceContains:${lockfileGlob()}`
  const events: string[] = manifest.activationEvents ?? []
  const idx = events.findIndex((e: string) => e.startsWith('workspaceContains:'))
  if (idx === -1) {
    changes.push('activationEvents (added workspaceContains)')
    manifest.activationEvents = [...events, wantEvent]
  } else if (events[idx] !== wantEvent) {
    changes.push('activationEvents[' + idx + '] (workspaceContains glob)')
    events[idx] = wantEvent
    manifest.activationEvents = events
  }

  const welcome = manifest.contributes?.viewsWelcome?.[0]
  if (welcome?.contents) {
    const sentence = supportedSentence()
    const replaced = welcome.contents.replace(/Supported lockfiles: [^\n]*/, sentence)
    if (replaced !== welcome.contents) {
      changes.push('viewsWelcome[0].contents (supported lockfiles sentence)')
      welcome.contents = replaced
    }
  }

  return changes
}

function main(): void {
  const check = process.argv.includes('--check')
  const raw = readFileSync(MANIFEST, 'utf8')
  const manifest = JSON.parse(raw)

  const changes = applyDerived(manifest)

  if (changes.length === 0) {
    console.log('package.json is in sync with src/detect.ts')
    return
  }

  if (check) {
    console.error('package.json has drifted from src/detect.ts:')
    for (const c of changes) console.error(`  ${c}`)
    console.error('\nRun: npm run sync:manifest')
    process.exit(1)
  }

  writeFileSync(MANIFEST, JSON.stringify(manifest, null, 2) + '\n')
  console.log(`Updated package.json (${changes.length} change(s)):`)
  for (const c of changes) console.log(`  ${c}`)
}

main()
