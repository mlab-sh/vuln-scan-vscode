// Parser for `.mlab/vuln.yml`. Pure module (no `vscode` import) so it can be
// unit tested.
//
// ponytail: flat `key: scalar` only (strings, booleans, numbers, comments,
// quotes). Nested maps and lists are ignored. Swap for a real YAML parser if
// the file ever needs structure.

export function parseFlatYaml(text: string): Record<string, string | number | boolean> {
  const out: Record<string, string | number | boolean> = {}
  for (const raw of text.split(/\r?\n/)) {
    if (/^\s/.test(raw)) continue // indented: part of a nested block
    const m = /^([A-Za-z_][\w-]*)\s*:\s*(.*)$/.exec(raw)
    if (!m) continue
    const value = scalar(m[2])
    if (value !== undefined) out[m[1]] = value
  }
  return out
}

function scalar(v: string): string | number | boolean | undefined {
  const quoted = /^(["'])(.*)\1\s*(#.*)?$/.exec(v)
  if (quoted) return quoted[2]
  const bare = v.replace(/\s+#.*$/, '').replace(/^#.*$/, '').trim()
  if (bare === '' || bare === '~' || bare === 'null') return undefined
  if (/^(true|yes|on)$/i.test(bare)) return true
  if (/^(false|no|off)$/i.test(bare)) return false
  if (/^-?\d+(\.\d+)?$/.test(bare)) return Number(bare)
  return bare
}
