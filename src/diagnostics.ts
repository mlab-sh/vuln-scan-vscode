import * as vscode from 'vscode'
import { Finding } from './api/types'
import { ScanOutcome } from './api/client'
import { DiagLevel, levelFor, locateLine } from './diagnosticsCore'
import * as config from './config'

// Diagnostics for vulnerable dependencies, anchored on the line of the lockfile
// that declares the package.
//
// This is what finally gives `mlab.severityFloor` a meaning. The setting has
// always been declared and documented as tuning the diagnostic severity mapping,
// but there was no DiagnosticCollection in the extension for it to tune.
//
// All the decision logic lives in ./diagnosticsCore, which has no vscode import
// and is unit tested. This file only translates it into VS Code types.

const LEVEL: Record<DiagLevel, vscode.DiagnosticSeverity> = {
  error: vscode.DiagnosticSeverity.Error,
  warning: vscode.DiagnosticSeverity.Warning,
  information: vscode.DiagnosticSeverity.Information,
}

export class LockfileDiagnostics {
  private readonly collection: vscode.DiagnosticCollection

  constructor() {
    this.collection = vscode.languages.createDiagnosticCollection('mlab')
  }

  /**
   * Publish diagnostics for one lockfile. `text` is the lockfile's own content,
   * which callers already hold from the scan, so this costs no extra IO.
   */
  set(uri: vscode.Uri, text: string, outcome: ScanOutcome): void {
    const floor = String(config.get('severityFloor'))
    this.collection.set(
      uri,
      outcome.findings.map((f) => toDiagnostic(text, f, floor)),
    )
  }

  clear(uri?: vscode.Uri): void {
    if (uri) this.collection.delete(uri)
    else this.collection.clear()
  }

  dispose(): void {
    this.collection.dispose()
  }
}

function toDiagnostic(text: string, f: Finding, floor: string): vscode.Diagnostic {
  const hit = locateLine(text, f.name, f.version)
  const fix = f.fixedVersion ? ` Fixed in ${f.fixedVersion}.` : ' No fixed version published.'
  const d = new vscode.Diagnostic(
    new vscode.Range(hit.line, hit.col, hit.line, hit.endCol),
    `${f.cve} (${f.severity}) in ${f.pkg}.${fix}${f.summary ? ` ${f.summary}` : ''}`,
    LEVEL[levelFor(f.severity, floor)],
  )
  d.source = 'mlab'
  d.code = f.url ? { value: f.cve, target: vscode.Uri.parse(f.url) } : f.cve
  return d
}
