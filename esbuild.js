'use strict'

const esbuild = require('esbuild')

const production = process.argv.includes('--production')
const watch = process.argv.includes('--watch')

/**
 * Bundle the extension into a single dist/extension.js. `vscode` is provided by
 * the host at runtime, so it must stay external. Everything else (jsonc-parser)
 * is bundled in, so the published .vsix carries no node_modules.
 */
async function main() {
  const ctx = await esbuild.context({
    entryPoints: ['src/extension.ts'],
    bundle: true,
    format: 'cjs',
    platform: 'node',
    target: 'node18',
    outfile: 'dist/extension.js',
    external: ['vscode'],
    sourcemap: !production,
    minify: production,
    logLevel: 'info',
  })

  if (watch) {
    await ctx.watch()
  } else {
    await ctx.rebuild()
    await ctx.dispose()
  }
}

main().catch((err) => {
  console.error(err)
  process.exit(1)
})
