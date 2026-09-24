'use strict'

const esbuild = require('esbuild')

const production = process.argv.includes('--production')
const watch = process.argv.includes('--watch')

const path = require('path')

/**
 * Bundle the extension twice from the same sources. `vscode` is provided by
 * the host at runtime, so it must stay external. The extension has no runtime
 * dependencies, so the published .vsix is the bundles plus resources, nothing else.
 *
 * - dist/extension.js      Node, for desktop VS Code and every fork (`main`)
 * - dist/web/extension.js  browser, for vscode.dev and github.dev (`browser`)
 *
 * The only difference between the two is src/platform.ts, swapped for
 * src/platform.web.ts in the browser build.
 */
const common = {
  entryPoints: ['src/extension.ts'],
  bundle: true,
  format: 'cjs',
  external: ['vscode'],
  sourcemap: !production,
  minify: production,
  logLevel: 'info',
}

const webPlatform = {
  name: 'web-platform',
  setup(build) {
    build.onResolve({ filter: /[\\/]platform$/ }, (args) => ({
      path: path.join(args.resolveDir, args.path + '.web.ts'),
    }))
  },
}

async function main() {
  const ctxs = await Promise.all([
    esbuild.context({
      ...common,
      platform: 'node',
      target: 'node18',
      outfile: 'dist/extension.js',
    }),
    esbuild.context({
      ...common,
      platform: 'browser',
      target: 'es2022',
      outfile: 'dist/web/extension.js',
      plugins: [webPlatform],
    }),
  ])

  if (watch) {
    await Promise.all(ctxs.map((c) => c.watch()))
  } else {
    await Promise.all(ctxs.map((c) => c.rebuild()))
    await Promise.all(ctxs.map((c) => c.dispose()))
  }
}

main().catch((err) => {
  console.error(err)
  process.exit(1)
})
