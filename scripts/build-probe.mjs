import { build } from 'esbuild';
import { mkdir, rm } from 'node:fs/promises';

// dist contains only generated artifacts. Recreate it so a deployment cannot
// accidentally retain an old, addressable dashboard or probe bundle.
await rm('dist', { recursive: true, force: true });
await mkdir('dist', { recursive: true });

await build({
  entryPoints: ['src/probe/index.ts'],
  outfile: 'dist/probe-runtime.js',
  bundle: true,
  minify: true,
  sourcemap: false,
  format: 'iife',
  target: ['es2020'],
  legalComments: 'linked',
});
