import { randomBytes } from 'node:crypto';
import { mkdtemp, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { spawnSync } from 'node:child_process';
import { createInterface } from 'node:readline/promises';
import { stdin as input, stdout as output } from 'node:process';

if (!input.isTTY || !output.isTTY) {
  console.error('Secure first deployment must run in an interactive terminal.');
  process.exit(1);
}

const run = (command, args) => {
  const result = spawnSync(command, args, {
    stdio: 'inherit',
    shell: false,
    windowsHide: true,
  });
  if (result.status !== 0) {
    throw new Error(`${command} ${args.join(' ')} failed with exit code ${result.status}`);
  }
};

const node = process.execPath;
const wrangler = 'node_modules/wrangler/bin/wrangler.js';

// Validate remote bindings before generating or displaying a new root-of-trust
// bundle. This prevents failed auto-provisioning state from producing multiple
// confusing recovery bundles.
console.log('Validating configured Cloudflare storage resources...');
run(node, [wrangler, 'd1', 'info', 'DB']);
run(node, [wrangler, 'r2', 'bucket', 'info', 'bxss-vault-vault']);

const randomToken = () => randomBytes(32).toString('base64url');
const secrets = {
  AUTH_PEPPER: randomToken(),
  DATA_ENCRYPTION_KEY: randomToken(),
  BOOTSTRAP_TOKEN: randomToken(),
};

console.log('\nBXSS Vault production recovery bundle');
console.log('====================================');
console.log(`AUTH_PEPPER=${secrets.AUTH_PEPPER}`);
console.log(`DATA_ENCRYPTION_KEY=${secrets.DATA_ENCRYPTION_KEY}`);
console.log(`BOOTSTRAP_TOKEN=${secrets.BOOTSTRAP_TOKEN}`);
console.log('====================================');
console.log('Store this bundle in an offline password manager before continuing.');
console.log('Losing DATA_ENCRYPTION_KEY makes existing captures unreadable.\n');

const rl = createInterface({ input, output });
const confirmation = await rl.question('Type BACKED UP to deploy: ');
rl.close();
if (confirmation !== 'BACKED UP') {
  console.error('Deployment cancelled.');
  process.exit(1);
}

const tempDir = await mkdtemp(join(tmpdir(), 'bxss-vault-deploy-'));
const secretFile = join(tempDir, 'secrets.env');

try {
  await writeFile(
    secretFile,
    Object.entries(secrets).map(([key, value]) => `${key}=${value}`).join('\n') + '\n',
    { encoding: 'utf8', mode: 0o600 },
  );

  run(node, ['node_modules/typescript/bin/tsc', '--noEmit']);
  run(node, ['node_modules/vitest/vitest.mjs', 'run']);
  run(node, ['scripts/build-probe.mjs']);
  run(node, ['node_modules/vite/bin/vite.js', 'build']);
  run(node, [wrangler, 'deploy', '--dry-run']);
  run(node, [wrangler, 'd1', 'migrations', 'apply', 'DB', '--remote']);
  run(node, [wrangler, 'deploy', '--secrets-file', secretFile]);

  console.log('\nDeployment and migrations completed.');
  console.log('For critical use, configure the final console/collector hostnames and Cloudflare Access before bootstrap.');
  console.log('Then use BOOTSTRAP_TOKEN on the final console hostname to register the first passkey.');
  console.log('Register a second passkey and download recovery codes before storing captures.');
} finally {
  await rm(tempDir, { recursive: true, force: true });
}
