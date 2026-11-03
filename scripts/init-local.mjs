import { randomBytes } from 'node:crypto';
import { access, writeFile } from 'node:fs/promises';

const output = '.dev.vars';

try {
  await access(output);
  console.error(`${output} already exists; refusing to overwrite it.`);
  process.exit(1);
} catch {
  // Expected when the file does not exist.
}

const token = () => randomBytes(32).toString('base64url');
const bootstrapToken = token();
const body = [
  `AUTH_PEPPER=${token()}`,
  `DATA_ENCRYPTION_KEY=${token()}`,
  `BOOTSTRAP_TOKEN=${bootstrapToken}`,
  '',
].join('\n');

await writeFile(output, body, { encoding: 'utf8', mode: 0o600, flag: 'wx' });
console.log(`Created ${output}.`);
console.log('Bootstrap token (store it temporarily):');
console.log(bootstrapToken);
console.log('Next: npm run db:migrate:local && npm run dev');
