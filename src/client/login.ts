import { startAuthentication, startRegistration } from '@simplewebauthn/browser';
import './login.css';

type JsonMap = Record<string, unknown>;

const AUTH = '/api/auth';

function element<T extends HTMLElement>(id: string): T {
  const value = document.getElementById(id);
  if (!value) throw new Error(`Missing login element: ${id}`);
  return value as T;
}

function asMap(value: unknown): JsonMap {
  return value !== null && typeof value === 'object' && !Array.isArray(value)
    ? value as JsonMap
    : {};
}

function asList(value: unknown): unknown[] {
  return Array.isArray(value) ? value : [];
}

function stringValue(value: unknown, fallback = ''): string {
  return typeof value === 'string' ? value : fallback;
}

const loadingPanel = element<HTMLElement>('loading-panel');
const signinPanel = element<HTMLElement>('signin-panel');
const recoveryPanel = element<HTMLFormElement>('recovery-panel');
const bootstrapPanel = element<HTMLFormElement>('bootstrap-panel');
const secretsPanel = element<HTMLElement>('secrets-panel');
const errorMessage = element<HTMLElement>('error-message');
const signinButton = element<HTMLButtonElement>('signin-button');
const showRecoveryButton = element<HTMLButtonElement>('show-recovery-button');
const hideRecoveryButton = element<HTMLButtonElement>('hide-recovery-button');
const recoveryEmail = element<HTMLInputElement>('recovery-email');
const recoveryCode = element<HTMLInputElement>('recovery-code');
const bootstrapToken = element<HTMLInputElement>('bootstrap-token');
const bootstrapName = element<HTMLInputElement>('bootstrap-name');
const bootstrapEmail = element<HTMLInputElement>('bootstrap-email');
const bootstrapPasskey = element<HTMLInputElement>('bootstrap-passkey');
const rpName = element<HTMLElement>('rp-name');
const recoveryCodes = element<HTMLElement>('recovery-codes');
const collectorToken = element<HTMLElement>('collector-token');
const copyCodesButton = element<HTMLButtonElement>('copy-codes-button');
const copyTokenButton = element<HTMLButtonElement>('copy-token-button');
const copyAllButton = element<HTMLButtonElement>('copy-all-button');
const secretsConfirmed = element<HTMLInputElement>('secrets-confirmed');
const openDashboardButton = element<HTMLButtonElement>('open-dashboard-button');

const panels = [loadingPanel, signinPanel, recoveryPanel, bootstrapPanel, secretsPanel];
let busy = false;
let issuedRecoveryCodes: string[] = [];
let issuedCollectorToken = '';

function showPanel(panel: HTMLElement): void {
  for (const candidate of panels) candidate.hidden = candidate !== panel;
}

function showError(message: string): void {
  errorMessage.textContent = message;
  errorMessage.hidden = !message;
}

function friendlyError(error: unknown): string {
  if (error instanceof DOMException && error.name === 'NotAllowedError') {
    return 'Passkey verification was cancelled or timed out.';
  }
  if (error instanceof Error && error.message) return error.message;
  return 'The request could not be completed.';
}

function updateDisabledState(): void {
  for (const control of document.querySelectorAll<HTMLButtonElement | HTMLInputElement>('button, input')) {
    if (control === openDashboardButton) continue;
    control.disabled = busy;
  }
  openDashboardButton.disabled = busy || !secretsConfirmed.checked;
  document.documentElement.dataset.busy = busy ? 'true' : 'false';
}

function setBusy(next: boolean): void {
  busy = next;
  updateDisabledState();
}

async function requestJson(path: string, init: RequestInit = {}): Promise<JsonMap> {
  const headers = new Headers(init.headers);
  headers.set('Accept', 'application/json');
  if (init.method && init.method !== 'GET') headers.set('Content-Type', 'application/json');
  const response = await fetch(path, {
    ...init,
    credentials: 'same-origin',
    headers,
  });
  const contentType = response.headers.get('Content-Type') || '';
  const payload = contentType.includes('application/json')
    ? asMap(await response.json().catch(() => null))
    : {};
  if (!response.ok) {
    const error = asMap(payload.error);
    throw new Error(stringValue(error.message, 'The request could not be completed.'));
  }
  return payload;
}

function goToDashboard(): void {
  window.location.assign('/dashboard');
}

async function copyValue(button: HTMLButtonElement, value: string): Promise<void> {
  if (!value) return;
  const original = button.textContent || 'Copy';
  try {
    await navigator.clipboard.writeText(value);
    button.textContent = 'Copied';
    window.setTimeout(() => {
      button.textContent = original;
    }, 1_500);
  } catch {
    showError('Clipboard access was denied. Select and copy the value manually.');
  }
}

async function signIn(): Promise<void> {
  setBusy(true);
  showError('');
  try {
    const options = await requestJson(`${AUTH}/login/options`, {
      method: 'POST',
      body: '{}',
    });
    const assertion = await startAuthentication({
      optionsJSON: options.options as Parameters<typeof startAuthentication>[0]['optionsJSON'],
    });
    await requestJson(`${AUTH}/login/verify`, {
      method: 'POST',
      body: JSON.stringify({ response: assertion }),
    });
    goToDashboard();
  } catch (error) {
    showError(friendlyError(error));
  } finally {
    setBusy(false);
  }
}

async function recover(event: SubmitEvent): Promise<void> {
  event.preventDefault();
  setBusy(true);
  showError('');
  try {
    const options = await requestJson(`${AUTH}/recovery`, {
      method: 'POST',
      body: JSON.stringify({
        email: recoveryEmail.value.trim(),
        code: recoveryCode.value.trim().toUpperCase(),
      }),
    });
    const credential = await startRegistration({
      optionsJSON: options.options as Parameters<typeof startRegistration>[0]['optionsJSON'],
    });
    await requestJson(`${AUTH}/recovery/verify`, {
      method: 'POST',
      body: JSON.stringify({ response: credential }),
    });
    goToDashboard();
  } catch (error) {
    showError(friendlyError(error));
  } finally {
    setBusy(false);
  }
}

function displayOneTimeSecrets(codes: string[], token: string): void {
  issuedRecoveryCodes = codes;
  issuedCollectorToken = token;
  recoveryCodes.replaceChildren();
  for (const [index, code] of codes.entries()) {
    const item = document.createElement('code');
    item.textContent = `${String(index + 1).padStart(2, '0')} · ${code}`;
    recoveryCodes.appendChild(item);
  }
  collectorToken.textContent = token;
  secretsConfirmed.checked = false;
  showPanel(secretsPanel);
  updateDisabledState();
}

async function bootstrap(event: SubmitEvent): Promise<void> {
  event.preventDefault();
  setBusy(true);
  showError('');
  const headers = { 'X-BXSS-Bootstrap': bootstrapToken.value.trim() };
  try {
    const options = await requestJson(`${AUTH}/bootstrap/options`, {
      method: 'POST',
      headers,
      body: JSON.stringify({
        email: bootstrapEmail.value.trim(),
        displayName: bootstrapName.value.trim(),
        passkeyName: bootstrapPasskey.value.trim(),
      }),
    });
    const credential = await startRegistration({
      optionsJSON: options.options as Parameters<typeof startRegistration>[0]['optionsJSON'],
    });
    const verified = await requestJson(`${AUTH}/bootstrap/verify`, {
      method: 'POST',
      headers,
      body: JSON.stringify({ response: credential }),
    });
    displayOneTimeSecrets(
      asList(verified.recoveryCodes).map((value) => stringValue(value)).filter(Boolean),
      stringValue(verified.collectorToken),
    );
  } catch (error) {
    showError(friendlyError(error));
  } finally {
    setBusy(false);
  }
}

signinButton.addEventListener('click', () => void signIn());
showRecoveryButton.addEventListener('click', () => {
  showError('');
  showPanel(recoveryPanel);
  recoveryEmail.focus();
});
hideRecoveryButton.addEventListener('click', () => {
  showError('');
  showPanel(signinPanel);
  signinButton.focus();
});
recoveryPanel.addEventListener('submit', (event) => void recover(event));
bootstrapPanel.addEventListener('submit', (event) => void bootstrap(event));
secretsConfirmed.addEventListener('change', updateDisabledState);
openDashboardButton.addEventListener('click', goToDashboard);
copyCodesButton.addEventListener('click', () => void copyValue(copyCodesButton, issuedRecoveryCodes.join('\n')));
copyTokenButton.addEventListener('click', () => void copyValue(copyTokenButton, issuedCollectorToken));
copyAllButton.addEventListener('click', () => void copyValue(
  copyAllButton,
  [...issuedRecoveryCodes, `Initial collector token: ${issuedCollectorToken}`].join('\n'),
));

async function initialize(): Promise<void> {
  try {
    const status = await requestJson(`${AUTH}/status`);
    rpName.textContent = stringValue(status.rp, 'Private access');
    showPanel(status.initialized === true ? signinPanel : bootstrapPanel);
  } catch (error) {
    showPanel(signinPanel);
    showError(friendlyError(error));
  }
}

void initialize();
