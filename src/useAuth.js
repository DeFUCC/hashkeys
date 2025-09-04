import { reactive, watch } from 'vue';
import AuthWorker from './auth-worker.js?worker&inline';
import { bech32 } from '@scure/base';
import { PassKeyLogin, PassKeyAuth } from './usePassKeys';

const worker = new AuthWorker();
const SESSION_KEY = 'hk.masterKey';
let requestId = 0;
const pending = new Map();

const send = (type, data = null) => {
  const id = ++requestId;
  return new Promise((resolve, reject) => {
    pending.set(id, { resolve, reject });
    worker.postMessage({ id, type, data });
  });
};

export const auth = reactive({
  authenticated: false,
  loading: false,
  error: null,
  publicKey: null,
  identity: null,
  encryptionKey: null,
  curve: null,

  async passKeyAuth(name) {
    const rawId = await PassKeyAuth(name);
    return rawId ? this.login(bech32.encode('hkwa', bech32.toWords(new Uint8Array(rawId)))) : false;
  },

  async passKeyLogin() {
    const rawId = await PassKeyLogin();
    return rawId ? this.login(bech32.encode('hkwa', bech32.toWords(new Uint8Array(rawId)))) : false;
  },

  async login(password) {
    this.loading = true;
    this.error = null;
    return send('auth', password);
  },

  async logout() {
    this.loading = true;
    this.error = null;
    return send('logout');
  },

  sign: (message) => (auth.requireAuth(), send('sign', { message })),
  verify: (message, signature, publicKey) => send('verify', { message, signature, publicKey }),

  encrypt(data, recipientPublicKey = null, algorithm = 'xchacha20poly1305') {
    this.requireAuth();
    return send('encrypt', { data, recipientPublicKey, algorithm });
  },

  decrypt(ciphertext, nonce, senderPublicKey = null, algorithm = 'xchacha20poly1305') {
    this.requireAuth();
    return send('decrypt', { ciphertext, nonce, senderPublicKey, algorithm });
  },

  deriveKey: (context, length = 32) => (auth.requireAuth(), send('derive-key', { context, length })),
  getIdentity: () => (auth.requireAuth(), send('get-identity')),
  getPublicKey: () => (auth.requireAuth(), send('get-public-key')),
  getMasterKey: () => (auth.requireAuth(), send('get-master-key')),

  async recall() {
    const stored = sessionStorage.getItem(SESSION_KEY);
    if (!stored) return false;
    try {
      await this.login(stored);
      return true;
    } catch {
      sessionStorage.removeItem(SESSION_KEY);
      return false;
    }
  },

  clearError: () => auth.error = null,
  requireAuth: () => { if (!auth.authenticated) throw new Error('Not authenticated'); }
});

worker.onmessage = ({ data: { id, success, error, type, result } }) => {
  if (success && type === 'auth' && result?.authenticated) {
    auth.loading = false;
    Object.assign(auth, {
      authenticated: true,
      publicKey: result.publicKey,
      identity: result.identity,
      encryptionKey: result.encryptionKey,
      curve: result.curve || null,
      error: null
    });
  } else if (success && (type === 'logout' || type === 'auth' && !result?.authenticated)) {
    Object.assign(auth, {
      loading: false,
      authenticated: false,
      publicKey: null,
      identity: null,
      encryptionKey: null,
      curve: null,
      error: null
    });
  }

  // Resolve pending request
  if (pending.has(id)) {
    const { resolve, reject } = pending.get(id);
    pending.delete(id);

    if (success) {
      resolve(result);
    } else {
      auth.error = error || 'Unknown error occurred';
      reject(new Error(auth.error));
    }
  }
};

worker.onerror = (error) => {
  console.error('Crypto Worker error:', error);
  auth.error = 'Cryptographic worker failed';
  auth.loading = false;
};

// Persist master key while authenticated
watch(() => auth.authenticated, async (authenticated) => {
  try {
    if (authenticated) {
      const mk = await auth.getMasterKey();
      if (mk) sessionStorage.setItem(SESSION_KEY, mk);
    } else {
      sessionStorage.removeItem(SESSION_KEY);
    }
  } catch { }
});

export default auth;