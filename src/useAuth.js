import { reactive, watch } from 'vue';
import { bech32 } from '@scure/base';
import AuthWorker from './auth-worker.js?worker&inline';
import { PassKeyLogin, PassKeyAuth } from './usePassKeys';

export { AuthWorker, useAuth }
export default useAuth

function useAuth(options = {}) {

  const normalizePrefix = (opt) => {
    const val = typeof opt === 'string'
      ? opt
      : (typeof opt?.value === 'string' ? opt.value : (typeof opt?.prefix === 'string' ? opt.prefix : (typeof opt?.prefix?.value === 'string' ? opt.prefix.value : 'hk')));
    const s = String(val || 'hk').trim().toLowerCase();
    return /^[a-z]{2}$/.test(s) ? s : 'hk';
  };

  let prefix = normalizePrefix(options);

  const worker = new AuthWorker();

  const sessionKeyFor = (p) => `${p}.masterKey`;
  let requestId = 0;
  const pending = new Map();

  const send = (type, data = null) => {
    const id = ++requestId;
    return new Promise((resolve, reject) => {
      pending.set(id, { resolve, reject });
      worker.postMessage({ id, type, data });
    });
  };

  send('init', { appPrefix: prefix })


  const auth = reactive({
    authenticated: false,
    loading: false,
    error: null,
    publicKey: null,
    identity: null,
    encryptionKey: null,
    curve: null,

    async passKeyAuth(name) {
      const rawId = await PassKeyAuth(name);
      return rawId ? this.login(bech32.encode(`${prefix}wa`, bech32.toWords(new Uint8Array(rawId)))) : false;
    },

    async passKeyLogin() {
      const rawId = await PassKeyLogin();
      return rawId ? this.login(bech32.encode(`${prefix}wa`, bech32.toWords(new Uint8Array(rawId)))) : false;
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

    sign({ message } = {}) {
      if (!auth.authenticated) throw new Error('Not authenticated');
      return send('sign', { message })
    },
    verify({ message, signature, publicKey } = {}) {
      return send('verify', { message, signature, publicKey })
    },
    encrypt({ data, recipientPublicKey = null, algorithm = 'xchacha20poly1305' } = {}) {
      if (!auth.authenticated) throw new Error('Not authenticated');
      return send('encrypt', { data, recipientPublicKey, algorithm });
    },

    decrypt({ ciphertext, nonce, senderPublicKey = null, algorithm = 'xchacha20poly1305' } = {}) {
      if (!auth.authenticated) throw new Error('Not authenticated');
      return send('decrypt', { ciphertext, nonce, senderPublicKey, algorithm });
    },

    deriveKey({ context, length = 32 } = {}) {
      if (!auth.authenticated) throw new Error('Not authenticated');
      return send('derive-key', { context, length })
    },

    getIdentity() {
      if (!auth.authenticated) throw new Error('Not authenticated');
      return send('get-identity')
    },
    getPublicKey() {
      if (!auth.authenticated) throw new Error('Not authenticated');
      return send('get-public-key')
    },
    getMasterKey() {
      if (!auth.authenticated) throw new Error('Not authenticated');
      return send('get-master-key')
    },
    getSplitKey(data) {
      if (!auth.authenticated) throw new Error('Not authenticated');
      return send('get-split-key', data)
    },
    combineKey(data) {
      if (!auth.authenticated) throw new Error('Not authenticated');
      return send('combine-key', data)
    },

    async recall() {
      // Try current prefix, then legacy 'hk'
      const preferred = sessionStorage.getItem(sessionKeyFor(prefix));
      const legacy = prefix !== 'hk' ? sessionStorage.getItem(sessionKeyFor('hk')) : null;
      const stored = preferred || legacy;
      if (!stored) return false;
      try {
        await this.login(stored);
        // If legacy key was used under non-hk prefix, re-persist under current and remove legacy
        if (!preferred && legacy && prefix !== 'hk') {
          sessionStorage.setItem(sessionKeyFor(prefix), stored);
          sessionStorage.removeItem(sessionKeyFor('hk'));
        }
        return true;
      } catch {
        sessionStorage.removeItem(sessionKeyFor(prefix));
        return false;
      }
    },
    clearError() {
      auth.error = null;
    },
  });

  worker.onmessage = ({ data: { id, success, error, type, result } }) => {
    if (success && type === 'init' && result?.appPrefix) {
      // Keep prefix in sync with worker in case it sanitized it
      const effective = String(result.appPrefix || '').trim().toLowerCase();
      if (effective && /^[a-z]{2}$/.test(effective)) prefix = effective;
    }

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
        if (mk) sessionStorage.setItem(sessionKeyFor(prefix), mk);
      } else {
        sessionStorage.removeItem(sessionKeyFor(prefix));
      }
    } catch { }
  });

  return auth
}