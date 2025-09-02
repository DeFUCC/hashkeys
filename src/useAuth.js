import { reactive } from 'vue';
import AuthWorker from './auth-worker.js?worker&inline';

const worker = new AuthWorker();

// Reactive state
export const auth = reactive({
  // Authentication state
  authenticated: false,
  loading: false,
  error: null,

  // Identity & keys
  publicKey: null,
  identity: null,
  encryptionKey: null,
  curve: null,

  // Request tracking
  requestId: 0,
  pendingRequests: new Map(),

  // Core authentication methods
  async login(password) {
    this.loading = true;
    this.error = null;

    return new Promise((resolve, reject) => {
      const id = ++this.requestId;
      this.pendingRequests.set(id, { resolve, reject, type: 'login' });
      worker.postMessage({ id, type: 'auth', data: password });
    });
  },

  async logout() {
    this.loading = true;
    this.error = null;

    return new Promise((resolve, reject) => {
      const id = ++this.requestId;
      this.pendingRequests.set(id, { resolve, reject, type: 'logout' });
      worker.postMessage({ id, type: 'logout' });
    });
  },

  // Cryptographic operations
  async sign(message) {
    if (!this.authenticated) throw new Error('Not authenticated');

    return new Promise((resolve, reject) => {
      const id = ++this.requestId;
      this.pendingRequests.set(id, { resolve, reject, type: 'sign' });
      worker.postMessage({ id, type: 'sign', data: { message } });
    });
  },

  async verify(message, signature, publicKey) {
    return new Promise((resolve, reject) => {
      const id = ++this.requestId;
      this.pendingRequests.set(id, { resolve, reject, type: 'verify' });
      worker.postMessage({
        id,
        type: 'verify',
        data: { message, signature, publicKey }
      });
    });
  },

  async encrypt(data, recipientPublicKey = null, algorithm = 'xchacha20poly1305') {
    if (!this.authenticated) throw new Error('Not authenticated');

    return new Promise((resolve, reject) => {
      const id = ++this.requestId;
      this.pendingRequests.set(id, { resolve, reject, type: 'encrypt' });
      worker.postMessage({
        id,
        type: 'encrypt',
        data: { data, recipientPublicKey, algorithm }
      });
    });
  },

  async decrypt(ciphertext, nonce, senderPublicKey = null, algorithm = 'xchacha20poly1305') {
    if (!this.authenticated) throw new Error('Not authenticated');

    return new Promise((resolve, reject) => {
      const id = ++this.requestId;
      this.pendingRequests.set(id, { resolve, reject, type: 'decrypt' });
      worker.postMessage({
        id,
        type: 'decrypt',
        data: { ciphertext, nonce, senderPublicKey, algorithm }
      });
    });
  },

  async deriveKey(context, length = 32) {
    if (!this.authenticated) throw new Error('Not authenticated');

    return new Promise((resolve, reject) => {
      const id = ++this.requestId;
      this.pendingRequests.set(id, { resolve, reject, type: 'deriveKey' });
      worker.postMessage({
        id,
        type: 'derive-key',
        data: { context, length }
      });
    });
  },

  async getIdentity() {
    if (!this.authenticated) throw new Error('Not authenticated');

    return new Promise((resolve, reject) => {
      const id = ++this.requestId;
      this.pendingRequests.set(id, { resolve, reject, type: 'getIdentity' });
      worker.postMessage({ id, type: 'get-identity' });
    });
  },

  async getPublicKey() {
    if (!this.authenticated) throw new Error('Not authenticated');

    return new Promise((resolve, reject) => {
      const id = ++this.requestId;
      this.pendingRequests.set(id, { resolve, reject, type: 'getPublicKey' });
      worker.postMessage({ id, type: 'get-public-key' });
    });
  },

  async getMasterKey() {
    if (!this.authenticated) throw new Error('Not authenticated');

    return new Promise((resolve, reject) => {
      const id = ++this.requestId;
      this.pendingRequests.set(id, { resolve, reject, type: 'getMasterKey' });
      worker.postMessage({ id, type: 'get-master-key' });
    });
  },

  // Helper methods
  clearError() {
    this.error = null;
  },
});

// Worker message handlers
const handlers = {
  auth(data) {
    auth.loading = false;

    if (data.result?.authenticated) {
      auth.authenticated = true;
      auth.publicKey = data.result.publicKey;
      auth.identity = data.result.identity;
      auth.encryptionKey = data.result.encryptionKey;
      auth.curve = data.result.curve || null;
      auth.error = null;
    } else {
      auth.authenticated = false;
      auth.publicKey = null;
      auth.identity = null;
      auth.encryptionKey = null;
      auth.curve = null;
    }
  },

  logout(data) {
    auth.loading = false;
    auth.authenticated = false;
    auth.publicKey = null;
    auth.identity = null;
    auth.encryptionKey = null;
    auth.curve = null;
    auth.error = null;
  }
};

// Worker message router
worker.onmessage = ({ data }) => {
  const { id, success, error, type, result } = data;

  // Handle specific type responses first
  if (success && handlers[type]) {
    handlers[type](data);
  }

  // Handle pending promise requests
  if (id && auth.pendingRequests.has(id)) {
    const { resolve, reject } = auth.pendingRequests.get(id);
    auth.pendingRequests.delete(id);

    if (success) {
      resolve(result);
    } else {
      const errorMsg = error || 'Unknown error occurred';
      auth.error = errorMsg;
      reject(new Error(errorMsg));
    }
  }
};

worker.onerror = (error) => {
  console.error('Crypto Worker error:', error);
  auth.error = 'Cryptographic worker failed';
  auth.loading = false;
};

export default auth;