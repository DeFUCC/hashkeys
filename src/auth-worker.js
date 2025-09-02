import { scrypt } from '@noble/hashes/scrypt.js';
import { sha256 } from '@noble/hashes/sha2.js';
import { hkdf } from '@noble/hashes/hkdf.js';
import { bech32 } from '@scure/base';

// Symmetric encryption
import { xchacha20poly1305 } from '@noble/ciphers/chacha.js';
import { gcm } from '@noble/ciphers/aes.js';

// Asymmetric cryptography
import { ed25519, x25519 } from '@noble/curves/ed25519.js';
import { secp256k1 } from '@noble/curves/secp256k1.js';

// Utils
import { bytesToHex, hexToBytes, concatBytes, randomBytes } from '@noble/curves/utils.js';

const appPrefix = 'ig';
const versionSalt = 'ig_v1';
const CURVE_TYPE = 'ed25519'; // Can be 'ed25519' or 'secp256k1'

const encoder = new TextEncoder();
const decoder = new TextDecoder();

// In-memory cryptographic state
let cryptoState = {
  masterKey: null,
  privateKey: null,
  publicKey: null,
  signingKey: null,
  verifyingKey: null,
  encryptionKey: null,
  identity: null
};

// Key derivation contexts
const CONTEXTS = {
  SIGNING: 'signing',
  ENCRYPTION: 'encryption',
  IDENTITY: 'identity'
};

self.onmessage = async (e) => {
  const { id, type, data } = e.data;
  try {
    if (type && handlers[type]) {
      await handlers[type](id, data);
    } else {
      self.postMessage({ id, success: false, error: 'Unknown handler type' });
    }
  } catch (error) {
    self.postMessage({ id, success: false, error: error.message });
  }
};

// Derive specialized keys from master key using HKDF
function deriveKey(context, length = 32) {
  if (!cryptoState.masterKey) throw new Error('Master key not available');
  return hkdf(sha256, cryptoState.masterKey, encoder.encode(context), encoder.encode(versionSalt), length);
}

// Initialize cryptographic keys from master key
function initializeCryptoKeys() {
  if (!cryptoState.masterKey) return;

  // Derive signing private key
  const signingKeyMaterial = deriveKey(CONTEXTS.SIGNING, 32);

  if (CURVE_TYPE === 'ed25519') {
    cryptoState.signingKey = signingKeyMaterial;
    cryptoState.verifyingKey = ed25519.getPublicKey(cryptoState.signingKey);
    cryptoState.publicKey = cryptoState.verifyingKey;

    // Derive X25519 key for encryption from Ed25519 key
    cryptoState.privateKey = signingKeyMaterial;
    cryptoState.encryptionKey = x25519.getPublicKey(cryptoState.privateKey);
  } else if (CURVE_TYPE === 'secp256k1') {
    cryptoState.privateKey = signingKeyMaterial;
    cryptoState.publicKey = secp256k1.getPublicKey(cryptoState.privateKey, true); // compressed
    cryptoState.signingKey = cryptoState.privateKey;
    cryptoState.verifyingKey = cryptoState.publicKey;
  }

  // Create identity hash from public key
  cryptoState.identity = sha256(cryptoState.publicKey);
}

// Generate deterministic nonce for encryption
function generateNonce(context, counter = 0) {
  const nonceKey = deriveKey(`nonce_${context}`, 32);
  const counterBytes = new Uint8Array(8);
  new DataView(counterBytes.buffer).setBigUint64(0, BigInt(counter), false);
  return sha256(concatBytes(nonceKey, counterBytes)).slice(0, 24); // 192-bit nonce for XChaCha20
}

const handlers = {
  async auth(id, data) {
    if (!data) {
      self.postMessage({ id, success: false, error: 'No auth data provided' });
      return;
    }

    const normalized = String(data).normalize('NFC').toLowerCase().trim();

    try {
      // Try to decode as bech32 first
      let { prefix, words } = bech32.decode(normalized);
      if (prefix === appPrefix && words.length === 52) {
        cryptoState.masterKey = bech32.fromWords(words);
      }
    } catch (e) {
      // Fallback to password-based key derivation
      cryptoState.masterKey = scrypt(
        encoder.encode(normalized),
        encoder.encode(versionSalt),
        { N: 1 << 17, r: 8, p: 1, dkLen: 32 }
      );
    }

    // Initialize all cryptographic keys
    initializeCryptoKeys();

    self.postMessage({
      id,
      type: 'auth',
      success: true,
      result: {
        authenticated: true,
        publicKey: bytesToHex(cryptoState.publicKey),
        identity: bytesToHex(cryptoState.identity),
        encryptionKey: CURVE_TYPE === 'ed25519' ? bytesToHex(cryptoState.encryptionKey) : null
      }
    });
  },

  logout(id) {
    // Securely clear all keys
    Object.keys(cryptoState).forEach(key => {
      if (cryptoState[key] instanceof Uint8Array) {
        cryptoState[key].fill(0);
      }
      cryptoState[key] = null;
    });

    self.postMessage({ id, type: 'logout', success: true, result: { authenticated: false } });
  },

  'get-public-key'(id) {
    if (!cryptoState.publicKey) {
      self.postMessage({ id, success: false, error: 'Not authenticated' });
      return;
    }

    self.postMessage({
      id,
      success: true,
      result: {
        publicKey: bytesToHex(cryptoState.publicKey),
        identity: bytesToHex(cryptoState.identity),
        curve: CURVE_TYPE
      }
    });
  },

  'get-master-key'(id) {
    if (!cryptoState.masterKey) {
      self.postMessage({ id, success: false, error: 'Not authenticated' });
      return;
    }

    self.postMessage({
      id,
      type: 'master-key',
      success: true,
      result: bech32.encode(appPrefix, bech32.toWords(cryptoState.masterKey))
    });
  },

  async sign(id, { message, encoding = 'utf8' }) {
    if (!cryptoState.signingKey) {
      self.postMessage({ id, success: false, error: 'Not authenticated' });
      return;
    }

    let messageBytes;
    if (encoding === 'hex') {
      messageBytes = hexToBytes(message);
    } else {
      messageBytes = encoder.encode(message);
    }

    let signature;
    if (CURVE_TYPE === 'ed25519') {
      signature = ed25519.sign(messageBytes, cryptoState.signingKey);
    } else if (CURVE_TYPE === 'secp256k1') {
      signature = secp256k1.sign(sha256(messageBytes), cryptoState.signingKey).toCompactRawBytes();
    }

    self.postMessage({
      id,
      success: true,
      result: {
        signature: bytesToHex(signature),
        publicKey: bytesToHex(cryptoState.verifyingKey)
      }
    });
  },

  async verify(id, { message, signature, publicKey, encoding = 'utf8' }) {
    let messageBytes;
    if (encoding === 'hex') {
      messageBytes = hexToBytes(message);
    } else {
      messageBytes = encoder.encode(message);
    }

    const signatureBytes = hexToBytes(signature);
    const publicKeyBytes = hexToBytes(publicKey);

    let isValid;
    if (CURVE_TYPE === 'ed25519') {
      isValid = ed25519.verify(signatureBytes, messageBytes, publicKeyBytes);
    } else if (CURVE_TYPE === 'secp256k1') {
      isValid = secp256k1.verify(signatureBytes, sha256(messageBytes), publicKeyBytes);
    }

    self.postMessage({ id, success: true, result: { valid: isValid } });
  },

  async encrypt(id, { data, recipientPublicKey, encoding = 'utf8', algorithm = 'xchacha20poly1305' }) {
    if (!cryptoState.privateKey) {
      self.postMessage({ id, success: false, error: 'Not authenticated' });
      return;
    }

    let dataBytes;
    if (encoding === 'hex') {
      dataBytes = hexToBytes(data);
    } else {
      dataBytes = encoder.encode(data);
    }

    if (CURVE_TYPE === 'ed25519' && recipientPublicKey) {
      // Perform X25519 key exchange
      const sharedSecret = x25519.getSharedSecret(cryptoState.privateKey, hexToBytes(recipientPublicKey));
      const encryptionKey = sha256(sharedSecret);

      const nonce = randomBytes(24); // XChaCha20 nonce
      const cipher = xchacha20poly1305(encryptionKey, nonce);
      const encrypted = cipher.encrypt(dataBytes);

      self.postMessage({
        id,
        success: true,
        result: {
          encrypted: bytesToHex(encrypted),
          nonce: bytesToHex(nonce),
          algorithm: 'xchacha20poly1305-x25519'
        }
      });
    } else {
      // Symmetric encryption with derived key
      const encKey = deriveKey('data_encryption', 32);
      const nonce = randomBytes(algorithm === 'aes-256-gcm' ? 12 : 24);

      let cipher, encrypted;
      if (algorithm === 'aes-256-gcm') {
        cipher = gcm(encKey, nonce);
        encrypted = cipher.encrypt(dataBytes);
      } else {
        cipher = xchacha20poly1305(encKey, nonce);
        encrypted = cipher.encrypt(dataBytes);
      }

      self.postMessage({
        id,
        success: true,
        result: {
          encrypted: bytesToHex(encrypted),
          nonce: bytesToHex(nonce),
          algorithm
        }
      });
    }
  },

  async decrypt(id, { encrypted, nonce, senderPublicKey, algorithm = 'xchacha20poly1305' }) {
    if (!cryptoState.privateKey) {
      self.postMessage({ id, success: false, error: 'Not authenticated' });
      return;
    }

    const encryptedBytes = hexToBytes(encrypted);
    const nonceBytes = hexToBytes(nonce);

    let decrypted;

    if (algorithm === 'xchacha20poly1305-x25519' && senderPublicKey) {
      // X25519 key exchange decryption
      const sharedSecret = x25519.getSharedSecret(cryptoState.privateKey, hexToBytes(senderPublicKey));
      const decryptionKey = sha256(sharedSecret);

      const cipher = xchacha20poly1305(decryptionKey, nonceBytes);
      decrypted = cipher.decrypt(encryptedBytes);
    } else {
      // Symmetric decryption
      const decKey = deriveKey('data_encryption', 32);

      let cipher;
      if (algorithm === 'aes-256-gcm') {
        cipher = gcm(decKey, nonceBytes);
      } else {
        cipher = xchacha20poly1305(decKey, nonceBytes);
      }

      decrypted = cipher.decrypt(encryptedBytes);
    }

    self.postMessage({
      id,
      success: true,
      result: {
        decrypted: decoder.decode(decrypted),
        decryptedHex: bytesToHex(decrypted)
      }
    });
  },

  async 'derive-key'(id, { context, length = 32 }) {
    if (!cryptoState.masterKey) {
      self.postMessage({ id, success: false, error: 'Not authenticated' });
      return;
    }

    const derivedKey = deriveKey(context, length);

    self.postMessage({
      id,
      success: true,
      result: {
        derivedKey: bytesToHex(derivedKey),
        context,
        length
      }
    });
  },

  async 'get-identity'(id) {
    if (!cryptoState.identity) {
      self.postMessage({ id, success: false, error: 'Not authenticated' });
      return;
    }

    self.postMessage({
      id,
      success: true,
      result: {
        identity: bytesToHex(cryptoState.identity),
        publicKey: bytesToHex(cryptoState.publicKey),
        curve: CURVE_TYPE
      }
    });
  }
};