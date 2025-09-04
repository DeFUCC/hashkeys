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
import { bytesToHex, hexToBytes, randomBytes } from '@noble/curves/utils.js';

let appPrefix = 'hk';            // base HRP (mutable via init)
let versionSalt = `${appPrefix}_v1`;       // KDF salt/version (ties to prefix)
const CURVE_TYPE = 'ed25519';      // 'ed25519' | 'secp256k1'

// Standard short tags (HRP = appPrefix + tag)
const TAG = Object.freeze({
  MK: 'mk',   // master key (32)
  PK: 'pk',   // public key (verify)
  SK: 'sk',   // signing private (32) [export optional]
  EK: 'ek',   // encryption public (x25519 or secp)
  ID: 'id',   // identity hash (32)
  SG: 'sg',   // signature
  NC: 'nc',   // nonce
  CT: 'ct',   // ciphertext
  DK: 'dk'    // derived key material
});

const encoder = new TextEncoder();
const decoder = new TextDecoder();

let cryptoState = {
  masterKey: null,
  privateKey: null,
  publicKey: null,
  signingKey: null,
  verifyingKey: null,
  encryptionKey: null,
  identity: null
};

// Contexts for HKDF
const CONTEXTS = {
  SIGNING: 'signing',
  ENCRYPTION: 'encryption',
  IDENTITY: 'identity'
};

// ---------- Bech32 helpers ----------
const hrp = (tag) => `${appPrefix}${tag}`;
const encB32 = (tag, bytes) => bech32.encode(hrp(tag), bech32.toWords(bytes), false);
const tryDecB32 = (s) => {
  try {
    const { prefix, words } = bech32.decode(String(s).trim(), false);
    if (!prefix.startsWith(appPrefix)) return null;
    const tag = prefix.slice(appPrefix.length);
    return { tag, bytes: bech32.fromWords(words) };
  } catch (_) { return null; }
};

// Flexible bytes parser: prefers bech32; falls back to hex; else utf8
function asBytes(input) {
  if (typeof input === 'string') {
    const b = tryDecB32(input);
    if (b) return b.bytes;
    const s = input.trim();
    if (/^[0-9a-fA-F]+$/.test(s) && s.length % 2 === 0) return hexToBytes(s);
    return encoder.encode(s);
  }
  return input instanceof Uint8Array ? input : new Uint8Array([]);
}

// Key derivation via HKDF
function deriveKey(context, length = 32) {
  if (!cryptoState.masterKey) throw new Error('Master key not available');
  return hkdf(sha256, cryptoState.masterKey, encoder.encode(context), encoder.encode(versionSalt), length);
}

function initializeCryptoKeys() {
  if (!cryptoState.masterKey) return;

  const signingKeyMaterial = deriveKey(CONTEXTS.SIGNING, 32);

  if (CURVE_TYPE === 'ed25519') {
    cryptoState.signingKey = signingKeyMaterial;
    cryptoState.verifyingKey = ed25519.getPublicKey(cryptoState.signingKey);
    cryptoState.publicKey = cryptoState.verifyingKey;

    // Derive X25519 key for encryption from Ed25519 key material
    cryptoState.privateKey = signingKeyMaterial;
    cryptoState.encryptionKey = x25519.getPublicKey(cryptoState.privateKey);
  } else if (CURVE_TYPE === 'secp256k1') {
    cryptoState.privateKey = signingKeyMaterial;
    cryptoState.publicKey = secp256k1.getPublicKey(cryptoState.privateKey, true); // compressed
    cryptoState.signingKey = cryptoState.privateKey;
    cryptoState.verifyingKey = cryptoState.publicKey;
  }

  cryptoState.identity = sha256(cryptoState.publicKey);
}

// ---------- Message handlers ----------
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

const handlers = {
  init(id, data) {
    const requested = (data && typeof data.appPrefix === 'string') ? data.appPrefix.trim().toLowerCase() : '';
    if (requested) {
      if (!/^[a-z]{2}$/.test(requested)) {
        self.postMessage({ id, success: false, error: 'appPrefix must be exactly 2 lowercase letters' });
        return;
      }
      appPrefix = requested;
      versionSalt = `${appPrefix}_v1`;
    } else {
      // keep defaults
      appPrefix = appPrefix || 'hk';
      versionSalt = `${appPrefix}_v1`;
    }
    self.postMessage({ id, type: 'init', success: true, result: { appPrefix, versionSalt } });
  },

  async auth(id, data) {
    if (!data) {
      self.postMessage({ id, success: false, error: 'No auth data provided' });
      return;
    }

    const normalized = String(data).normalize('NFC').trim();

    // Import master key: prefer bech32 igmk..., accept legacy ig... or derive from password
    const b = tryDecB32(normalized);
    if (b && (b.tag === TAG.MK || b.tag === '' /* legacy */)) {
      cryptoState.masterKey = b.bytes;
    } else {
      // legacy: appPrefix without tag and exact length (compat)
      try {
        const { prefix, words } = bech32.decode(normalized, false);
        if (prefix === appPrefix) cryptoState.masterKey = bech32.fromWords(words);
      } catch (_) { }
      if (!cryptoState.masterKey) {
        cryptoState.masterKey = scrypt(
          encoder.encode(normalized.toLowerCase()),
          encoder.encode(versionSalt),
          { N: 1 << 17, r: 8, p: 1, dkLen: 32 }
        );
      }
    }

    initializeCryptoKeys();

    self.postMessage({
      id,
      type: 'auth',
      success: true,
      result: {
        authenticated: true,
        publicKey: encB32(TAG.PK, cryptoState.publicKey),
        identity: encB32(TAG.ID, cryptoState.identity),
        encryptionKey: CURVE_TYPE === 'ed25519' ? encB32(TAG.EK, cryptoState.encryptionKey) : null,
        curve: CURVE_TYPE
      }
    });
  },

  logout(id) {
    Object.keys(cryptoState).forEach((key) => {
      if (cryptoState[key] instanceof Uint8Array) cryptoState[key].fill(0);
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
        publicKey: encB32(TAG.PK, cryptoState.publicKey),
        identity: encB32(TAG.ID, cryptoState.identity),
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
      result: encB32(TAG.MK, cryptoState.masterKey)
    });
  },

  async sign(id, { message }) {
    if (!cryptoState.signingKey) {
      self.postMessage({ id, success: false, error: 'Not authenticated' });
      return;
    }

    const messageBytes = asBytes(message);

    let signature;
    if (CURVE_TYPE === 'ed25519') {
      signature = ed25519.sign(messageBytes, cryptoState.signingKey);
    } else {
      signature = secp256k1.sign(sha256(messageBytes), cryptoState.signingKey).toCompactRawBytes();
    }

    self.postMessage({
      id,
      success: true,
      result: {
        signature: encB32(TAG.SG, signature),
        publicKey: encB32(TAG.PK, cryptoState.verifyingKey)
      }
    });
  },

  async verify(id, { message, signature, publicKey }) {
    const messageBytes = asBytes(message);

    const sigB = tryDecB32(signature);
    const pkB = tryDecB32(publicKey);
    if (!sigB || sigB.tag !== TAG.SG || !pkB || (pkB.tag !== TAG.PK && pkB.tag !== TAG.EK)) {
      self.postMessage({ id, success: false, error: 'Invalid bech32 inputs for signature/publicKey' });
      return;
    }

    const signatureBytes = sigB.bytes;
    const publicKeyBytes = pkB.bytes;

    let isValid;
    if (CURVE_TYPE === 'ed25519') {
      isValid = ed25519.verify(signatureBytes, messageBytes, publicKeyBytes);
    } else {
      isValid = secp256k1.verify(signatureBytes, sha256(messageBytes), publicKeyBytes);
    }

    self.postMessage({ id, success: true, result: { valid: isValid } });
  },

  async encrypt(id, { data, recipientPublicKey, algorithm = 'xchacha20poly1305' }) {
    if (!cryptoState.privateKey) {
      self.postMessage({ id, success: false, error: 'Not authenticated' });
      return;
    }

    const dataBytes = asBytes(data);

    if (CURVE_TYPE === 'ed25519' && recipientPublicKey) {
      const rec = tryDecB32(recipientPublicKey);
      if (!rec || (rec.tag !== TAG.EK && rec.tag !== TAG.PK)) {
        self.postMessage({ id, success: false, error: 'recipientPublicKey must be bech32 igek... or igpk...' });
        return;
      }

      // X25519 key exchange
      const sharedSecret = x25519.getSharedSecret(cryptoState.privateKey, rec.bytes);
      const encryptionKey = sha256(sharedSecret);

      const nonce = randomBytes(24);
      const cipher = xchacha20poly1305(encryptionKey, nonce);
      const encrypted = cipher.encrypt(dataBytes);

      self.postMessage({
        id,
        success: true,
        result: {
          ciphertext: encB32(TAG.CT, encrypted),
          nonce: encB32(TAG.NC, nonce),
          algorithm: 'xchacha20poly1305-x25519'
        }
      });
    } else {
      // Symmetric encryption with derived key
      const encKey = deriveKey('data_encryption', 32);
      const nonce = randomBytes(algorithm === 'aes-256-gcm' ? 12 : 24);

      let encrypted;
      if (algorithm === 'aes-256-gcm') {
        encrypted = gcm(encKey, nonce).encrypt(dataBytes);
      } else {
        encrypted = xchacha20poly1305(encKey, nonce).encrypt(dataBytes);
      }

      self.postMessage({
        id,
        success: true,
        result: {
          ciphertext: encB32(TAG.CT, encrypted),
          nonce: encB32(TAG.NC, nonce),
          algorithm
        }
      });
    }
  },

  async decrypt(id, { ciphertext, nonce, senderPublicKey, algorithm = 'xchacha20poly1305' }) {
    if (!cryptoState.privateKey) {
      self.postMessage({ id, success: false, error: 'Not authenticated' });
      return;
    }

    const ctB = tryDecB32(ciphertext);
    const ncB = tryDecB32(nonce);
    if (!ctB || ctB.tag !== TAG.CT || !ncB || ncB.tag !== TAG.NC) {
      self.postMessage({ id, success: false, error: 'ciphertext/nonce must be bech32 igct.../ignc...' });
      return;
    }
    const encryptedBytes = ctB.bytes;
    const nonceBytes = ncB.bytes;

    let decrypted;

    if (algorithm === 'xchacha20poly1305-x25519' && senderPublicKey) {
      const sen = tryDecB32(senderPublicKey);
      if (!sen || (sen.tag !== TAG.EK && sen.tag !== TAG.PK)) {
        self.postMessage({ id, success: false, error: 'senderPublicKey must be bech32 igek... or igpk...' });
        return;
      }
      const sharedSecret = x25519.getSharedSecret(cryptoState.privateKey, sen.bytes);
      const decryptionKey = sha256(sharedSecret);
      decrypted = xchacha20poly1305(decryptionKey, nonceBytes).decrypt(encryptedBytes);
    } else {
      const decKey = deriveKey('data_encryption', 32);
      if (algorithm === 'aes-256-gcm') {
        decrypted = gcm(decKey, nonceBytes).decrypt(encryptedBytes);
      } else {
        decrypted = xchacha20poly1305(decKey, nonceBytes).decrypt(encryptedBytes);
      }
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
        derivedKey: encB32(TAG.DK, derivedKey),
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
        identity: encB32(TAG.ID, cryptoState.identity),
        publicKey: encB32(TAG.PK, cryptoState.publicKey),
        curve: CURVE_TYPE
      }
    });
  }
};