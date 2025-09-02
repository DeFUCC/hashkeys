# hashkeys — Vue reactive auth and crypto

Reactive Noble cryptography for local‑first apps and p2p identity. `hashkeys` exposes a single Vue 3 reactive object that runs all cryptography in a Web Worker and gives you a simple API for:

- Authentication from a passphrase or bech32 master key
- Identity and public keys
- Sign/verify
- Symmetric and end‑to‑end encryption
- HKDF key derivation

---

## Install

- Peer dependency: Vue 3
- Modern bundler (Vite recommended)

```bash
npm i hashkeys
# or
pnpm add hashkeys
```

---

## Quick start (Vue 3)

```vue
<script setup>
import auth from 'hashkeys';

async function onLogin() {
  try {
    // Pass a strong passphrase OR a bech32 master key (hkmk…)
    await auth.login('correct horse battery staple');
    console.log('identity', auth.identity); // hkid…
  } catch (e) {
    console.error(e);
  }
}

async function doSign() {
  const { signature, publicKey } = await auth.sign('hello world');
  console.log(signature, publicKey);
}
</script>

<template>
  <div>
    <button @click="onLogin">Login</button>
    <p v-if="auth.loading">Loading…</p>
    <p v-else>Authenticated: {{ auth.authenticated }}</p>

    <button :disabled="!auth.authenticated" @click="doSign">Sign message</button>

    <div v-if="auth.error" class="error">{{ auth.error }}</div>
  </div>
</template>
```

---

## API

The default export is a Vue `reactive` object with state and async methods that proxy to an internal Worker.

### State
- `authenticated: boolean`
- `loading: boolean`
- `error: string | null`
- `publicKey: string | null` — bech32 `hkpk…`
- `identity: string | null` — bech32 `hkid…` (`SHA256(publicKey)`)
- `encryptionKey: string | null` — bech32 `hkek…` (X25519 public key for E2E on ed25519)
- `curve: 'ed25519' | 'secp256k1' | null`

### Methods
- `login(passwordOrKey: string): Promise<{ authenticated: true, publicKey: string, identity: string, encryptionKey?: string, curve: string }>`
  - Accepts a passphrase or a bech32 master key (`hkmk…`).
- `logout(): Promise<{ authenticated: false }>`
- `sign(message: Uint8Array | string): Promise<{ signature: string, publicKey: string }>`
- `verify(message, signatureB32, publicKeyB32): Promise<{ valid: boolean }>`
- `encrypt(data, recipientPublicKeyB32?, algorithm?): Promise<{ ciphertext: string, nonce: string, algorithm: string }>`
  - Algorithms: `xchacha20poly1305` (default), `aes-256-gcm`, or `xchacha20poly1305-x25519` when `recipientPublicKey` is provided on ed25519/X25519.
- `decrypt(ciphertextB32, nonceB32, senderPublicKeyB32?, algorithm?): Promise<{ decrypted: string, decryptedHex: string }>`
- `deriveKey(context: string, length = 32): Promise<{ derivedKey: string, context, length }>`
- `getIdentity(): Promise<{ identity: string, publicKey: string, curve: string }>`
- `getPublicKey(): Promise<{ publicKey: string, identity: string, curve: string }>`
- `getMasterKey(): Promise<string>` — bech32 `hkmk…`
- `clearError(): void`

Notes:
- All methods throw if not authenticated, except `verify`, which operates on provided public inputs.

---

## Bech32 prefixes

The library uses short, readable Bech32 encodings with an app prefix `hk` and a tag.

- `hkmk…` master key
- `hkpk…` public/verify key
- `hkek…` encryption public key (X25519)
- `hkid…` identity (`SHA256(publicKey)`)
- `hksg…` signature
- `hknc…` nonce
- `hkct…` ciphertext
- `hkdk…` derived key material

---

## Under the hood

All cryptography runs off the main thread in a Worker and uses audited Noble primitives:

- Hash/KDF: `scrypt`, `HKDF-SHA256`, `SHA-256`
- Curves: `ed25519` (default), X25519 for ECDH; `secp256k1` supported via internal switches
- AEAD: `XChaCha20-Poly1305` and `AES-256-GCM`

The `identity` is defined as `SHA256(publicKey)` and is provided as a bech32 string (`hkid…`).

---

## Examples

### Password to identity
```js
await auth.login('correct horse battery staple');
console.log(auth.identity); // hkid…
```

### End‑to‑end encrypt to a recipient
```js
const { ciphertext, nonce, algorithm } = await auth.encrypt('hi', 'hkek1…');
// send {ciphertext, nonce, algorithm} to recipient
```

### Decrypt from a sender
```js
const { decrypted } = await auth.decrypt('hkct1…', 'hknc1…', 'hkek1…', 'xchacha20poly1305-x25519');
```

### Verify someone else’s signature (no login required)
```js
const { valid } = await auth.verify('msg', 'hksg1…', 'hkpk1…');
```

---

## Environment

- Built and tested with Vite + Vue 3; the Worker is bundled for package consumers.
- Works in modern browsers with Web Worker support.
- Avoid persisting raw key bytes; if you must export, prefer the bech32 forms.

---

## License

MIT
