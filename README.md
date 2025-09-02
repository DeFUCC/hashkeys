# HashKeys — Vue reactive auth and cryptography

Reactive Noble cryptography for local‑first apps and p2p identity. `hashkeys` exposes a single Vue 3 reactive object that runs all cryptography in a Web Worker and provides a simple API for:

- Authentication from a passphrase or bech32 master key
- Identity and public keys
- Sign/verify
- Symmetric and end‑to‑end encryption
- HKDF key derivation
- PassKeys (WebAuthn) helper flows
- Session persistence

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
- `recall(): Promise<boolean>` — attempts to read the bech32 master key from sessionStorage and log in. Returns `true` if a stored key was found and a login attempt was made.
- `clearError(): void`
- `passKeyAuth(name: string): Promise<boolean>` — creates/registers a WebAuthn credential (PassKey) for the given user name, then logs in using the generated credential ID encoded as `hkwa…`.
- `passKeyLogin(): Promise<boolean>` — prompts for an existing PassKey and logs in using its credential ID encoded as `hkwa…`.

Notes:
- All methods throw if not authenticated, except `verify`, which operates on provided public inputs.
- PassKeys helpers encode the WebAuthn `rawId` with Bech32 HRP `hkwa` and use it as the login secret. The worker derives keys from whatever string you pass to `login()`; `hkwa…` is simply a recognizable wrapper for the credential ID.

---

## Bech32 prefixes

Short, readable Bech32 encodings are used with app prefix `hk` + tag:

- `hkmk…` master key
- `hkpk…` public/verify key
- `hkek…` encryption public key (X25519)
- `hkid…` identity (`SHA256(publicKey)`)
- `hksg…` signature
- `hknc…` nonce
- `hkct…` ciphertext
- `hkdk…` derived key material
- `hkwa…` WebAuthn credential ID (used as a login secret by helpers)

---

## Session persistence

When you authenticate, hashkeys will fetch the bech32 master key (`hkmk…`) from the worker and store it in `sessionStorage` under `hk.masterKey`. When you logout or the page is refreshed without recalling, it is cleared. Use `auth.recall()` at startup to restore the session if a key is present.

- Uses `sessionStorage`, so the key persists for the lifetime of the browser tab/window only.
- The stored value is the bech32-encoded master key, not raw bytes.
- Calling `auth.logout()` clears the stored key.

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

### PassKeys (WebAuthn)
```js
// Create/register a new PassKey for a username and login
await auth.passKeyAuth('alice@example.com');
console.log(auth.identity); // hkid…

// Use an existing PassKey to login
await auth.passKeyLogin();
```

### Session persistence (auto-recall)

```vue
<script setup>
import { onMounted } from 'vue'
import auth from 'hashkeys'

onMounted(() => {
  auth.recall()
})
</script>
```

---

## Minimal HTML example

This mirrors `public/test.html` but targets consumers of the package. Uses Vue's `watch` to react to auth changes.

```html
<!DOCTYPE html>
<html>
  <head>
    <meta charset="utf-8" />
    <script type="importmap">{ "imports": { "vue": "https://esm.sh/vue" } }</script>
  </head>
  <body>
    <div id="app">
      <input id="input" placeholder="passphrase" />
      <button id="login" disabled>LOGIN</button>
      <button id="get-key" disabled>GET KEY</button>
      <pre id="id"></pre>
      <pre id="master"></pre>
    </div>
    <script type="module">
      import { watch } from 'vue';
      import auth from 'hashkeys';

      document.getElementById('get-key').addEventListener('click', async () => {
        document.getElementById('master').textContent = await auth.getMasterKey();
      });

      document.getElementById('input').addEventListener('input', (e) => {
        document.getElementById('login').disabled = !e.target.value;
      });

      document.getElementById('login').addEventListener('click', () => {
        auth.login(document.getElementById('input').value);
      });

      watch(auth, ({ authenticated, identity }) => {
        if (authenticated) {
          document.getElementById('id').textContent = identity;
          document.getElementById('get-key').disabled = false;
        }
      });
    </script>
  </body>
</html>
```

---

## Environment

- Built and tested with Vite + Vue 3; the Worker is bundled for package consumers.
- Works in modern browsers with Web Worker support.
- Avoid persisting raw key bytes; if you must export, prefer the bech32 forms.

---

## License

MIT
