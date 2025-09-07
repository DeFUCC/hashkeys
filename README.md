# HashKeys

Reactive Noble cryptography for local‑first apps and p2p identity. `hashkeys` exposes a Vue 3 composable `useAuth()` that returns a reactive object running all cryptography in a Web Worker and provides a simple API for:

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
import { useAuth } from 'hashkeys';

// Optional: customize app prefix for bech32 encodings (defaults to 'hk')
const auth = useAuth('hk');

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
  const { signature, publicKey } = await auth.sign({ message: 'hello world' });
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

The package exports a composable `useAuth()` (also as the default export) that returns a Vue `reactive` object with state and async methods that proxy to an internal Worker. The worker itself is also provided as `AuthWorker` for direct use.

### Constructing

- `useAuth(prefixOrOptions?)`
  - `prefixOrOptions` can be:
    - string: e.g. `'hk'`
    - Vue Ref('string'): e.g. `ref('hk')`
    - object: `{ prefix: 'hk' }` or `{ prefix: ref('hk') }`
  - The prefix must be exactly 2 lowercase letters; invalid inputs fall back to `'hk'`.

### State

- `authenticated: boolean`
- `loading: boolean`
- `error: string | null`
- `publicKey: string | null` — bech32 `hkpk…`
- `identity: string | null` — bech32 `hkid…` (`SHA256(publicKey)`)
- `encryptionKey: string | null` — bech32 `hkek…` (X25519 public key for E2E on ed25519)
- `curve: 'ed25519' | 'secp256k1' | null`

### Methods

#### login(secret)

Authenticate using a passphrase or a bech32 master key.

Parameters:

- `secret` — string. Either a strong passphrase or `hkmk…` bech32 master key.

Returns: object with `authenticated: true` and current keys (`publicKey`, `identity`, optionally `encryptionKey`, `curve`).

#### logout()

End the session and clear in-memory state. Also clears the stored master key in session storage.

Returns: object with `authenticated: false`.

#### sign({ message })

Create a detached signature for the provided data.

Parameters:

- `message` — string or Uint8Array. The data to sign.

Returns: `{ signature, publicKey }` (bech32-encoded).

Requires authentication.

#### verify({ message, signature, publicKey })

Verify a detached signature using the provided public key. Does not require authentication.

Parameters:

- `message` — string or Uint8Array. The original message that was signed.
- `signature` — bech32 `hksg…`. The signature to verify.
- `publicKey` — bech32 `hkpk…`. The public key to verify against.

Returns: `{ valid: boolean }`.

#### encrypt({ data, recipientPublicKey, algorithm })

Encrypt data. If `recipientPublicKey` is omitted, uses a symmetric key derived from your master key. If provided, performs E2E encryption (ed25519/X25519) to the recipient.

Parameters:

- `data` — string or Uint8Array. The data to encrypt.
- `recipientPublicKey` — optional bech32 `hkek…` (recipient's X25519 public key).
- `algorithm` — optional string. Defaults to `xchacha20poly1305`. With a recipient on ed25519, the algorithm becomes `xchacha20poly1305-x25519`.

Returns: `{ ciphertext, nonce, algorithm }` (nonce/ciphertext bech32-encoded).

Requires authentication.

#### decrypt({ ciphertext, nonce, senderPublicKey, algorithm })

Decrypt data. For symmetric self-encryption, only `ciphertext` and `nonce` are required. For E2E, provide the sender's public key so the worker can derive the shared secret via ECDH (your private key never leaves the worker).

Parameters:

- `ciphertext` — bech32 `hkct…`.
- `nonce` — bech32 `hknc…`.
- `senderPublicKey` — optional bech32 `hkek…` (sender's X25519 public key). Required for E2E.
- `algorithm` — optional string. Usually the value returned by `encrypt()`.

Returns: `{ decrypted, decryptedHex }`.

Requires authentication.

#### deriveKey({ context, length })

Derive application- or feature-specific key material using HKDF.

Parameters:

- `context` — string. A namespace for the derivation (e.g., app or feature name).
- `length` — number, optional. Bytes of key material to derive (default 32).

Returns: `{ derivedKey, context, length }` (bech32-derived key material).

Requires authentication.

#### getIdentity()

Fetch identity information.

Returns: `{ identity, publicKey, curve }`.

Requires authentication.

#### getPublicKey()

Fetch the current public key and associated metadata.

Returns: `{ publicKey, identity, curve }`.

Requires authentication.

#### getMasterKey()

Export the current bech32 master key.

Returns: `hkmk…` string.

Requires authentication.

#### recall()

Attempt to read a stored bech32 master key from `sessionStorage` and log in automatically.

Returns: `true` if a stored key was found and a login attempt was made, otherwise `false`.

#### clearError()

Reset the `error` field to `null`.

#### passKeyAuth(name)

Create/register a WebAuthn credential (PassKey) for the given user name and log in using the generated credential ID (encoded as `hkwa…`).

Parameters:

- `name` — string (user handle).

Returns: boolean indicating whether login was initiated.

#### passKeyLogin()

Prompt for an existing PassKey and log in using its credential ID (encoded as `hkwa…`).

Returns: boolean indicating whether login was initiated.

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

When you authenticate, hashkeys will fetch the bech32 master key (`hkmk…`) from the worker and store it in `sessionStorage` under `${appPrefix}.masterKey` (default `hk.masterKey`). When you logout or the page is refreshed without recalling, it is cleared. Use `auth.recall()` at startup to restore the session if a key is present.

- Uses `sessionStorage`, so the key persists for the lifetime of the browser tab/window only.
- The stored value is the bech32-encoded master key, not raw bytes.
- Calling `auth.logout()` clears the stored key.

---

## Examples

### Password to identity

```js
import { useAuth } from 'hashkeys'
const auth = useAuth('hk')
await auth.login('correct horse battery staple');
console.log(auth.identity); // hkid…
```

### End‑to‑end encrypt to a recipient

```js
const { ciphertext, nonce, algorithm } = await auth.encrypt({ 
  data: 'hi', 
  recipientPublicKey: 'hkek1…',
  algorithm: 'xchacha20poly1305'
});
// send {ciphertext, nonce, algorithm} to recipient
```

### Decrypt from a sender

```js
const { decrypted } = await auth.decrypt({ 
  ciphertext: 'hkct1…', 
  nonce: 'hknc1…', 
  senderPublicKey: 'hkek1…', 
  algorithm: 'xchacha20poly1305-x25519' 
});
```

### Verify someone else’s signature (no login required)

```js
const { valid } = await auth.verify({ 
  message: 'msg', 
  signature: 'hksg1…', 
  publicKey: 'hkpk1…' 
});
```

### PassKeys (WebAuthn)

```js
// Create/register a new PassKey for a username and login
await auth.passKeyAuth('alice@example.com');
console.log(auth.identity); // hkid…

// Use an existing PassKey to login
await auth.passKeyLogin();
```

### Multiple instances (local peer / Alice)

```js
import { useAuth } from 'hashkeys'
const me = useAuth('hk')
const alice = useAuth('hk')

await me.login('correct horse battery staple')
await alice.login('alice-secret')

// You -> Alice
const env = await me.encrypt({ 
  data: 'hi Alice', 
  recipientPublicKey: alice.encryptionKey 
})
const { decrypted } = await alice.decrypt({ 
  ciphertext: env.ciphertext, 
  nonce: env.nonce, 
  senderPublicKey: me.encryptionKey, 
  algorithm: env.algorithm 
})
```

### Session persistence (auto-recall)

```vue
<script setup>
import { onMounted } from 'vue'
import { useAuth } from 'hashkeys'

const auth = useAuth('hk')

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
    <script type="importmap">{ "imports": { "vue": "https://esm.sh/vue", "hashkeys": "https://esm.sh/hashkeys" } }</script>
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
      import { useAuth } from 'hashkeys';

      const auth = useAuth('ex');

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

MIT (c) 2025 davay42
