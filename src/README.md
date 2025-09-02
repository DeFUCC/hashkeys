# Crypto Auth Worker API Usage Scenarios

## 1. **auth(data)** - Initial Authentication & Key Setup
**Scenario**: User logs into your local-first app for the first time or returning session.

```javascript
// User enters password "my_secret_password"
worker.postMessage({id: 1, type: 'auth', data: 'my_secret_password'});
// Returns: {publicKey: "abc123...", identity: "def456...", encryptionKey: "ghi789..."}
```

**Crypto Math**: 
- **Scrypt**: Password → 32-byte master key using `scrypt(password, "ig_v1", {N: 2^17, r: 8, p: 1})`
- **HKDF**: Master key → signing key using `HKDF-SHA256(masterKey, "signing", "ig_v1")`
- **Ed25519**: Signing key (32 bytes) → public key (32 bytes) via elliptic curve point multiplication
- **X25519**: Same private key → encryption public key (different curve point)
- **SHA256**: Public key → identity hash for unique user identification

## 2. **sign(message)** - Digital Signatures for Authentication/Integrity
**Scenario**: User wants to prove they created a document, or authenticate to a service without passwords.

```javascript
// Sign a document hash or login challenge
worker.postMessage({id: 2, type: 'sign', data: {message: "Document content or challenge"}});
// Returns: {signature: "signature_hex", publicKey: "public_key_hex"}
```

**Crypto Math**:
- **Ed25519 Signing**: Uses `EdDSA` with twisted Edwards curve `y² - x² = 1 + dx²y²`
- **Algorithm**: `signature = (r, s)` where `r = [k]B` and `s = k + H(r,A,m) * a`
- `k` = deterministic nonce, `A` = public key, `m` = message, `a` = private key
- **Security**: Provides 128-bit security, immune to timing attacks, deterministic signatures

## 3. **verify(message, signature, publicKey)** - Signature Verification
**Scenario**: Verify someone else's signature on data, or verify your own signature from another device.

```javascript
// Verify a document signature
worker.postMessage({
  id: 3, 
  type: 'verify', 
  data: {message: "Document content", signature: "sig_hex", publicKey: "pubkey_hex"}
});
// Returns: {valid: true/false}
```

**Crypto Math**:
- **Ed25519 Verification**: Check if `[s]B = r + [H(r,A,m)]A`
- Point addition on Edwards curve to verify the signature equation
- **No secret data needed** - purely public key cryptography

## 4. **encrypt(data, recipientPublicKey)** - Secure Data Storage/Sharing
**Scenario A**: Encrypt personal data for local storage
```javascript
// Personal data encryption (no recipient)
worker.postMessage({id: 4, type: 'encrypt', data: {data: "My private notes"}});
```

**Scenario B**: Send encrypted message to another user
```javascript
// End-to-end encryption to another user
worker.postMessage({
  id: 4, 
  type: 'encrypt', 
  data: {data: "Secret message", recipientPublicKey: "their_pubkey_hex"}
});
```

**Crypto Math**:
- **Case A (Self)**: `HKDF(masterKey, "data_encryption") → AES key → AES-256-GCM encryption`
- **Case B (E2E)**: 
  - **X25519 ECDH**: `sharedSecret = [privateKey] × [recipientPublicKey]` on Curve25519
  - **Key Derivation**: `encryptionKey = SHA256(sharedSecret)`
  - **XChaCha20-Poly1305**: Stream cipher + MAC with 192-bit nonce for authenticated encryption
  - **Security**: Perfect forward secrecy, 256-bit encryption strength

## 5. **decrypt(encrypted, nonce, senderPublicKey)** - Data Decryption
**Scenario A**: Decrypt your own stored data
```javascript
worker.postMessage({
  id: 5, 
  type: 'decrypt', 
  data: {encrypted: "cipher_hex", nonce: "nonce_hex"}
});
```

**Scenario B**: Decrypt message from another user
```javascript
worker.postMessage({
  id: 5, 
  type: 'decrypt', 
  data: {encrypted: "cipher_hex", nonce: "nonce_hex", senderPublicKey: "sender_pubkey"}
});
```

**Crypto Math**: Reverse of encryption process
- **Case A**: Derive same symmetric key → decrypt with AES-256-GCM
- **Case B**: ECDH with sender → derive shared secret → decrypt with XChaCha20-Poly1305

## 6. **derive-key(context, length)** - Application-Specific Keys
**Scenario**: Generate different keys for different purposes from same master key.

```javascript
// Generate database encryption key
worker.postMessage({id: 6, type: 'derive-key', data: {context: "database", length: 32}});

// Generate API authentication key  
worker.postMessage({id: 7, type: 'derive-key', data: {context: "api_auth", length: 16}});
```

**Crypto Math**:
- **HKDF-SHA256**: `HKDF(masterKey, context, "ig_v1", length)`
- **Key Separation**: Different contexts produce completely different keys
- **Security**: Even if one derived key is compromised, others remain secure

## 7. **get-identity()** - User Identity & Public Key Sharing
**Scenario**: Get your cryptographic identity for sharing with others or displaying in UI.

```javascript
worker.postMessage({id: 8, type: 'get-identity'});
// Returns: {identity: "unique_hash", publicKey: "pubkey_for_sharing", curve: "ed25519"}
```

**Crypto Math**:
- **Identity**: `SHA256(publicKey)` - unique 256-bit fingerprint
- **Usage**: Identity for user discovery, public key for encryption/verification

## Key Cryptographic Properties:

- **Ed25519**: 128-bit security, fast signing/verification, small signatures (64 bytes)
- **X25519**: Key exchange with same security level, enables perfect forward secrecy
- **XChaCha20-Poly1305**: Authenticated encryption, prevents tampering, large nonce space
- **HKDF**: Cryptographically secure key derivation, enables key hierarchy
- **Scrypt**: Memory-hard password hashing, resistant to brute-force attacks

This gives you a complete cryptographic toolkit for local-first applications with strong security guarantees!