# Crypto Toolkit

[![npm version](https://img.shields.io/npm/v/@empowered-humanity/crypto-toolkit.svg)](https://www.npmjs.com/package/@empowered-humanity/crypto-toolkit)
[![License: MIT](https://img.shields.io/badge/License-MIT-gold.svg)](https://opensource.org/licenses/MIT)
[![TypeScript](https://img.shields.io/badge/TypeScript-Strict-blue.svg)](https://www.typescriptlang.org/)
[![Tests](https://img.shields.io/badge/Tests-225%20passing-brightgreen.svg)]()
[![Node](https://img.shields.io/badge/Node-%3E%3D18-339933.svg)](https://nodejs.org/)
[![Cryptography](https://img.shields.io/badge/Crypto-Libsodium-blueviolet.svg)](https://doc.libsodium.org/)
[![NIST](https://img.shields.io/badge/NIST-Compliant-navy.svg)](https://csrc.nist.gov/)

Secure-by-default cryptographic utilities library built on Libsodium.

## Philosophy

**"There is one way to do it"** — Opinionated, misuse-resistant API following Libsodium's design philosophy:

- Secure defaults (XChaCha20-Poly1305, Argon2id)
- No weak algorithms exposed (no HS256, CBC, MD5, SHA-1)
- Automatic nonce generation
- Constant-time operations
- NIST/RFC test vector validation

## Features

### Core Primitives

- **AEAD Encryption**: XChaCha20-Poly1305 (192-bit nonce, safe for random generation)
- **Password Hashing**: Argon2id (OWASP-compliant parameters)
- **Digital Signatures**: Ed25519 (fast, deterministic)
- **Key Exchange**: X25519 ECDH
- **Hashing**: SHA-256, SHA-512, BLAKE2b
- **Random Generation**: CSPRNG for keys, tokens, UUIDs
- **Constant-Time**: Timing-safe comparisons

### Advanced Features

- **JWT Security**: Signing, verification, algorithm lock, refresh token families, blacklisting
- **API Key Management**: Generation and validation
- **Sealed Box**: Anonymous public-key encryption

## Installation

```bash
npm install @empowered-humanity/crypto-toolkit
```

## Quick Start

### Encryption

```typescript
import { encrypt, decrypt, generateKey } from '@empowered-humanity/crypto-toolkit';

// Generate a key
const key = generateKey(); // 32 bytes

// Encrypt
const encrypted = encrypt('Secret message', key);

// Decrypt
const decrypted = decrypt(encrypted, key);
console.log(Buffer.from(decrypted).toString('utf-8')); // 'Secret message'
```

### Password Hashing

```typescript
import { hashPassword, verifyPassword } from '@empowered-humanity/crypto-toolkit';

// Hash
const hashed = await hashPassword('my-secure-password');

// Verify
const isValid = await verifyPassword('my-secure-password', hashed);
console.log(isValid); // true
```

### Digital Signatures

```typescript
import { generateKeyPair, sign, verify } from '@empowered-humanity/crypto-toolkit';

// Generate key pair
const keyPair = generateKeyPair();

// Sign
const signature = sign('Document to sign', keyPair.secretKey);

// Verify
const isValid = verify('Document to sign', signature, keyPair.publicKey);
console.log(isValid); // true
```

### Key Exchange

```typescript
import { generateX25519KeyPair, computeSharedSecret } from '@empowered-humanity/crypto-toolkit';

// Alice and Bob generate key pairs
const alice = generateX25519KeyPair();
const bob = generateX25519KeyPair();

// Both compute the same shared secret
const aliceShared = computeSharedSecret(alice.secretKey, bob.publicKey);
const bobShared = computeSharedSecret(bob.secretKey, alice.publicKey);
// aliceShared === bobShared (32 bytes)
```

### Sealed Box (Anonymous Encryption)

```typescript
import { sealedBox, openSealedBox, generateX25519KeyPair } from '@empowered-humanity/crypto-toolkit';

const recipient = generateX25519KeyPair();

// Encrypt (sender anonymous)
const sealed = sealedBox('Anonymous message', recipient.publicKey);

// Decrypt
const plaintext = openSealedBox(sealed, recipient.secretKey, recipient.publicKey);
```

## CLI Usage

```bash
# Encrypt a file
te-crypto encrypt --file secret.txt --key-file key.bin --output secret.enc

# Decrypt a file
te-crypto decrypt --file secret.enc --key-file key.bin --output secret.txt

# Generate keys
te-crypto keygen --type aes256 --output keys/
te-crypto keygen --type ed25519 --output keys/
te-crypto keygen --type x25519 --output keys/

# Password hashing
te-crypto hash-password "my-password"
te-crypto verify-password "my-password" '$argon2id$v=19$...'

# Signing
te-crypto sign --file document.pdf --key private.key --output document.sig
te-crypto verify --file document.pdf --sig document.sig --key public.key

# Random generation
te-crypto random --bytes 32 --format hex
te-crypto random --format uuid
te-crypto random --format token

# Hashing
te-crypto hash --file document.pdf --algorithm sha256
```

## Algorithm Choices

| Purpose | Algorithm | Why? |
|---------|-----------|------|
| Encryption | XChaCha20-Poly1305 | Nonce-misuse resistant, fast, modern |
| Password Hashing | Argon2id | Winner of PHC, OWASP recommended |
| Signatures | Ed25519 | Fast, small signatures, deterministic |
| Key Exchange | X25519 | Modern ECDH on Curve25519 |
| Hashing | BLAKE2b/SHA-256 | Fast, collision-resistant |

## Test Vectors

All cryptographic functions are validated against official test vectors:

- RFC 8439 ChaCha20-Poly1305 vectors
- RFC 8032 Ed25519 test vectors
- Wycheproof test suite

```bash
npm test
```

## Dependencies

- **sodium-native**: Libsodium bindings (core crypto)
- **jose**: JWT operations
- **commander**: CLI interface
- **chalk**: Terminal colors

## Compliance

- **NIST SP 800-57**: Key management recommendations
- **NIST SP 800-132**: Password-based key derivation
- **OWASP**: Password storage cheat sheet (Argon2id, 256 MiB RAM)
- **FIPS 140-3**: Cryptographic module validation (when using FIPS OpenSSL)

## License

MIT — See [LICENSE](LICENSE) for details.

## References

- [Libsodium Documentation](https://doc.libsodium.org/)
- [RFC 8439 - ChaCha20 and Poly1305](https://www.rfc-editor.org/rfc/rfc8439)
- [RFC 8032 - Ed25519](https://www.rfc-editor.org/rfc/rfc8032)
- [OWASP Password Storage](https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html)
