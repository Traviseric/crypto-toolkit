# Crypto Toolkit

[![License: MIT](https://img.shields.io/badge/License-MIT-gold.svg)](https://opensource.org/licenses/MIT)
[![TypeScript](https://img.shields.io/badge/TypeScript-Strict-blue.svg)](https://www.typescriptlang.org/)
[![Tests](https://img.shields.io/badge/Tests-225%20passing-brightgreen.svg)]()
[![Node](https://img.shields.io/badge/Node-%3E%3D18-339933.svg)](https://nodejs.org/)
[![Cryptography](https://img.shields.io/badge/Crypto-Libsodium-blueviolet.svg)](https://doc.libsodium.org/)
[![NIST](https://img.shields.io/badge/NIST-Compliant-navy.svg)](https://csrc.nist.gov/)

Comprehensive cryptographic utilities library providing secure-by-default primitives for the TE Code stack.

## Philosophy

**"There is one way to do it"** - Opinionated, misuse-resistant API following Libsodium's design philosophy:

- Secure defaults (XChaCha20-Poly1305, Argon2id)
- No weak algorithms exposed (no HS256, CBC, MD5, SHA-1)
- Automatic nonce generation
- Constant-time operations
- NIST/RFC test vector validation

## Features

### Core Primitives ✅

- **AEAD Encryption**: XChaCha20-Poly1305 (192-bit nonce, safe for random generation)
- **Password Hashing**: Argon2id (OWASP-compliant parameters)
- **Digital Signatures**: Ed25519 (fast, deterministic)
- **Key Exchange**: X25519 ECDH
- **Hashing**: SHA-256, SHA-512, BLAKE2b
- **Random Generation**: CSPRNG for keys, tokens, UUIDs
- **Constant-Time**: Timing-safe comparisons

### Advanced Features (Planned)

- Shamir's Secret Sharing
- Blind Indexing (searchable encryption)
- Streaming File Encryption
- JWT Security (rotation, blacklisting)
- Certificate Validation (OCSP)
- API Key Management
- Post-Quantum Cryptography (Kyber, Dilithium)
- Zero-Knowledge Proofs (zk-SNARKs)

## Installation

```bash
pnpm install @te-security/crypto-toolkit
```

## Quick Start

### Encryption

```typescript
import { encrypt, decrypt, generateKey } from '@te-security/crypto-toolkit';

// Generate a key
const key = generateKey(); // 32 bytes

// Encrypt
const encrypted = encrypt('Secret message', key);
// {
//   ciphertext: Uint8Array,
//   nonce: Uint8Array (24 bytes, randomly generated),
//   tag: Uint8Array (16 bytes, authentication tag),
//   algorithm: 'xchacha20-poly1305'
// }

// Decrypt
const decrypted = decrypt(encrypted, key);
console.log(Buffer.from(decrypted).toString('utf-8')); // 'Secret message'
```

### Password Hashing

```typescript
import { hashPassword, verifyPassword } from '@te-security/crypto-toolkit';

// Hash
const hashed = await hashPassword('my-secure-password');
// {
//   hash: '$argon2id$v=19$m=262144,t=3,p=1$...',
//   algorithm: 'argon2id',
//   parameters: { memoryCost: 262144, timeCost: 3 }
// }

// Verify
const isValid = await verifyPassword('my-secure-password', hashed);
console.log(isValid); // true
```

### Digital Signatures

```typescript
import { generateKeyPair, sign, verify } from '@te-security/crypto-toolkit';

// Generate key pair
const keyPair = generateKeyPair();
// { publicKey: Uint8Array (32 bytes), secretKey: Uint8Array (64 bytes) }

// Sign
const signature = sign('Document to sign', keyPair.secretKey);
// Uint8Array (64 bytes)

// Verify
const isValid = verify('Document to sign', signature, keyPair.publicKey);
console.log(isValid); // true
```

### Key Exchange

```typescript
import { generateX25519KeyPair, computeSharedSecret } from '@te-security/crypto-toolkit';

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
import { sealedBox, openSealedBox, generateX25519KeyPair } from '@te-security/crypto-toolkit';

const recipient = generateX25519KeyPair();

// Encrypt (sender anonymous)
const sealed = sealedBox('Anonymous message', recipient.publicKey);

// Decrypt
const plaintext = openSealedBox(sealed, recipient.secretKey, recipient.publicKey);
console.log(Buffer.from(plaintext!).toString('utf-8')); // 'Anonymous message'
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

## Security Considerations

1. **Key Storage**: Store keys securely (KMS, hardware tokens, encrypted key files)
2. **Key Rotation**: Implement regular key rotation policies
3. **Nonce Reuse**: XChaCha20's 192-bit nonce prevents birthday-bound collisions
4. **Timing Attacks**: All comparisons use constant-time functions
5. **Memory Safety**: Wipe sensitive data after use (use `sodium.sodium_memzero()`)

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

- NIST AES-GCM test vectors
- RFC 8439 ChaCha20-Poly1305 vectors
- RFC 8032 Ed25519 test vectors
- Wycheproof test suite

Run tests:

```bash
pnpm test
```

## Dependencies

- **sodium-native**: Libsodium bindings (core crypto)
- **jose**: JWT operations (planned)
- **commander**: CLI interface
- **chalk**: Terminal colors

## Compliance

- **NIST SP 800-57**: Key management recommendations
- **NIST SP 800-132**: Password-based key derivation
- **OWASP**: Password storage cheat sheet (Argon2id, 256 MiB RAM)
- **FIPS 140-3**: Cryptographic module validation (when using FIPS OpenSSL)

## License

MIT - See [LICENSE](LICENSE) for details.

## References

- [Libsodium Documentation](https://doc.libsodium.org/)
- [RFC 8439 - ChaCha20 and Poly1305](https://www.rfc-editor.org/rfc/rfc8439)
- [RFC 8032 - Ed25519](https://www.rfc-editor.org/rfc/rfc8032)
- [NIST Post-Quantum Cryptography](https://csrc.nist.gov/projects/post-quantum-cryptography)
- [OWASP Password Storage](https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html)
