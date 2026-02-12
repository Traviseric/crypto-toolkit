/**
 * X25519 Key Exchange (ECDH on Curve25519)
 *
 * X25519 is used for Diffie-Hellman key exchange.
 * Properties:
 * - Fast key agreement
 * - 32-byte keys
 * - Constant-time implementation
 * - Secure against timing attacks
 *
 * @module asymmetric/x25519
 */

import sodium from 'sodium-native';
import type { X25519KeyPair } from '../types/index.js';

const PUBLIC_KEY_BYTES = sodium.crypto_box_PUBLICKEYBYTES;      // 32
const SECRET_KEY_BYTES = sodium.crypto_box_SECRETKEYBYTES;      // 32
const SHARED_SECRET_BYTES = sodium.crypto_scalarmult_BYTES;     // 32
const NONCE_BYTES = sodium.crypto_box_NONCEBYTES;               // 24
const MAC_BYTES = sodium.crypto_box_MACBYTES;                   // 16
const SEAL_BYTES = sodium.crypto_box_SEALBYTES;                 // 48

/**
 * Generate an X25519 key pair
 *
 * @param seed - Optional 32-byte seed for deterministic generation
 * @returns Key pair with public and secret keys
 *
 * @example
 * ```typescript
 * const keyPair = generateX25519KeyPair();
 * // Share keyPair.publicKey with peer
 * // Keep keyPair.secretKey private
 * ```
 */
export function generateX25519KeyPair(seed?: Uint8Array): X25519KeyPair {
  const publicKey = Buffer.alloc(PUBLIC_KEY_BYTES);
  const secretKey = Buffer.alloc(SECRET_KEY_BYTES);

  if (seed) {
    if (seed.length !== 32) {
      throw new Error('Seed must be 32 bytes');
    }
    sodium.crypto_box_seed_keypair(publicKey, secretKey, Buffer.from(seed));
  } else {
    sodium.crypto_box_keypair(publicKey, secretKey);
  }

  return {
    publicKey: new Uint8Array(publicKey),
    secretKey: new Uint8Array(secretKey),
  };
}

/**
 * Compute shared secret using X25519 ECDH
 *
 * Both parties compute the same shared secret:
 * - Alice: computeSharedSecret(aliceSecret, bobPublic)
 * - Bob: computeSharedSecret(bobSecret, alicePublic)
 *
 * The shared secret should be used with a KDF (like HKDF) before use.
 *
 * @param mySecretKey - Your 32-byte secret key
 * @param theirPublicKey - Their 32-byte public key
 * @returns 32-byte shared secret
 *
 * @example
 * ```typescript
 * const alice = generateX25519KeyPair();
 * const bob = generateX25519KeyPair();
 *
 * const aliceShared = computeSharedSecret(alice.secretKey, bob.publicKey);
 * const bobShared = computeSharedSecret(bob.secretKey, alice.publicKey);
 * // aliceShared === bobShared
 * ```
 */
export function computeSharedSecret(
  mySecretKey: Uint8Array,
  theirPublicKey: Uint8Array
): Uint8Array {
  if (mySecretKey.length !== SECRET_KEY_BYTES) {
    throw new Error(`Secret key must be ${SECRET_KEY_BYTES} bytes`);
  }

  if (theirPublicKey.length !== PUBLIC_KEY_BYTES) {
    throw new Error(`Public key must be ${PUBLIC_KEY_BYTES} bytes`);
  }

  const sharedSecret = Buffer.alloc(SHARED_SECRET_BYTES);

  sodium.crypto_scalarmult(
    sharedSecret,
    Buffer.from(mySecretKey),
    Buffer.from(theirPublicKey)
  );

  return new Uint8Array(sharedSecret);
}

/**
 * Encrypt a message to a recipient's public key (authenticated box)
 *
 * Creates an authenticated ciphertext that can only be decrypted by the recipient.
 * Both sender and recipient are authenticated.
 *
 * @param message - Message to encrypt
 * @param recipientPublicKey - Recipient's public key
 * @param senderSecretKey - Sender's secret key
 * @returns Ciphertext with nonce
 *
 * @example
 * ```typescript
 * const ciphertext = box(message, bobPublic, aliceSecret);
 * const plaintext = openBox(ciphertext, alicePublic, bobSecret);
 * ```
 */
export function box(
  message: Uint8Array | string,
  recipientPublicKey: Uint8Array,
  senderSecretKey: Uint8Array
): Uint8Array {
  const messageBuf = typeof message === 'string'
    ? Buffer.from(message, 'utf-8')
    : Buffer.from(message);

  if (recipientPublicKey.length !== PUBLIC_KEY_BYTES) {
    throw new Error(`Recipient public key must be ${PUBLIC_KEY_BYTES} bytes`);
  }

  if (senderSecretKey.length !== SECRET_KEY_BYTES) {
    throw new Error(`Sender secret key must be ${SECRET_KEY_BYTES} bytes`);
  }

  // Generate random nonce
  const nonce = Buffer.alloc(NONCE_BYTES);
  sodium.randombytes_buf(nonce);

  // Encrypt
  const ciphertext = Buffer.alloc(messageBuf.length + MAC_BYTES);

  sodium.crypto_box_easy(
    ciphertext,
    messageBuf,
    nonce,
    Buffer.from(recipientPublicKey),
    Buffer.from(senderSecretKey)
  );

  // Combine nonce || ciphertext
  return new Uint8Array(Buffer.concat([nonce, ciphertext]));
}

/**
 * Decrypt a box-encrypted message
 *
 * @param ciphertext - Encrypted message from box()
 * @param senderPublicKey - Sender's public key (for authentication)
 * @param recipientSecretKey - Recipient's secret key
 * @returns Decrypted message or null if authentication fails
 *
 * @example
 * ```typescript
 * const plaintext = openBox(ciphertext, alicePublic, bobSecret);
 * if (!plaintext) {
 *   throw new Error('Decryption failed');
 * }
 * ```
 */
export function openBox(
  ciphertext: Uint8Array,
  senderPublicKey: Uint8Array,
  recipientSecretKey: Uint8Array
): Uint8Array | null {
  if (ciphertext.length < NONCE_BYTES + MAC_BYTES) {
    return null;
  }

  if (senderPublicKey.length !== PUBLIC_KEY_BYTES) {
    return null;
  }

  if (recipientSecretKey.length !== SECRET_KEY_BYTES) {
    return null;
  }

  const ciphertextBuf = Buffer.from(ciphertext);

  // Extract nonce and ciphertext
  const nonce = ciphertextBuf.slice(0, NONCE_BYTES);
  const encrypted = ciphertextBuf.slice(NONCE_BYTES);

  // Decrypt
  const plaintext = Buffer.alloc(encrypted.length - MAC_BYTES);

  try {
    const success = sodium.crypto_box_open_easy(
      plaintext,
      encrypted,
      nonce,
      Buffer.from(senderPublicKey),
      Buffer.from(recipientSecretKey)
    );

    if (!success) {
      return null;
    }

    return new Uint8Array(plaintext);
  } catch {
    return null;
  }
}

/**
 * Create a sealed box (anonymous encryption)
 *
 * Encrypts a message to a recipient's public key without revealing sender identity.
 * Recipient cannot authenticate sender.
 *
 * Use case: anonymous messages, dead drops
 *
 * @param message - Message to encrypt
 * @param recipientPublicKey - Recipient's public key
 * @returns Sealed ciphertext
 *
 * @example
 * ```typescript
 * const sealed = sealedBox(message, bobPublic);
 * const plaintext = openSealedBox(sealed, bobSecret, bobPublic);
 * ```
 */
export function sealedBox(
  message: Uint8Array | string,
  recipientPublicKey: Uint8Array
): Uint8Array {
  const messageBuf = typeof message === 'string'
    ? Buffer.from(message, 'utf-8')
    : Buffer.from(message);

  if (recipientPublicKey.length !== PUBLIC_KEY_BYTES) {
    throw new Error(`Recipient public key must be ${PUBLIC_KEY_BYTES} bytes`);
  }

  const ciphertext = Buffer.alloc(messageBuf.length + SEAL_BYTES);

  sodium.crypto_box_seal(ciphertext, messageBuf, Buffer.from(recipientPublicKey));

  return new Uint8Array(ciphertext);
}

/**
 * Open a sealed box
 *
 * @param ciphertext - Sealed ciphertext
 * @param recipientSecretKey - Recipient's secret key
 * @param recipientPublicKey - Recipient's public key
 * @returns Decrypted message or null if decryption fails
 *
 * @example
 * ```typescript
 * const plaintext = openSealedBox(sealed, secretKey, publicKey);
 * ```
 */
export function openSealedBox(
  ciphertext: Uint8Array,
  recipientSecretKey: Uint8Array,
  recipientPublicKey: Uint8Array
): Uint8Array | null {
  if (ciphertext.length < SEAL_BYTES) {
    return null;
  }

  if (recipientSecretKey.length !== SECRET_KEY_BYTES) {
    return null;
  }

  if (recipientPublicKey.length !== PUBLIC_KEY_BYTES) {
    return null;
  }

  const plaintext = Buffer.alloc(ciphertext.length - SEAL_BYTES);

  try {
    const success = sodium.crypto_box_seal_open(
      plaintext,
      Buffer.from(ciphertext),
      Buffer.from(recipientPublicKey),
      Buffer.from(recipientSecretKey)
    );

    if (!success) {
      return null;
    }

    return new Uint8Array(plaintext);
  } catch {
    return null;
  }
}

/**
 * Convert Ed25519 key to X25519 key
 *
 * Allows using Ed25519 signing keys for encryption.
 * Uses birationally equivalent curve conversion.
 *
 * @param ed25519Key - Ed25519 public or secret key
 * @param type - 'public' or 'secret'
 * @returns X25519 key
 *
 * @example
 * ```typescript
 * const signingKey = generateKeyPair(); // Ed25519
 * const encryptionKey = convertEd25519ToX25519(signingKey.publicKey, 'public');
 * ```
 */
export function convertEd25519ToX25519(
  ed25519Key: Uint8Array,
  type: 'public' | 'secret'
): Uint8Array {
  const x25519Key = Buffer.alloc(32);

  if (type === 'public') {
    if (ed25519Key.length !== 32) {
      throw new Error('Ed25519 public key must be 32 bytes');
    }
    sodium.crypto_sign_ed25519_pk_to_curve25519(x25519Key, Buffer.from(ed25519Key));
  } else {
    if (ed25519Key.length !== 64) {
      throw new Error('Ed25519 secret key must be 64 bytes');
    }
    sodium.crypto_sign_ed25519_sk_to_curve25519(x25519Key, Buffer.from(ed25519Key));
  }

  return new Uint8Array(x25519Key);
}

/**
 * Get public key size
 *
 * @returns 32 bytes
 */
export function getPublicKeySize(): number {
  return PUBLIC_KEY_BYTES;
}

/**
 * Get secret key size
 *
 * @returns 32 bytes
 */
export function getSecretKeySize(): number {
  return SECRET_KEY_BYTES;
}

/**
 * Get shared secret size
 *
 * @returns 32 bytes
 */
export function getSharedSecretSize(): number {
  return SHARED_SECRET_BYTES;
}
