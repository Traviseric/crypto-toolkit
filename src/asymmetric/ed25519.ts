/**
 * Ed25519 Digital Signatures
 *
 * Ed25519 is a modern signature scheme based on Curve25519.
 * Properties:
 * - Fast signing and verification
 * - Small signatures (64 bytes)
 * - Small public keys (32 bytes)
 * - Deterministic (no random number generation during signing)
 * - Collision-resistant
 *
 * @module asymmetric/ed25519
 */

import sodium from 'sodium-native';
import type { KeyPair, Signature } from '../types/index.js';

const PUBLIC_KEY_BYTES = sodium.crypto_sign_PUBLICKEYBYTES; // 32
const SECRET_KEY_BYTES = sodium.crypto_sign_SECRETKEYBYTES; // 64
const SIGNATURE_BYTES = sodium.crypto_sign_BYTES;            // 64

/**
 * Generate an Ed25519 key pair
 *
 * The secret key is 64 bytes (includes the public key for convenience).
 * The public key is 32 bytes.
 *
 * @param seed - Optional 32-byte seed for deterministic key generation
 * @returns Key pair with public and secret keys
 *
 * @example
 * ```typescript
 * const keyPair = generateKeyPair();
 * // Store keyPair.secretKey securely
 * // Share keyPair.publicKey with verifiers
 * ```
 */
export function generateKeyPair(seed?: Uint8Array): KeyPair {
  const publicKey = Buffer.alloc(PUBLIC_KEY_BYTES);
  const secretKey = Buffer.alloc(SECRET_KEY_BYTES);

  if (seed) {
    if (seed.length !== 32) {
      throw new Error('Seed must be 32 bytes');
    }
    sodium.crypto_sign_seed_keypair(publicKey, secretKey, Buffer.from(seed));
  } else {
    sodium.crypto_sign_keypair(publicKey, secretKey);
  }

  return {
    publicKey: new Uint8Array(publicKey),
    secretKey: new Uint8Array(secretKey),
  };
}

/**
 * Extract public key from secret key
 *
 * The Ed25519 secret key format includes the public key in the last 32 bytes.
 *
 * @param secretKey - 64-byte secret key
 * @returns 32-byte public key
 *
 * @example
 * ```typescript
 * const publicKey = extractPublicKey(secretKey);
 * ```
 */
export function extractPublicKey(secretKey: Uint8Array): Uint8Array {
  if (secretKey.length !== SECRET_KEY_BYTES) {
    throw new Error(`Secret key must be ${SECRET_KEY_BYTES} bytes`);
  }

  const publicKey = Buffer.alloc(PUBLIC_KEY_BYTES);
  sodium.crypto_sign_ed25519_sk_to_pk(publicKey, Buffer.from(secretKey));

  return new Uint8Array(publicKey);
}

/**
 * Sign a message with Ed25519
 *
 * Produces a detached signature (signature only, message not included).
 * Signing is deterministic (same message + key = same signature).
 *
 * @param message - Message to sign
 * @param secretKey - 64-byte secret key
 * @returns 64-byte signature
 *
 * @example
 * ```typescript
 * const signature = sign('Hello, world!', secretKey);
 * // Send message + signature
 * ```
 */
export function sign(
  message: Uint8Array | string,
  secretKey: Uint8Array
): Uint8Array {
  const messageBuf = typeof message === 'string'
    ? Buffer.from(message, 'utf-8')
    : Buffer.from(message);

  if (secretKey.length !== SECRET_KEY_BYTES) {
    throw new Error(`Secret key must be ${SECRET_KEY_BYTES} bytes`);
  }

  const signature = Buffer.alloc(SIGNATURE_BYTES);

  sodium.crypto_sign_detached(signature, messageBuf, Buffer.from(secretKey));

  return new Uint8Array(signature);
}

/**
 * Verify an Ed25519 signature
 *
 * @param message - Original message
 * @param signature - 64-byte signature
 * @param publicKey - 32-byte public key
 * @returns True if signature is valid
 *
 * @example
 * ```typescript
 * const isValid = verify(message, signature, publicKey);
 * if (isValid) {
 *   console.log('Signature valid!');
 * }
 * ```
 */
export function verify(
  message: Uint8Array | string,
  signature: Uint8Array,
  publicKey: Uint8Array
): boolean {
  const messageBuf = typeof message === 'string'
    ? Buffer.from(message, 'utf-8')
    : Buffer.from(message);

  if (signature.length !== SIGNATURE_BYTES) {
    return false;
  }

  if (publicKey.length !== PUBLIC_KEY_BYTES) {
    return false;
  }

  try {
    return sodium.crypto_sign_verify_detached(
      Buffer.from(signature),
      messageBuf,
      Buffer.from(publicKey)
    );
  } catch {
    return false;
  }
}

/**
 * Sign a message and return combined format (signature || message)
 *
 * Legacy format where signature is prepended to message.
 * Modern applications should use detached signatures.
 *
 * @param message - Message to sign
 * @param secretKey - 64-byte secret key
 * @returns Signed message (signature || message)
 *
 * @example
 * ```typescript
 * const signed = signCombined('message', secretKey);
 * // Send signed (includes both signature and message)
 * ```
 */
export function signCombined(
  message: Uint8Array | string,
  secretKey: Uint8Array
): Uint8Array {
  const messageBuf = typeof message === 'string'
    ? Buffer.from(message, 'utf-8')
    : Buffer.from(message);

  if (secretKey.length !== SECRET_KEY_BYTES) {
    throw new Error(`Secret key must be ${SECRET_KEY_BYTES} bytes`);
  }

  const signedMessage = Buffer.alloc(SIGNATURE_BYTES + messageBuf.length);

  sodium.crypto_sign(signedMessage, messageBuf, Buffer.from(secretKey));

  return new Uint8Array(signedMessage);
}

/**
 * Verify and extract message from combined format
 *
 * @param signedMessage - Signed message (signature || message)
 * @param publicKey - 32-byte public key
 * @returns Original message if signature valid, null otherwise
 *
 * @example
 * ```typescript
 * const message = verifyCombined(signed, publicKey);
 * if (message) {
 *   console.log('Message:', Buffer.from(message).toString());
 * }
 * ```
 */
export function verifyCombined(
  signedMessage: Uint8Array,
  publicKey: Uint8Array
): Uint8Array | null {
  if (signedMessage.length < SIGNATURE_BYTES) {
    return null;
  }

  if (publicKey.length !== PUBLIC_KEY_BYTES) {
    return null;
  }

  const message = Buffer.alloc(signedMessage.length - SIGNATURE_BYTES);

  try {
    const success = sodium.crypto_sign_open(
      message,
      Buffer.from(signedMessage),
      Buffer.from(publicKey)
    );

    if (!success) {
      return null;
    }

    return new Uint8Array(message);
  } catch {
    return null;
  }
}

/**
 * Create a signature object with metadata
 *
 * @param message - Message to sign
 * @param secretKey - Secret key
 * @returns Signature object with signature and public key
 *
 * @example
 * ```typescript
 * const sig = createSignature('document', secretKey);
 * // { signature: Uint8Array, publicKey: Uint8Array }
 * ```
 */
export function createSignature(
  message: Uint8Array | string,
  secretKey: Uint8Array
): Signature {
  const signature = sign(message, secretKey);
  const publicKey = extractPublicKey(secretKey);

  return {
    signature,
    publicKey,
  };
}

/**
 * Get public key size in bytes
 *
 * @returns 32 bytes
 */
export function getPublicKeySize(): number {
  return PUBLIC_KEY_BYTES;
}

/**
 * Get secret key size in bytes
 *
 * @returns 64 bytes
 */
export function getSecretKeySize(): number {
  return SECRET_KEY_BYTES;
}

/**
 * Get signature size in bytes
 *
 * @returns 64 bytes
 */
export function getSignatureSize(): number {
  return SIGNATURE_BYTES;
}
