/**
 * Tests for AEAD encryption (XChaCha20-Poly1305)
 */

import { describe, it, expect } from 'vitest';
import {
  encrypt,
  decrypt,
  encryptCombined,
  decryptCombined,
  generateKey,
  getKeySize,
  getNonceSize,
  getTagSize,
} from '../src/core/aead.js';

describe('AEAD - XChaCha20-Poly1305', () => {
  describe('Key generation', () => {
    it('should generate 32-byte keys', () => {
      const key = generateKey();
      expect(key.length).toBe(32);
    });

    it('should generate different keys', () => {
      const key1 = generateKey();
      const key2 = generateKey();
      expect(key1).not.toEqual(key2);
    });

    it('should report correct key size', () => {
      expect(getKeySize()).toBe(32);
      expect(getNonceSize()).toBe(24);
      expect(getTagSize()).toBe(16);
    });
  });

  describe('Encryption and Decryption', () => {
    it('should encrypt and decrypt strings', () => {
      const key = generateKey();
      const plaintext = 'Hello, World!';

      const encrypted = encrypt(plaintext, key);
      const decrypted = decrypt(encrypted, key);

      expect(Buffer.from(decrypted).toString('utf-8')).toBe(plaintext);
    });

    it('should encrypt and decrypt binary data', () => {
      const key = generateKey();
      const plaintext = new Uint8Array([1, 2, 3, 4, 5, 6, 7, 8]);

      const encrypted = encrypt(plaintext, key);
      const decrypted = decrypt(encrypted, key);

      expect(decrypted).toEqual(plaintext);
    });

    it('should produce different ciphertexts for same plaintext (random nonces)', () => {
      const key = generateKey();
      const plaintext = 'Same message';

      const encrypted1 = encrypt(plaintext, key);
      const encrypted2 = encrypt(plaintext, key);

      // Nonces should be different
      expect(encrypted1.nonce).not.toEqual(encrypted2.nonce);
      // Ciphertexts should be different
      expect(encrypted1.ciphertext).not.toEqual(encrypted2.ciphertext);

      // But both should decrypt correctly
      const decrypted1 = decrypt(encrypted1, key);
      const decrypted2 = decrypt(encrypted2, key);

      expect(Buffer.from(decrypted1).toString('utf-8')).toBe(plaintext);
      expect(Buffer.from(decrypted2).toString('utf-8')).toBe(plaintext);
    });

    it('should handle empty messages', () => {
      const key = generateKey();
      const plaintext = '';

      const encrypted = encrypt(plaintext, key);
      const decrypted = decrypt(encrypted, key);

      expect(Buffer.from(decrypted).toString('utf-8')).toBe(plaintext);
      expect(encrypted.ciphertext.length).toBe(0);
    });

    it('should handle large messages', () => {
      const key = generateKey();
      const plaintext = new Uint8Array(1024 * 1024); // 1 MB
      plaintext.fill(42);

      const encrypted = encrypt(plaintext, key);
      const decrypted = decrypt(encrypted, key);

      expect(decrypted).toEqual(plaintext);
    });
  });

  describe('Authentication', () => {
    it('should detect tampering with ciphertext', () => {
      const key = generateKey();
      const plaintext = 'Secret message';

      const encrypted = encrypt(plaintext, key);

      // Tamper with ciphertext
      if (encrypted.ciphertext.length > 0) {
        encrypted.ciphertext[0] ^= 1;
      }

      expect(() => decrypt(encrypted, key)).toThrow('authentication tag mismatch');
    });

    it('should detect tampering with nonce', () => {
      const key = generateKey();
      const plaintext = 'Secret message';

      const encrypted = encrypt(plaintext, key);

      // Tamper with nonce
      encrypted.nonce[0] ^= 1;

      expect(() => decrypt(encrypted, key)).toThrow('authentication tag mismatch');
    });

    it('should detect tampering with tag', () => {
      const key = generateKey();
      const plaintext = 'Secret message';

      const encrypted = encrypt(plaintext, key);

      // Tamper with tag
      encrypted.tag[0] ^= 1;

      expect(() => decrypt(encrypted, key)).toThrow('authentication tag mismatch');
    });

    it('should reject decryption with wrong key', () => {
      const key1 = generateKey();
      const key2 = generateKey();
      const plaintext = 'Secret message';

      const encrypted = encrypt(plaintext, key1);

      expect(() => decrypt(encrypted, key2)).toThrow('authentication tag mismatch');
    });
  });

  describe('Associated Data', () => {
    it('should support associated data', () => {
      const key = generateKey();
      const plaintext = 'Message';
      const associatedData = new Uint8Array([1, 2, 3, 4]);

      const encrypted = encrypt(plaintext, key, { associatedData });
      const decrypted = decrypt(encrypted, key, { associatedData });

      expect(Buffer.from(decrypted).toString('utf-8')).toBe(plaintext);
    });

    it('should reject decryption with different associated data', () => {
      const key = generateKey();
      const plaintext = 'Message';
      const ad1 = new Uint8Array([1, 2, 3, 4]);
      const ad2 = new Uint8Array([5, 6, 7, 8]);

      const encrypted = encrypt(plaintext, key, { associatedData: ad1 });

      expect(() => decrypt(encrypted, key, { associatedData: ad2 })).toThrow(
        'authentication tag mismatch'
      );
    });

    it('should reject decryption when associated data is missing', () => {
      const key = generateKey();
      const plaintext = 'Message';
      const associatedData = new Uint8Array([1, 2, 3, 4]);

      const encrypted = encrypt(plaintext, key, { associatedData });

      expect(() => decrypt(encrypted, key)).toThrow('authentication tag mismatch');
    });
  });

  describe('Combined format', () => {
    it('should encrypt and decrypt in combined format', () => {
      const key = generateKey();
      const plaintext = 'Hello, World!';

      const combined = encryptCombined(plaintext, key);
      const decrypted = decryptCombined(combined, key);

      expect(Buffer.from(decrypted).toString('utf-8')).toBe(plaintext);
    });

    it('should produce correct combined length', () => {
      const key = generateKey();
      const plaintext = 'Test';

      const combined = encryptCombined(plaintext, key);

      // Length should be: nonce (24) + ciphertext (4) + tag (16) = 44
      expect(combined.length).toBe(24 + 4 + 16);
    });

    it('should reject too-short combined buffers', () => {
      const key = generateKey();
      const tooShort = new Uint8Array(10);

      expect(() => decryptCombined(tooShort, key)).toThrow('Combined buffer too short');
    });
  });

  describe('Error handling', () => {
    it('should reject invalid key length', () => {
      const badKey = new Uint8Array(16); // Should be 32
      const plaintext = 'Test';

      expect(() => encrypt(plaintext, badKey)).toThrow('Key must be 32 bytes');
    });

    it('should reject invalid nonce length during decryption', () => {
      const key = generateKey();
      const encrypted = {
        nonce: new Uint8Array(12), // Should be 24
        ciphertext: new Uint8Array(10),
        tag: new Uint8Array(16),
        algorithm: 'xchacha20-poly1305' as const,
      };

      expect(() => decrypt(encrypted, key)).toThrow('Nonce must be 24 bytes');
    });

    it('should reject invalid tag length during decryption', () => {
      const key = generateKey();
      const encrypted = {
        nonce: new Uint8Array(24),
        ciphertext: new Uint8Array(10),
        tag: new Uint8Array(8), // Should be 16
        algorithm: 'xchacha20-poly1305' as const,
      };

      expect(() => decrypt(encrypted, key)).toThrow('Tag must be 16 bytes');
    });
  });

  describe('Interoperability', () => {
    it('should be able to decrypt previously encrypted data', () => {
      const key = new Uint8Array(32);
      key.fill(1); // Deterministic key for testing

      const plaintext = 'Test message';

      const encrypted = encrypt(plaintext, key);
      const decrypted = decrypt(encrypted, key);

      expect(Buffer.from(decrypted).toString('utf-8')).toBe(plaintext);
    });
  });
});
