/**
 * Tests for password hashing (Argon2id)
 */

import { describe, it, expect } from 'vitest';
import {
  hashPassword,
  verifyPassword,
  needsRehash,
  deriveKey,
  getSecurityLevels,
} from '../src/core/password.js';
import { randomBytes } from '../src/core/random.js';

describe('Password Hashing - Argon2id', () => {
  describe('Hash generation', () => {
    it('should hash passwords', async () => {
      const password = 'my-secure-password';
      const hashed = await hashPassword(password);

      expect(hashed.hash).toMatch(/^\$argon2id\$/);
      expect(hashed.algorithm).toBe('argon2id');
      expect(hashed.parameters).toHaveProperty('memoryCost');
      expect(hashed.parameters).toHaveProperty('timeCost');
    });

    it('should produce different hashes for same password (random salts)', async () => {
      const password = 'same-password';

      const hash1 = await hashPassword(password);
      const hash2 = await hashPassword(password);

      expect(hash1.hash).not.toBe(hash2.hash);

      // But both should verify
      expect(await verifyPassword(password, hash1)).toBe(true);
      expect(await verifyPassword(password, hash2)).toBe(true);
    });

    it('should reject empty passwords', async () => {
      await expect(hashPassword('')).rejects.toThrow('Password cannot be empty');
    });

    it('should handle long passwords', async () => {
      const longPassword = 'a'.repeat(1000);
      const hashed = await hashPassword(longPassword);

      expect(await verifyPassword(longPassword, hashed)).toBe(true);
    });

    it('should handle unicode passwords', async () => {
      const unicodePassword = '密码🔒测试';
      const hashed = await hashPassword(unicodePassword);

      expect(await verifyPassword(unicodePassword, hashed)).toBe(true);
    });
  });

  describe('Password verification', () => {
    it('should verify correct passwords', async () => {
      const password = 'correct-password';
      const hashed = await hashPassword(password);

      const isValid = await verifyPassword(password, hashed);
      expect(isValid).toBe(true);
    });

    it('should reject incorrect passwords', async () => {
      const password = 'correct-password';
      const hashed = await hashPassword(password);

      const isValid = await verifyPassword('wrong-password', hashed);
      expect(isValid).toBe(false);
    });

    it('should accept hash string directly', async () => {
      const password = 'test-password';
      const hashed = await hashPassword(password);

      const isValid = await verifyPassword(password, hashed.hash);
      expect(isValid).toBe(true);
    });

    it('should reject empty passwords during verification', async () => {
      const hashed = await hashPassword('test');

      await expect(verifyPassword('', hashed)).rejects.toThrow('Password cannot be empty');
    });

    it('should reject empty hash', async () => {
      const isValid = await verifyPassword('test', '');
      expect(isValid).toBe(false);
    });

    it('should handle invalid hash formats gracefully', async () => {
      const isValid = await verifyPassword('test', 'invalid-hash');
      expect(isValid).toBe(false);
    });

    it('should be case-sensitive', async () => {
      const password = 'Test123';
      const hashed = await hashPassword(password);

      expect(await verifyPassword('test123', hashed)).toBe(false);
      expect(await verifyPassword('TEST123', hashed)).toBe(false);
      expect(await verifyPassword('Test123', hashed)).toBe(true);
    });
  });

  describe('Security levels', () => {
    it('should provide security level presets', () => {
      const levels = getSecurityLevels();

      expect(levels).toHaveProperty('interactive');
      expect(levels).toHaveProperty('moderate');
      expect(levels).toHaveProperty('sensitive');

      expect(levels.interactive.memoryCost).toBeLessThan(levels.moderate.memoryCost);
      expect(levels.moderate.memoryCost).toBeLessThan(levels.sensitive.memoryCost);
    });

    it('should hash with custom parameters', async () => {
      const password = 'test';
      const levels = getSecurityLevels();

      const hashed = await hashPassword(password, {
        memoryCost: levels.sensitive.memoryCost,
        timeCost: levels.sensitive.timeCost,
      });

      expect(await verifyPassword(password, hashed)).toBe(true);
    });
  });

  describe('Rehashing detection', () => {
    it('should detect when rehashing is not needed', async () => {
      const password = 'test';
      const hashed = await hashPassword(password);

      const needsUpdate = await needsRehash(hashed);
      expect(needsUpdate).toBe(false);
    });

    it('should detect when rehashing is needed (parameters changed)', async () => {
      const password = 'test';
      const levels = getSecurityLevels();

      // Hash with interactive parameters
      const hashed = await hashPassword(password, {
        memoryCost: levels.interactive.memoryCost,
        timeCost: levels.interactive.timeCost,
      });

      // Check if rehash needed with higher parameters
      const needsUpdate = await needsRehash(hashed, {
        memoryCost: levels.sensitive.memoryCost,
        timeCost: levels.sensitive.timeCost,
      });

      expect(needsUpdate).toBe(true);
    });

    it('should recommend rehashing for invalid hashes', async () => {
      const needsUpdate = await needsRehash('invalid-hash');
      expect(needsUpdate).toBe(true);
    });
  });

  describe('Key derivation', () => {
    it('should derive keys from passwords', async () => {
      const password = 'my-password';
      const salt = randomBytes(16);

      const key = await deriveKey(password, salt, 32);

      expect(key.length).toBe(32);
    });

    it('should produce same key with same password and salt', async () => {
      const password = 'my-password';
      const salt = randomBytes(16);

      const key1 = await deriveKey(password, salt, 32);
      const key2 = await deriveKey(password, salt, 32);

      expect(key1).toEqual(key2);
    });

    it('should produce different keys with different salts', async () => {
      const password = 'my-password';
      const salt1 = randomBytes(16);
      const salt2 = randomBytes(16);

      const key1 = await deriveKey(password, salt1, 32);
      const key2 = await deriveKey(password, salt2, 32);

      expect(key1).not.toEqual(key2);
    });

    it('should produce different keys with different passwords', async () => {
      const salt = randomBytes(16);

      const key1 = await deriveKey('password1', salt, 32);
      const key2 = await deriveKey('password2', salt, 32);

      expect(key1).not.toEqual(key2);
    });

    it('should reject invalid salt length', async () => {
      const password = 'test';
      const badSalt = randomBytes(8); // Should be 16

      await expect(deriveKey(password, badSalt, 32)).rejects.toThrow(
        'Salt must be 16 bytes'
      );
    });

    it('should support variable key lengths', async () => {
      const password = 'test';
      const salt = randomBytes(16);

      const key16 = await deriveKey(password, salt, 16);
      const key32 = await deriveKey(password, salt, 32);
      const key64 = await deriveKey(password, salt, 64);

      expect(key16.length).toBe(16);
      expect(key32.length).toBe(32);
      expect(key64.length).toBe(64);
    });

    it('should reject empty password', async () => {
      const salt = randomBytes(16);

      await expect(deriveKey('', salt, 32)).rejects.toThrow(
        'Password cannot be empty'
      );
    });
  });

  describe('Timing safety', () => {
    it('should take similar time for correct and incorrect passwords', async () => {
      const password = 'test-password';
      const hashed = await hashPassword(password);

      const start1 = Date.now();
      await verifyPassword(password, hashed);
      const time1 = Date.now() - start1;

      const start2 = Date.now();
      await verifyPassword('wrong-password', hashed);
      const time2 = Date.now() - start2;

      // Allow for some variation, but should be roughly similar
      // This is a weak test, but helps catch obvious timing leaks
      const diff = Math.abs(time1 - time2);
      expect(diff).toBeLessThan(100); // Within 100ms
    });
  });
});
