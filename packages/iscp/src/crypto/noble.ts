/**
 * Default CryptoProvider backed by the audited noble libraries:
 * @noble/curves (Ed25519/X25519), @noble/hashes (SHA-256/HMAC/HKDF),
 * @noble/ciphers (ChaCha20-Poly1305). Pure TS, synchronous, works on Node
 * and React Native/Hermes without polyfills (crypto.getRandomValues is
 * available on both).
 */

import { chacha20poly1305 } from '@noble/ciphers/chacha';
import { ed25519, x25519 } from '@noble/curves/ed25519';
import { hkdf } from '@noble/hashes/hkdf.js';
import { hmac } from '@noble/hashes/hmac.js';
import { sha256 } from '@noble/hashes/sha2.js';

import { IscpErrorCodes, iscpError } from '../errors';
import {
  CHACHA20_POLY1305_KEY_SIZE,
  CHACHA20_POLY1305_NONCE_SIZE,
  type CryptoProvider,
  Ed25519PrivateKey,
  Ed25519PublicKey,
  X25519PrivateKey,
  X25519PublicKey,
  assertEd25519Private,
  assertX25519Private,
} from './provider';

function checkAeadInputs(key: Uint8Array, nonce: Uint8Array): void {
  if (key.length !== CHACHA20_POLY1305_KEY_SIZE) {
    throw iscpError(IscpErrorCodes.EnvelopeInvalid, 'invalid aead key size');
  }
  if (nonce.length !== CHACHA20_POLY1305_NONCE_SIZE) {
    throw iscpError(IscpErrorCodes.EnvelopeInvalid, 'invalid nonce size');
  }
}

export class NobleCryptoProvider implements CryptoProvider {
  /**
   * Random source seam: tests and vector generation can inject a
   * deterministic stream; production uses crypto.getRandomValues.
   */
  constructor(private readonly random?: (length: number) => Uint8Array) {}

  randomBytes(length: number): Uint8Array {
    if (this.random) return this.random(length);
    const out = new Uint8Array(length);
    // getRandomValues rejects requests above 65536 bytes (Web Crypto quota).
    for (let offset = 0; offset < length; offset += 65536) {
      globalThis.crypto.getRandomValues(out.subarray(offset, Math.min(offset + 65536, length)));
    }
    return out;
  }

  generateIdentityKeyPair(): { privateKey: Ed25519PrivateKey; publicKey: Ed25519PublicKey } {
    const seed = this.randomBytes(32);
    const privateKey = new Ed25519PrivateKey(seed);
    return { privateKey, publicKey: this.ed25519PublicKey(privateKey) };
  }

  ed25519PublicKey(privateKey: Ed25519PrivateKey): Ed25519PublicKey {
    assertEd25519Private(privateKey);
    return new Ed25519PublicKey(ed25519.getPublicKey(privateKey.bytes));
  }

  sign(privateKey: Ed25519PrivateKey, message: Uint8Array): Uint8Array {
    assertEd25519Private(privateKey);
    return ed25519.sign(message, privateKey.bytes);
  }

  verify(publicKey: Ed25519PublicKey, message: Uint8Array, signature: Uint8Array): boolean {
    if (!(publicKey instanceof Ed25519PublicKey)) {
      throw iscpError(IscpErrorCodes.KeyInvalid, 'expected an Ed25519 public key');
    }
    if (signature.length !== 64) return false;
    try {
      return ed25519.verify(signature, message, publicKey.bytes, { zip215: false });
    } catch {
      return false;
    }
  }

  generateSessionKeyPair(): { privateKey: X25519PrivateKey; publicKey: X25519PublicKey } {
    // Matches Go reference clamping before deriving the public key; x25519
    // clamps internally as well, so the stored private bytes stay raw.
    const privateKey = new X25519PrivateKey(this.randomBytes(32));
    return { privateKey, publicKey: this.x25519PublicKey(privateKey) };
  }

  x25519PublicKey(privateKey: X25519PrivateKey): X25519PublicKey {
    assertX25519Private(privateKey);
    return new X25519PublicKey(x25519.getPublicKey(privateKey.bytes));
  }

  sharedSecret(privateKey: X25519PrivateKey, publicKey: X25519PublicKey): Uint8Array {
    assertX25519Private(privateKey);
    if (!(publicKey instanceof X25519PublicKey)) {
      throw iscpError(IscpErrorCodes.KeyInvalid, 'expected an X25519 public key');
    }
    try {
      return x25519.getSharedSecret(privateKey.bytes, publicKey.bytes);
    } catch (cause) {
      throw iscpError(IscpErrorCodes.KeyInvalid, 'x25519 agreement failed', { cause });
    }
  }

  hkdfSha256(secret: Uint8Array, salt: Uint8Array, info: Uint8Array, length: number): Uint8Array {
    return hkdf(sha256, secret, salt, info, length);
  }

  sha256(data: Uint8Array): Uint8Array {
    return sha256(data);
  }

  hmacSha256(key: Uint8Array, data: Uint8Array): Uint8Array {
    return hmac(sha256, key, data);
  }

  seal(key: Uint8Array, nonce: Uint8Array, plaintext: Uint8Array, aad: Uint8Array): Uint8Array {
    checkAeadInputs(key, nonce);
    return chacha20poly1305(key, nonce, aad).encrypt(plaintext);
  }

  open(key: Uint8Array, nonce: Uint8Array, ciphertext: Uint8Array, aad: Uint8Array): Uint8Array {
    checkAeadInputs(key, nonce);
    try {
      return chacha20poly1305(key, nonce, aad).decrypt(ciphertext);
    } catch (cause) {
      throw iscpError(IscpErrorCodes.EnvelopeInvalid, 'aead authentication failed', { cause });
    }
  }
}

export function createNobleProvider(random?: (length: number) => Uint8Array): CryptoProvider {
  return new NobleCryptoProvider(random);
}
