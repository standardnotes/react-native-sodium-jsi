const g = global as any;

import { NativeModules } from 'react-native';

const SodiumNative = NativeModules.Sodium;

if (SodiumNative && typeof SodiumNative.install === 'function') {
  SodiumNative.install();
}

export type SodiumConstants = {
  crypto_pwhash_ALG_ARGON2I13: number;
  crypto_pwhash_ALG_ARGON2ID13: number;
  crypto_pwhash_ALG_DEFAULT: number;
  crypto_pwhash_BYTES_MAX: number;
  crypto_pwhash_MEMLIMIT_MAX: number;
  crypto_pwhash_MEMLIMIT_MIN: number;
  crypto_pwhash_MEMLIMIT_MODERATE: number;
  crypto_pwhash_MEMLIMIT_SENSITIVE: number;
  crypto_pwhash_OPSLIMIT_MAX: number;
  crypto_pwhash_OPSLIMIT_MIN: number;
  crypto_pwhash_OPSLIMIT_MODERATE: number;
  crypto_pwhash_PASSWD_MAX: number;
  crypto_pwhash_SALTBYTES: number;
  crypto_aead_xchacha20poly1305_IETF_ABYTES: number;
  crypto_aead_xchacha20poly1305_IETF_KEYBYTES: number;
  crypto_aead_xchacha20poly1305_IETF_NPUBBYTES: number;
  crypto_aead_xchacha20poly1305_IETF_NSECBYTES: number;
  base64_variant_ORIGINAL: number;
  base64_variant_VARIANT_ORIGINAL_NO_PADDING: number;
  base64_variant_VARIANT_URLSAFE: number;
  base64_variant_VARIANT_URLSAFE_NO_PADDING: number;
};

export const constants: SodiumConstants = SodiumNative.getConstants();

export function crypto_aead_xchacha20poly1305_ietf_encrypt(
  message: string,
  public_nonce: string,
  key: string,
  additional_data: string | null
): string {
  if (typeof g.crypto_aead_xchacha20poly1305_ietf_encrypt !== 'undefined') {
    return g.crypto_aead_xchacha20poly1305_ietf_encrypt(
      message,
      public_nonce,
      key,
      additional_data
    );
  }
  throw Error('[react-native-sodium-jsi] native module not accesible');
}

export function crypto_aead_xchacha20poly1305_ietf_decrypt(
  cipherText: string,
  public_nonce: string,
  key: string,
  additional_data: string | null
): string {
  if (typeof g.crypto_aead_xchacha20poly1305_ietf_decrypt !== 'undefined') {
    return g.crypto_aead_xchacha20poly1305_ietf_decrypt(
      cipherText,
      public_nonce,
      key,
      additional_data
    );
  }
  throw Error('[react-native-sodium-jsi] native module not accesible');
}

export function crypto_pwhash(
  keyLength: number,
  password: string,
  salt: string,
  opsLimit: number,
  memLimit: number,
  algorithm: number
): string {
  if (typeof g.crypto_pwhash !== 'undefined') {
    return g.crypto_pwhash(
      keyLength,
      password,
      salt,
      opsLimit,
      memLimit,
      algorithm
    );
  }
  throw Error('[react-native-sodium-jsi] native module not accesible');
}

export function crypto_aead_xchacha20poly1305_ietf_keygen(): string {
  if (typeof g.crypto_aead_xchacha20poly1305_ietf_keygen !== 'undefined') {
    return g.crypto_aead_xchacha20poly1305_ietf_keygen();
  }
  throw Error('[react-native-sodium-jsi] native module not accesible');
}

export function randombytes_buf(length: number): string {
  if (typeof g.randombytes_buf !== 'undefined') {
    return g.randombytes_buf(length);
  }
  throw Error('[react-native-sodium-jsi] native module not accesible');
}

export function randombytes_random(): number {
  if (typeof g.randombytes_random !== 'undefined') {
    return g.randombytes_random();
  }
  throw Error('[react-native-sodium-jsi] native module not accesible');
}
