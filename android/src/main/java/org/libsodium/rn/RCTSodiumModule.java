package org.libsodium.rn;

/**
 * Created by Lyubomir Ivanov on 21/09/16.
 */

import java.util.Arrays;
import java.util.Map;
import java.util.HashMap;
import android.util.Base64;
import android.util.Log;

import com.facebook.react.bridge.Callback;
import com.facebook.react.bridge.Promise;
import com.facebook.react.bridge.ReactContextBaseJavaModule;
import com.facebook.react.bridge.ReactApplicationContext;
import com.facebook.react.bridge.ReactMethod;
import com.facebook.react.bridge.WritableNativeMap;
import com.facebook.react.common.MapBuilder;
import com.facebook.react.common.StandardCharsets;

import org.libsodium.jni.Sodium;

public class RCTSodiumModule extends ReactContextBaseJavaModule {

  static final String ESODIUM = "ESODIUM";
  static final String ERR_BAD_KEY = "BAD_KEY";
  static final String ERR_BAD_MAC = "BAD_MAC";
  static final String ERR_BAD_MSG = "BAD_MSG";
  static final String ERR_BAD_NONCE = "BAD_NONCE";
  static final String ERR_BAD_SEED = "BAD_SEED";
  static final String ERR_BAD_SIG = "BAD_SIG";
  static final String ERR_FAILURE = "FAILURE";

  public RCTSodiumModule(ReactApplicationContext reactContext) {
    super(reactContext);
    Sodium.loadLibrary();
  }

  @Override
  public String getName() {
    return "Sodium";
  }

  @Override
  public Map<String, Object> getConstants() {
    final Map<String, Object> constants = new HashMap<>();
    constants.put("crypto_pwhash_SALTBYTES", Sodium.crypto_pwhash_salt_bytes());
    constants.put("crypto_pwhash_OPSLIMIT_MODERATE", Sodium.crypto_pwhash_opslimit_moderate());
    constants.put("crypto_pwhash_OPSLIMIT_MIN", Sodium.crypto_pwhash_opslimit_min());
    constants.put("crypto_pwhash_OPSLIMIT_MAX", Sodium.crypto_pwhash_opslimit_max());
    constants.put("crypto_pwhash_MEMLIMIT_MODERATE", Sodium.crypto_pwhash_memlimit_moderate());
    constants.put("crypto_pwhash_MEMLIMIT_MIN", Sodium.crypto_pwhash_memlimit_min());
    constants.put("crypto_pwhash_MEMLIMIT_MAX", Sodium.crypto_pwhash_memlimit_max());
    constants.put("crypto_pwhash_ALG_DEFAULT", Sodium.crypto_pwhash_algo_default());
    constants.put("crypto_pwhash_ALG_ARGON2I13", Sodium.crypto_pwhash_algo_argon2i13());
    constants.put("crypto_pwhash_ALG_ARGON2ID13", Sodium.crypto_pwhash_algo_argon2id13());
    constants.put("crypto_aead_xchacha20poly1305_IETF_ABYTES", Sodium.crypto_aead_chacha20poly1305_IETF_ABYTES());
    constants.put("crypto_aead_xchacha20poly1305_IETF_KEYBYTES", Sodium.crypto_aead_xchacha20poly1305_IETF_KEYBYTES());
    constants.put("crypto_aead_xchacha20poly1305_IETF_NPUBBYTES", Sodium.crypto_aead_xchacha20poly1305_IETF_NPUBBYTES());
    constants.put("crypto_aead_xchacha20poly1305_IETF_NSECBYTES", Sodium.crypto_aead_xchacha20poly1305_IETF_NSECBYTES());
    constants.put("base64_variant_ORIGINAL", Sodium.base64_variant_ORIGINAL());
    constants.put("base64_variant_VARIANT_ORIGINAL_NO_PADDING", Sodium.base64_variant_VARIANT_ORIGINAL_NO_PADDING());
    constants.put("base64_variant_VARIANT_URLSAFE", Sodium.base64_variant_VARIANT_URLSAFE());
    constants.put("base64_variant_VARIANT_URLSAFE_NO_PADDING", Sodium.base64_variant_VARIANT_URLSAFE_NO_PADDING());

    return constants;
  }

  // ***************************************************************************
  // * Sodium-specific functions
  // ***************************************************************************
  @ReactMethod
  public void sodium_version_string(final Promise p) {
    p.resolve(Sodium.sodium_version_string());
  }

  // ***************************************************************************
  // * Random data generation
  // ***************************************************************************
  @ReactMethod
  public void randombytes_random(final Promise p) {
    // RN0.34: Long can't be passed through the bridge (int and double only)
    p.resolve(Long.valueOf(Sodium.randombytes_random()).doubleValue());
  }

  @ReactMethod
  public void randombytes_buf(int size, final Promise p) {
    try {
      byte[] buf = new byte[size];
      Sodium.randombytes_buf(buf, size);
      p.resolve(this.binToHex(buf));
    }
    catch (Throwable t) {
      p.reject(ESODIUM,ERR_FAILURE,t);
    }
  }


  // ***************************************************************************
  // * Public-key cryptography - XChaCha20-Poly1305 encryption
  // ***************************************************************************

  @ReactMethod
  public void crypto_aead_xchacha20poly1305_ietf_keygen(final Promise p) {
    byte[] k = new byte[Sodium.crypto_aead_xchacha20poly1305_IETF_KEYBYTES()];
    Sodium.crypto_aead_xchacha20poly1305_ietf_keygen(k);
    String s = Base64.encodeToString(k, Base64.NO_WRAP);
    p.resolve(s);
  }

  @ReactMethod
  public void crypto_aead_xchacha20poly1305_ietf_encrypt(final String message, final String public_nonce, final String key, final String additionalData, final Promise p) {
    try {
      byte[] m = message.getBytes(StandardCharsets.UTF_8);
      byte[] npub = this.hexToBin(public_nonce);
      byte[] k = this.hexToBin(key);

      if (m.length <= 0)
        p.reject(ESODIUM,ERR_FAILURE);
      else if (npub.length != Sodium.crypto_aead_xchacha20poly1305_IETF_NPUBBYTES())
        p.reject(ESODIUM,ERR_BAD_NONCE);
      else if (k.length != Sodium.crypto_aead_xchacha20poly1305_IETF_KEYBYTES())
        p.reject(ESODIUM,ERR_BAD_KEY);
      else {
        byte[] ad = additionalData != null ? additionalData.getBytes(StandardCharsets.UTF_8) : null;
        int adlen = additionalData != null ? ad.length : 0;
        byte[] c = new byte[m.length + Sodium.crypto_aead_chacha20poly1305_IETF_ABYTES()];
        int result = Sodium.crypto_aead_xchacha20poly1305_ietf_encrypt(c, null, m, m.length, ad, adlen, null, npub, k);
        if (result != 0)
          p.reject(ESODIUM,ERR_FAILURE);
        else
          p.resolve(this.binToBase64(c, Sodium.base64_variant_ORIGINAL()));
      }
    }
    catch (Throwable t) {
      p.reject(ESODIUM,ERR_FAILURE,t);
    }
  }

  @ReactMethod
  public void crypto_aead_xchacha20poly1305_ietf_decrypt(final String cipherText, final String public_nonce, final String key, final String additionalData, final Promise p) {
    try {
      byte[] c = this.base64ToBin(cipherText, Sodium.base64_variant_ORIGINAL());
      byte[] npub = this.hexToBin(public_nonce);
      byte[] k = this.hexToBin(key);
      if (c == null || c.length <= 0)
        p.reject(ESODIUM,ERR_FAILURE);
      else if (npub.length != Sodium.crypto_aead_xchacha20poly1305_IETF_NPUBBYTES())
        p.reject(ESODIUM,ERR_BAD_NONCE);
      else if (k.length != Sodium.crypto_aead_xchacha20poly1305_IETF_KEYBYTES())
        p.reject(ESODIUM,ERR_BAD_KEY);
      else {
        byte[] ad = additionalData != null ? additionalData.getBytes(StandardCharsets.UTF_8) : null;
        int adlen = additionalData != null ? ad.length : 0;
        int[] decrypted_len = new int[1];
        byte[] decrypted = new byte[c.length - Sodium.crypto_aead_chacha20poly1305_IETF_ABYTES()];

        int result = Sodium.crypto_aead_xchacha20poly1305_ietf_decrypt(decrypted, decrypted_len, null, c, c.length, ad, adlen, npub, k);
        if (result != 0)
          p.reject(ESODIUM,ERR_FAILURE);
        else
          p.resolve(new String(decrypted, StandardCharsets.UTF_8));
      }
    }
    catch (Throwable t) {
      p.reject(ESODIUM,ERR_FAILURE,t);
    }
  }

  @ReactMethod
  public void crypto_pwhash(final Integer keylen, final String password, final String salt, final Integer opslimit, final Integer memlimit, final Integer algo , final Promise p) {
    try {
      byte[] saltb = this.hexToBin(salt);
      byte[] passwordb = password.getBytes(StandardCharsets.UTF_8);
      byte[] out = new byte[keylen];

      int result = Sodium.crypto_pwhash(out, out.length, passwordb, passwordb.length, saltb, opslimit, memlimit, algo);
      if (result != 0)
        p.reject(ESODIUM,ERR_FAILURE);
      else
        p.resolve(this.binToHex(out));
    }
    catch (Throwable t) {
      p.reject(ESODIUM,ERR_FAILURE,t);
    }
  }

  // ***************************************************************************
  // * Utils
  // ***************************************************************************

  @ReactMethod
  public void to_base64(final String message, final int variant, final Promise p) {
    byte[] m = message.getBytes(StandardCharsets.UTF_8);
    String result = this.binToBase64(m, variant);
    if (result == null) {
      p.reject(ESODIUM,ERR_FAILURE);
    } else {
      p.resolve(result);
    }
  }

  @ReactMethod
  public void from_base64(final String cipher, final int variant, final Promise p) {
    byte[] result = this.base64ToBin(cipher, variant);
    if (result == null) {
      p.reject(ESODIUM,ERR_FAILURE);
    } else {
      p.resolve(new String(result, StandardCharsets.UTF_8));
    }
  }

  @ReactMethod
  public void to_hex(final String message, final Promise p) {
    byte[] m = message.getBytes(StandardCharsets.UTF_8);
    String result = this.binToHex(m);
    if (result == null) {
      p.reject(ESODIUM,ERR_FAILURE);
    } else {
      p.resolve(result);
    }
  }

  @ReactMethod
  public void from_hex(final String cipher, final Promise p) {
    byte[] result = this.hexToBin(cipher);
    if (result == null) {
      p.reject(ESODIUM,ERR_FAILURE);
    } else {
      p.resolve(new String(result, StandardCharsets.UTF_8));
    }
  }

  private String binToBase64(final byte[] data, final int variant) {
    try {
      if (data.length <= 0 || variant == 0)
        return null;
      else {
        int encoded_len = Sodium.sodium_base64_encoded_len(data.length, variant);
        byte[] encoded = new byte[encoded_len];
        Sodium.sodium_bin2base64(encoded, encoded_len, data, data.length, variant);
        String result = new String(encoded, StandardCharsets.UTF_8);
        return result.substring(0, result.length() - 1); // remove /0 byte
      }
    }
    catch (Throwable t) {
      return null;
    }
  }

  private byte[] base64ToBin(String cipher, final int variant) {
    try {
      byte[] c = cipher.getBytes(StandardCharsets.UTF_8);

      if (c.length <= 0 || variant == 0)
        return null;

      else {
        int blen = c.length;
        byte[] decoded = new byte[blen];
        int[] decoded_len = new int[1];
        int result = Sodium.sodium_base642bin(decoded, blen, c, c.length, null, decoded_len, null, variant);
        if (result != 0)
          return null;
        else
          return Arrays.copyOfRange(decoded, 0, decoded_len[0]);
      }
    }
    catch (Throwable t) {
      return null;
    }
  }

  private String binToHex(final byte[] data) {
    try {
      if (data.length <= 0)
        return null;

      else {
        int encoded_len = data.length * 2 + 1;
        byte[] encoded = new byte[encoded_len];
        Sodium.sodium_bin2hex(encoded, encoded_len, data, data.length);
        String result = new String(encoded, StandardCharsets.UTF_8);
        return result.substring(0, result.length() - 1); // remove /0 byte
      }
    } catch (Throwable t) {
      return null;
    }
  }

  private byte[] hexToBin(String cipher) {
    try {
      byte[] c = cipher.getBytes(StandardCharsets.UTF_8);

      if (c.length <= 0)
        return null;

      else {
        int blen = c.length;
        byte[] decoded = new byte[blen];
        int[] decoded_len = new int[1];
        int result = Sodium.sodium_hex2bin(decoded, blen, c, c.length, null, decoded_len, null);
        if (result != 0)
          return null;
        else
          return Arrays.copyOfRange(decoded, 0, decoded_len[0]);
      }
    } catch (Throwable t) {
      return null;
    }
  }
}
