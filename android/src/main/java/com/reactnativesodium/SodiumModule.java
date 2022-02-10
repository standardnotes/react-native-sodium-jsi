package com.reactnativesodium;

import android.util.Log;

import androidx.annotation.NonNull;

import com.facebook.react.bridge.JavaScriptContextHolder;
import com.facebook.react.bridge.ReactApplicationContext;
import com.facebook.react.bridge.ReactContextBaseJavaModule;
import com.facebook.react.bridge.ReactMethod;
import com.facebook.react.module.annotations.ReactModule;

import java.util.HashMap;
import java.util.Map;

@ReactModule(name = SodiumModule.NAME)
public class SodiumModule extends ReactContextBaseJavaModule {
    public static final String NAME = "Sodium";

    public SodiumModule(ReactApplicationContext reactContext) {
        super(reactContext);
    }

    @Override
    @NonNull
    public String getName() {
        return NAME;
    }

  @Override
  public Map<String, Object> getConstants() {
    final Map<String, Object> constants = new HashMap<>();
    constants.put("crypto_pwhash_SALTBYTES", crypto_pwhash_salt_bytes());
    constants.put("crypto_pwhash_OPSLIMIT_MODERATE", crypto_pwhash_opslimit_moderate());
    constants.put("crypto_pwhash_OPSLIMIT_MIN", crypto_pwhash_opslimit_min());
    constants.put("crypto_pwhash_OPSLIMIT_MAX", crypto_pwhash_opslimit_max());
    constants.put("crypto_pwhash_MEMLIMIT_MODERATE", crypto_pwhash_memlimit_moderate());
    constants.put("crypto_pwhash_MEMLIMIT_MIN", crypto_pwhash_memlimit_min());
    constants.put("crypto_pwhash_MEMLIMIT_MAX", crypto_pwhash_memlimit_max());
    constants.put("crypto_pwhash_ALG_DEFAULT", crypto_pwhash_algo_default());
    constants.put("crypto_pwhash_ALG_ARGON2I13", crypto_pwhash_algo_argon2i13());
    constants.put("crypto_pwhash_ALG_ARGON2ID13", crypto_pwhash_algo_argon2id13());
    constants.put("crypto_aead_xchacha20poly1305_IETF_ABYTES", crypto_aead_chacha20poly1305_IETF_ABYTES());
    constants.put("crypto_aead_xchacha20poly1305_IETF_KEYBYTES", crypto_aead_xchacha20poly1305_IETF_KEYBYTES());
    constants.put("crypto_aead_xchacha20poly1305_IETF_NPUBBYTES", crypto_aead_xchacha20poly1305_IETF_NPUBBYTES());
    constants.put("crypto_aead_xchacha20poly1305_IETF_NSECBYTES", crypto_aead_xchacha20poly1305_IETF_NSECBYTES());
    constants.put("base64_variant_ORIGINAL", base64_variant_ORIGINAL());
    constants.put("base64_variant_VARIANT_ORIGINAL_NO_PADDING", base64_variant_VARIANT_ORIGINAL_NO_PADDING());
    constants.put("base64_variant_VARIANT_URLSAFE", base64_variant_VARIANT_URLSAFE());
    constants.put("base64_variant_VARIANT_URLSAFE_NO_PADDING", base64_variant_VARIANT_URLSAFE_NO_PADDING());

    return constants;
  }

    @ReactMethod(isBlockingSynchronousMethod = true)
    public boolean install() {
      try {
        Log.i(NAME, "Loading C++ library...");
        System.loadLibrary("reactnativesodiumjsi");
        JavaScriptContextHolder jsContext = getReactApplicationContext().getJavaScriptContextHolder();
        Log.i(NAME, "Installing JSI Bindings...");
        install(jsContext.get());
        return true;
      } catch (Exception exception) {
        Log.e(NAME, "Failed to install JSI Bindings!", exception);
        return false;
      }
    }

    public static native void install(long jsiPointer);
    public final static native int crypto_pwhash_salt_bytes();
    public final static native int crypto_pwhash_opslimit_moderate();
    public final static native int crypto_pwhash_opslimit_min();
    public final static native int crypto_pwhash_opslimit_max();
    public final static native int crypto_pwhash_memlimit_moderate();
    public final static native int crypto_pwhash_memlimit_min();
    public final static native int crypto_pwhash_memlimit_max();
    public final static native int crypto_pwhash_algo_default();
    public final static native int crypto_pwhash_algo_argon2i13();
    public final static native int crypto_pwhash_algo_argon2id13();

    public final static native int crypto_aead_chacha20poly1305_IETF_ABYTES();
    public final static native int crypto_aead_xchacha20poly1305_IETF_KEYBYTES();
    public final static native int crypto_aead_xchacha20poly1305_IETF_NPUBBYTES();
    public final static native int crypto_aead_xchacha20poly1305_IETF_NSECBYTES();

    public final static native int base64_variant_ORIGINAL();
    public final static native int base64_variant_VARIANT_ORIGINAL_NO_PADDING();
    public final static native int base64_variant_VARIANT_URLSAFE();
    public final static native int base64_variant_VARIANT_URLSAFE_NO_PADDING();
}
