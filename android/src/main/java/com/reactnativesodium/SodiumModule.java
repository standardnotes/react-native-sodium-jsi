package com.reactnativesodium;

import android.util.Log;

import androidx.annotation.NonNull;

import com.facebook.react.bridge.JavaScriptContextHolder;
import com.facebook.react.bridge.Promise;
import com.facebook.react.bridge.ReactApplicationContext;
import com.facebook.react.bridge.ReactContextBaseJavaModule;
import com.facebook.react.bridge.ReactMethod;
import com.facebook.react.module.annotations.ReactModule;

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

    @ReactMethod(isBlockingSynchronousMethod = true)
    public boolean install() {
      try {
        Log.i(NAME, "Loading C++ library...");
        System.loadLibrary("reactnativesodiumjsi");
        JavaScriptContextHolder jsContext = getReactApplicationContext().getJavaScriptContextHolder();
        Log.i(NAME, "Installing JSI Bindings...");
        install(jsContext.get(), this);
        return true;
      } catch (Exception exception) {
        Log.e(NAME, "Failed to install JSI Bindings!", exception);
        return false;
      }
    }

    public static native void install(long jsiPointer, SodiumModule instance);
}
