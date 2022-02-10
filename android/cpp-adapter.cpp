#include "sodium-jsi.h"
#include "sodium.h"
#include <jni.h>

extern "C"
JNIEXPORT void JNICALL
Java_com_reactnativesodium_SodiumModule_install(JNIEnv *env, jclass clazz, jlong jsi_pointer) {
    auto runtime = reinterpret_cast<facebook::jsi::Runtime*>(jsi_pointer);
    if (runtime) {
       install(*runtime);
    }
}

extern "C"
JNIEXPORT jint JNICALL
Java_com_reactnativesodium_SodiumModule_crypto_1pwhash_1salt_1bytes(JNIEnv *env, jclass clazz) {
    return (jint) crypto_pwhash_SALTBYTES;
}

extern "C"
JNIEXPORT jint JNICALL
Java_com_reactnativesodium_SodiumModule_crypto_1pwhash_1opslimit_1moderate(JNIEnv *env,
                                                                           jclass clazz) {
    return (jint) crypto_pwhash_OPSLIMIT_MODERATE;
}

extern "C"
JNIEXPORT jint JNICALL
Java_com_reactnativesodium_SodiumModule_crypto_1pwhash_1opslimit_1min(JNIEnv *env, jclass clazz) {
    return (jint) crypto_pwhash_OPSLIMIT_MIN;
}

extern "C"
JNIEXPORT jint JNICALL
Java_com_reactnativesodium_SodiumModule_crypto_1pwhash_1opslimit_1max(JNIEnv *env, jclass clazz) {
    return (jint) crypto_pwhash_OPSLIMIT_MAX;
}

extern "C"
JNIEXPORT jint JNICALL
Java_com_reactnativesodium_SodiumModule_crypto_1pwhash_1memlimit_1moderate(JNIEnv *env,
                                                                           jclass clazz) {
    return (jint) crypto_pwhash_MEMLIMIT_MODERATE;
}

extern "C"
JNIEXPORT jint JNICALL
Java_com_reactnativesodium_SodiumModule_crypto_1pwhash_1memlimit_1min(JNIEnv *env, jclass clazz) {
    return (jint) crypto_pwhash_MEMLIMIT_MIN;
}

extern "C"
JNIEXPORT jint JNICALL
Java_com_reactnativesodium_SodiumModule_crypto_1pwhash_1memlimit_1max(JNIEnv *env, jclass clazz) {
    return (jint) crypto_pwhash_MEMLIMIT_MAX;
}

extern "C"
JNIEXPORT jint JNICALL
Java_com_reactnativesodium_SodiumModule_crypto_1pwhash_1algo_1default(JNIEnv *env, jclass clazz) {
    return (jint) crypto_pwhash_ALG_DEFAULT;
}

extern "C"
JNIEXPORT jint JNICALL
Java_com_reactnativesodium_SodiumModule_crypto_1pwhash_1algo_1argon2i13(JNIEnv *env, jclass clazz) {
    return (jint) crypto_pwhash_ALG_ARGON2I13;
}

extern "C"
JNIEXPORT jint JNICALL
Java_com_reactnativesodium_SodiumModule_crypto_1pwhash_1algo_1argon2id13(JNIEnv *env,
                                                                         jclass clazz) {
    return (jint) crypto_pwhash_ALG_ARGON2ID13;
}

extern "C"
JNIEXPORT jint JNICALL
Java_com_reactnativesodium_SodiumModule_crypto_1aead_1chacha20poly1305_1IETF_1ABYTES(JNIEnv *env,
                                                                                     jclass clazz) {
    return (jint) crypto_aead_chacha20poly1305_IETF_ABYTES;
}

extern "C"
JNIEXPORT jint JNICALL
Java_com_reactnativesodium_SodiumModule_crypto_1aead_1xchacha20poly1305_1IETF_1KEYBYTES(JNIEnv *env,
                                                                                        jclass clazz) {
    return (jint)crypto_aead_xchacha20poly1305_IETF_KEYBYTES;
}

extern "C"
JNIEXPORT jint JNICALL
Java_com_reactnativesodium_SodiumModule_crypto_1aead_1xchacha20poly1305_1IETF_1NPUBBYTES(
        JNIEnv *env, jclass clazz) {
    return (jint)crypto_aead_xchacha20poly1305_IETF_NPUBBYTES;
}

extern "C"
JNIEXPORT jint JNICALL
Java_com_reactnativesodium_SodiumModule_crypto_1aead_1xchacha20poly1305_1IETF_1NSECBYTES(
        JNIEnv *env, jclass clazz) {
    return (jint)crypto_aead_xchacha20poly1305_IETF_NSECBYTES;
}

extern "C"
JNIEXPORT jint JNICALL
Java_com_reactnativesodium_SodiumModule_base64_1variant_1ORIGINAL(JNIEnv *env, jclass clazz) {
    return (jint)sodium_base64_VARIANT_ORIGINAL;
}

extern "C"
JNIEXPORT jint JNICALL
Java_com_reactnativesodium_SodiumModule_base64_1variant_1VARIANT_1ORIGINAL_1NO_1PADDING(JNIEnv *env,
                                                                                        jclass clazz) {
    return (jint)sodium_base64_VARIANT_ORIGINAL_NO_PADDING;
}

extern "C"
JNIEXPORT jint JNICALL
Java_com_reactnativesodium_SodiumModule_base64_1variant_1VARIANT_1URLSAFE(JNIEnv *env,
                                                                          jclass clazz) {
    return (jint)sodium_base64_VARIANT_URLSAFE;
}

extern "C"
JNIEXPORT jint JNICALL
Java_com_reactnativesodium_SodiumModule_base64_1variant_1VARIANT_1URLSAFE_1NO_1PADDING(JNIEnv *env,
                                                                                       jclass clazz) {
    return (jint)sodium_base64_VARIANT_URLSAFE_NO_PADDING;
}
