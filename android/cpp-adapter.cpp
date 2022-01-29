#include "sodium-jsi.h"
#include <jni.h>

extern "C"
JNIEXPORT void JNICALL
Java_com_reactnativesodium_SodiumModule_install(JNIEnv *env, jclass clazz, jlong jsi_pointer,
                                                jobject instance) {
    auto runtime = reinterpret_cast<facebook::jsi::Runtime*>(jsi_pointer);
    if (runtime) {
       install(*reinterpret_cast<facebook::jsi::Runtime*>(jsi_pointer));
    }
}
