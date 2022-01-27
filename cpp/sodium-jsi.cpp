#import "sodium.h"
#import "sodium-jsi.h"

#include <iostream>
#include <sstream>


using namespace facebook;

unsigned char * const hexToBin(const char *hex) {
    int clen = sizeof(hex);
    unsigned char * const decoded = (unsigned char * const) sodium_malloc(clen);
    size_t decoded_len;
    if (sodium_hex2bin(decoded, clen, hex, clen, NULL, &decoded_len, NULL) != 0) {
            return NULL;
    } else {
        return decoded;
    }
}

char * const binToHex(const unsigned char *bin) {
    size_t hex_maxlen = sizeof(bin) * 2 + 1;
    char * const encoded = (char * const) sodium_malloc(hex_maxlen);
    
    try {
        sodium_bin2hex(encoded, hex_maxlen, bin, sizeof(bin));
        return encoded;
    }
    catch (const std::exception& e) {
        return NULL;
    }
}

unsigned char * const base64ToBin(const char *b64) {
    
    // since libsodium doesn't provide the reverse of
    // sodium_base64_encoded_len(size_t bin_len, int variant)
    // to estimate bin_maxlen, we set it conservatively to
    // the size of the base64 representation

    size_t clen = sizeof(b64);
    unsigned char * const decoded = (unsigned char * const) sodium_malloc(clen);
    size_t decoded_len = sizeof(b64);
    if (sodium_base642bin(decoded, decoded_len, b64, clen, NULL, &decoded_len, NULL, sodium_base64_VARIANT_ORIGINAL)!= 0) {
            return NULL;
    } else {
        return decoded;
    }
}

char * const binToBase64(const unsigned char *bin) {
    const size_t binLength = sizeof(bin);
    if (binLength == 0) return NULL;
    
    const size_t max_len = sodium_base64_encoded_len(binLength,sodium_base64_VARIANT_ORIGINAL);
    char * const encoded = (char * const) sodium_malloc(max_len);
    try {
        sodium_bin2base64(encoded, max_len, bin, binLength, sodium_base64_VARIANT_ORIGINAL);
        return encoded;
    }
    catch (const std::exception& e) {
        return NULL;
    }
}

void install(jsi::Runtime& jsiRuntime) {
    std::cout << "Initializing react-native-sodium" << "\n";
    
    sodium_init();
    
    auto jsi_crypto_aead_xchacha20poly1305_ietf_keygen = jsi::Function::createFromHostFunction(
                                                                        jsiRuntime,
                                                                        jsi::PropNameID::forAscii(jsiRuntime, "crypto_aead_xchacha20poly1305_ietf_keygen"),
                                                                        0,  // no arguments
                                                                        [](jsi::Runtime& runtime, const jsi::Value& thisValue, const jsi::Value* arguments, size_t count) -> jsi::Value {
                                                                            unsigned char k[crypto_aead_xchacha20poly1305_ietf_KEYBYTES];
                                                                            crypto_aead_xchacha20poly1305_ietf_keygen(k);
                                                                            const char *result = binToHex(k);
                                                                            return jsi::String::createFromUtf8(runtime, result);
                                                                        }
                                                                        );
    jsiRuntime.global().setProperty(jsiRuntime, "crypto_aead_xchacha20poly1305_ietf_keygen", std::move(jsi_crypto_aead_xchacha20poly1305_ietf_keygen));
    
    auto jsi_randombytes_random = jsi::Function::createFromHostFunction(
                                                                        jsiRuntime,
                                                                        jsi::PropNameID::forAscii(jsiRuntime, "randombytes_random"),
                                                                        0,  // no arguments
                                                                        [](jsi::Runtime& runtime, const jsi::Value& thisValue, const jsi::Value* arguments, size_t count) -> jsi::Value {
                                                                            uint32_t res = randombytes_random();
                                                                            return jsi::Value((int)res);
                                                                        }
                                                                        );
    jsiRuntime.global().setProperty(jsiRuntime, "randombytes_random", std::move(jsi_randombytes_random));
    
      auto jsi_randombytes_buf = jsi::Function::createFromHostFunction(
          jsiRuntime,
          jsi::PropNameID::forAscii(jsiRuntime, "randombytes_buf"),
          1,  // string
          [](jsi::Runtime& runtime, const jsi::Value& thisValue, const jsi::Value* arguments, size_t count) -> jsi::Value {
            if (arguments[0].isNull()) {
                jsi::detail::throwJSError(runtime, "[react-native-sodium] size cannot be null in randombytes_buf");
                return {};
            }
            u_int32_t size = (u_int32_t) arguments[0].asNumber();
            unsigned char *buf = (unsigned char *) sodium_malloc(size);
            randombytes_buf(buf, size);
            int hex_length = size * 2 + 1;
            char * const hex = (char * const) sodium_malloc(hex_length);
            sodium_bin2hex(hex, hex_length, buf, size);
            sodium_free(buf);
            jsi::String result = jsi::String::createFromUtf8(runtime, hex);
            sodium_free(hex);
              
            return result;
          }
      );
      jsiRuntime.global().setProperty(jsiRuntime, "randombytes_buf", std::move(jsi_randombytes_buf));
    
    
    auto jsi_crypto_aead_xchacha20poly1305_ietf_encrypt = jsi::Function::createFromHostFunction(
        jsiRuntime,
        jsi::PropNameID::forAscii(jsiRuntime, "crypto_aead_xchacha20poly1305_ietf_encrypt"),
        4,  // 4 arguments
        [](jsi::Runtime& runtime, const jsi::Value& thisValue, const jsi::Value* arguments, size_t count) -> jsi::Value {
            
            
          if (arguments[0].isNull() || arguments[1].isNull() || arguments[2].isNull()) {
              jsi::detail::throwJSError(runtime, "[react-native-sodium] jsi_crypto_aead_xchacha20poly1305_ietf_encrypt arguments are null" );
              return {};
          }
        
            std::string message = arguments[0].asString(runtime).utf8(runtime);
            std::string public_nonce = arguments[1].asString(runtime).utf8(runtime);
            std::string key = arguments[2].asString(runtime).utf8(runtime);
            
            const unsigned char *m = hexToBin(message.c_str());
            unsigned char *npub = hexToBin(public_nonce.c_str());
            unsigned char *k = hexToBin(key.c_str());
            
            unsigned long long clen = (unsigned long long) crypto_aead_chacha20poly1305_IETF_ABYTES + sizeof(m);
            unsigned char *c = (unsigned char *) sodium_malloc(crypto_aead_chacha20poly1305_IETF_ABYTES + sizeof(m));
            
            bool hasAdditionalData = !(arguments[3].isNull() || arguments[3].isUndefined());
            auto additionalData = hasAdditionalData ? NULL : NULL;
            const unsigned char *ad = hasAdditionalData ?  NULL : nullptr;
            unsigned long adlen = hasAdditionalData ? sizeof(ad) : 0;
            
            int result = crypto_aead_xchacha20poly1305_ietf_encrypt(c, &clen, m, sizeof(m), NULL, 0, NULL, npub, k);
            if (result != 0) {
                sodium_free(c);
                return jsi::Value(nullptr);
            }
           else {
               const char *b64 = binToBase64(c);
               sodium_free(c);
               return jsi::String::createFromUtf8(runtime, b64);
           }
        }
    );
    jsiRuntime.global().setProperty(jsiRuntime, "crypto_aead_xchacha20poly1305_ietf_encrypt", std::move(jsi_crypto_aead_xchacha20poly1305_ietf_encrypt));
    
    auto jsi_crypto_aead_xchacha20poly1305_ietf_decrypt = jsi::Function::createFromHostFunction(
        jsiRuntime,
        jsi::PropNameID::forAscii(jsiRuntime, "crypto_aead_xchacha20poly1305_ietf_decrypt"),
        4,  // 4 arguments
        [](jsi::Runtime& runtime, const jsi::Value& thisValue, const jsi::Value* arguments, size_t count) -> jsi::Value {
            
            
          if (arguments[0].isNull() || arguments[1].isNull() || arguments[2].isNull()) {
              jsi::detail::throwJSError(runtime, "[react-native-sodium] crypto_aead_xchacha20poly1305_ietf_decrypt arguments are null" );
              return {};
          }
        
            std::string cipherText = arguments[0].asString(runtime).utf8(runtime);
            std::string public_nonce = arguments[1].asString(runtime).utf8(runtime);
            std::string key = arguments[2].asString(runtime).utf8(runtime);
            
            
            const unsigned char *c = reinterpret_cast<const unsigned char*>(base64ToBin(cipherText.c_str()));
            unsigned char *npub = hexToBin(public_nonce.c_str());
            unsigned char *k = hexToBin(key.c_str());
            
            if (sizeof(npub) != crypto_aead_xchacha20poly1305_IETF_KEYBYTES) {
                jsi::detail::throwJSError(runtime, "[react-native-sodium] crypto_aead_xchacha20poly1305_ietf_decrypt wrong nonce length" );
                return {};
            }
            if (sizeof(k) != crypto_aead_xchacha20poly1305_ietf_NPUBBYTES) {
                jsi::detail::throwJSError(runtime, "[react-native-sodium] crypto_aead_xchacha20poly1305_ietf_decrypt wrong key length" );
                return {};
            }
            
            
            bool hasAdditionalData = !(arguments[3].isNull() || arguments[3].isUndefined());
            std::string additionalData = hasAdditionalData ? arguments[3].asString(runtime).utf8(runtime) : NULL;
            const unsigned char *ad = hasAdditionalData ?  reinterpret_cast<const unsigned char*>(additionalData.c_str()) : NULL;
            unsigned long adlen = hasAdditionalData ? sizeof(ad) : 0;
            
            unsigned long long decrypted_len = sizeof(c);
                    unsigned char* decrypted = (unsigned char *) sodium_malloc(decrypted_len - crypto_aead_chacha20poly1305_IETF_ABYTES);
            int result = crypto_aead_xchacha20poly1305_ietf_decrypt(decrypted, &decrypted_len, NULL, c, sizeof(c), ad, adlen, npub, k);
            if (result != 0) {
                sodium_free(decrypted);
                return jsi::Value(nullptr);
            }
           else {
               jsi::String resultString = jsi::String::createFromUtf8(runtime, reinterpret_cast<const char*>(decrypted));
               sodium_free(decrypted);
               return resultString;
           }
        }
    );
    jsiRuntime.global().setProperty(jsiRuntime, "crypto_aead_xchacha20poly1305_ietf_decrypt", std::move(jsi_crypto_aead_xchacha20poly1305_ietf_decrypt));
}

void cleanup() {}
