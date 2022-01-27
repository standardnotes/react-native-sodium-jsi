#include "sodium.h"
#include "sodium-jsi.h"

#include <vector>
#include <string>
#include <iostream>

using namespace facebook;

static std::string binToHex(const uint8_t * buf, size_t len)
{
    std::string ret;
    ret.resize(len*2+1);
    sodium_bin2hex((char*)ret.data(), ret.size(), buf, len);
    return ret;
}
static std::string binToHex(const std::vector<uint8_t>& buf)
{
    return binToHex(buf.data(), buf.size());
}

static std::vector<uint8_t> hexToBin(jsi::Runtime& runtime, const std::string& str)
{
    std::vector<uint8_t> ret;
    ret.resize(str.size()/2);
    if (str.size()%2 || sodium_hex2bin(ret.data(), ret.size(), str.data(), str.size(), nullptr, nullptr, nullptr) != 0)
        jsi::detail::throwJSError(runtime, "[react-native-sodium] invalid hex input");
    return ret;
}

static std::string binToBase64(const uint8_t * buf, size_t len) {
    std::string ret;
    ret.resize(sodium_base64_encoded_len(len, sodium_base64_VARIANT_ORIGINAL));
    sodium_bin2base64((char*)ret.data(), ret.size(), buf, len, sodium_base64_VARIANT_ORIGINAL);
    return ret;
}

static std::vector<uint8_t> base64ToBin(jsi::Runtime& runtime, const std::string& str)
{
    // since libsodium doesn't provide the reverse of
    // sodium_base64_encoded_len(size_t bin_len, int variant)
    // to estimate bin_maxlen, we set it conservatively to
    // the size of the base64 representation
    std::vector<uint8_t> ret;
    ret.resize(str.size());
    size_t decoded_len;
    if (sodium_base642bin(ret.data(), ret.size(), str.data(), str.size(), nullptr, &decoded_len, nullptr, sodium_base64_VARIANT_ORIGINAL) != 0)
        jsi::detail::throwJSError(runtime, "[react-native-sodium] invalid base64 input");
    ret.resize(decoded_len);
    return ret;
}

void install(jsi::Runtime& jsiRuntime) {
    std::cout << "Initializing react-native-sodium" << "\n";
    
    if (sodium_init() != 0)
        jsi::detail::throwJSError(jsiRuntime, "[react-native-sodium] sodium_init() failed");
    
    auto jsi_crypto_aead_xchacha20poly1305_ietf_keygen = jsi::Function::createFromHostFunction(
        jsiRuntime,
        jsi::PropNameID::forAscii(jsiRuntime, "crypto_aead_xchacha20poly1305_ietf_keygen"),
        0,  // no arguments
        [](jsi::Runtime& runtime, const jsi::Value& thisValue, const jsi::Value* arguments, size_t count) -> jsi::Value {
            unsigned char k[crypto_aead_xchacha20poly1305_ietf_KEYBYTES];
            crypto_aead_xchacha20poly1305_ietf_keygen(k);
            char k_hex[crypto_aead_xchacha20poly1305_ietf_KEYBYTES*2+1];
            sodium_bin2hex(k_hex, sizeof(k_hex), k, sizeof(k));
            return jsi::String::createFromUtf8(runtime, k_hex);
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
        1,  // integer
        [](jsi::Runtime& runtime, const jsi::Value& thisValue, const jsi::Value* arguments, size_t count) -> jsi::Value {
          if (arguments[0].isNull()) {
              jsi::detail::throwJSError(runtime, "[react-native-sodium] size cannot be null in randombytes_buf");
              return {};
          }
          size_t size = arguments[0].asNumber();
          std::vector<uint8_t> buf(size);
          randombytes_buf(buf.data(), size);
          return jsi::String::createFromUtf8(runtime, binToHex(buf));
        }
    );
    jsiRuntime.global().setProperty(jsiRuntime, "randombytes_buf", std::move(jsi_randombytes_buf));
    
    auto jsi_crypto_aead_xchacha20poly1305_ietf_encrypt = jsi::Function::createFromHostFunction(
        jsiRuntime,
        jsi::PropNameID::forAscii(jsiRuntime, "crypto_aead_xchacha20poly1305_ietf_encrypt"),
        4,  // 4 arguments (message as utf8 string, nonce as hex string, key as hex string, assoc_data as utf8 string)
        [](jsi::Runtime& runtime, const jsi::Value& thisValue, const jsi::Value* arguments, size_t count) -> jsi::Value {
            if (arguments[0].isNull() || arguments[1].isNull() || arguments[2].isNull()) {
                jsi::detail::throwJSError(runtime, "[react-native-sodium] jsi_crypto_aead_xchacha20poly1305_ietf_encrypt arguments are null");
            }
        
            std::string message = arguments[0].asString(runtime).utf8(runtime);
            std::string public_nonce = arguments[1].asString(runtime).utf8(runtime);
            std::string key = arguments[2].asString(runtime).utf8(runtime);
            std::string assoc_data = arguments[3].asString(runtime).utf8(runtime);
            
            std::vector<uint8_t> npub = hexToBin(runtime, public_nonce);
            std::vector<uint8_t> k = hexToBin(runtime, key);
            
            if (npub.size() != crypto_aead_xchacha20poly1305_ietf_NPUBBYTES) {
                jsi::detail::throwJSError(runtime, "[react-native-sodium] crypto_aead_xchacha20poly1305_ietf_encrypt wrong nonce length");
            }
            if (k.size() != crypto_aead_xchacha20poly1305_IETF_KEYBYTES) {
                jsi::detail::throwJSError(runtime, "[react-native-sodium] crypto_aead_xchacha20poly1305_ietf_encrypt wrong key length");
            }
            
            std::vector<uint8_t> c;
            unsigned long long clen = crypto_aead_chacha20poly1305_IETF_ABYTES + message.size();
            c.resize(clen);
            
            int result = crypto_aead_xchacha20poly1305_ietf_encrypt(c.data(), &clen, (uint8_t*)message.data(), message.size(), (uint8_t*)assoc_data.data(), assoc_data.size(), NULL, npub.data(), k.data());
            if (result != 0) {
                return jsi::Value(nullptr);
            }
           else {
               return jsi::String::createFromUtf8(runtime, binToBase64(c.data(), clen));
           }
        }
    );
    jsiRuntime.global().setProperty(jsiRuntime, "crypto_aead_xchacha20poly1305_ietf_encrypt", std::move(jsi_crypto_aead_xchacha20poly1305_ietf_encrypt));
    
    auto jsi_crypto_aead_xchacha20poly1305_ietf_decrypt = jsi::Function::createFromHostFunction(
        jsiRuntime,
        jsi::PropNameID::forAscii(jsiRuntime, "crypto_aead_xchacha20poly1305_ietf_decrypt"),
        4,  // 4 arguments (ciphertext as base64 string, nonce as hex string, key as hex string, assoc_data as utf8 string)
        [](jsi::Runtime& runtime, const jsi::Value& thisValue, const jsi::Value* arguments, size_t count) -> jsi::Value {
            
            
          if (arguments[0].isNull() || arguments[1].isNull() || arguments[2].isNull()) {
              jsi::detail::throwJSError(runtime, "[react-native-sodium] crypto_aead_xchacha20poly1305_ietf_decrypt arguments are null");
              return {};
          }
        
            std::string cipherText = arguments[0].asString(runtime).utf8(runtime);
            std::string public_nonce = arguments[1].asString(runtime).utf8(runtime);
            std::string key = arguments[2].asString(runtime).utf8(runtime);
            std::string assoc_data = arguments[3].asString(runtime).utf8(runtime);
            
            std::vector<uint8_t> c = base64ToBin(runtime, cipherText);
            std::vector<uint8_t> npub = hexToBin(runtime, public_nonce);
            std::vector<uint8_t> k = hexToBin(runtime, key);
            
            if (npub.size() != crypto_aead_xchacha20poly1305_ietf_NPUBBYTES) {
                jsi::detail::throwJSError(runtime, "[react-native-sodium] crypto_aead_xchacha20poly1305_ietf_decrypt wrong nonce length");
            }
            if (k.size() != crypto_aead_xchacha20poly1305_IETF_KEYBYTES) {
                jsi::detail::throwJSError(runtime, "[react-native-sodium] crypto_aead_xchacha20poly1305_ietf_decrypt wrong key length");
            }
            
            unsigned long long m_len = c.size();
            std::vector<uint8_t> m;
            m.resize(m_len);
            int result = crypto_aead_xchacha20poly1305_ietf_decrypt(m.data(), &m_len, nullptr, c.data(), c.size(), (uint8_t*)assoc_data.data(), assoc_data.size(), npub.data(), k.data());
            if (result != 0) {
                return jsi::Value(nullptr);
            }
           else {
               jsi::String resultString = jsi::String::createFromUtf8(runtime, m.data(), m_len);
               return resultString;
           }
        }
    );
    jsiRuntime.global().setProperty(jsiRuntime, "crypto_aead_xchacha20poly1305_ietf_decrypt", std::move(jsi_crypto_aead_xchacha20poly1305_ietf_decrypt));
}

void cleanup() {}
