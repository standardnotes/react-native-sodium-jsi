#include "sodium.h"
#include "sodium-jsi.h"

#include <vector>
#include <string>
#include <iostream>

using namespace facebook;

static std::string binToHex(const uint8_t *buf, size_t len)
{
    std::string ret;
    ret.resize(len * 2 + 1);
    sodium_bin2hex((char *)ret.data(), ret.size(), buf, len);
    if (ret.size() && ret[ret.size() - 1] == '\0')
    {
        ret.resize(ret.size() - 1); // sodium_bin2hex appends a null terminator, drop it
    }
    return ret;
}
static std::string binToHex(const std::vector<uint8_t> &buf)
{
    return binToHex(buf.data(), buf.size());
}

static std::vector<uint8_t> hexToBin(jsi::Runtime &runtime, const std::string &str)
{
    std::vector<uint8_t> ret;
    ret.resize(str.size());
    size_t decoded_len = 0;
    if (str.size() % 2 || sodium_hex2bin(ret.data(), ret.size(), str.data(), str.size(), nullptr, &decoded_len, nullptr) != 0)
        jsi::detail::throwJSError(runtime, "[react-native-sodium-jsi] invalid hex input");
    ret.resize(decoded_len);
    return ret;
}

static std::string binToBase64(const uint8_t *buf, size_t len, uint8_t variant)
{
    std::string ret;
    ret.resize(sodium_base64_encoded_len(len, variant));
    sodium_bin2base64((char *)ret.data(), ret.size(), buf, len, variant);
    if (ret.size() && ret[ret.size() - 1] == '\0')
    {
        ret.resize(ret.size() - 1); // sodium_bin2base64 appends a null terminator, drop it
    }
    return ret;
}

static std::vector<uint8_t> base64ToBin(jsi::Runtime &runtime, const std::string &str)
{
    std::vector<uint8_t> ret;
    // binary is 0.75x of the base64 string
    ret.resize((str.size() / 4) * 3);
    size_t decoded_len = 0;
    if (sodium_base642bin(ret.data(), ret.size(), str.data(), str.size(), nullptr, &decoded_len, nullptr, sodium_base64_VARIANT_ORIGINAL) != 0)
    {
        jsi::detail::throwJSError(runtime, "[react-native-sodium-jsi] invalid base64 input");
    }
    ret.resize(decoded_len);
    return ret;
}

static jsi::Value createArrayBuffer(jsi::Runtime &runtime, size_t size)
{
    return runtime.global().getPropertyAsFunction(runtime, "ArrayBuffer").callAsConstructor(runtime, (double)size);
}

static jsi::ArrayBuffer asArrayBuffer(jsi::Runtime &runtime, const jsi::Value &val)
{
    jsi::Object obj = val.asObject(runtime);
    if (!obj.isArrayBuffer(runtime))
        jsi::detail::throwJSError(runtime, "[react-native-sodium-jsi] expected ArrayBuffer");
    return obj.getArrayBuffer(runtime);
}
static uint8_t *extractArrayBuffer(jsi::Runtime &runtime, const jsi::Value &val, size_t size)
{
    jsi::ArrayBuffer buf = asArrayBuffer(runtime, val);
    if (buf.size(runtime) != size)
        jsi::detail::throwJSError(runtime, "[react-native-sodium-jsi] unexpected ArrayBuffer size");
    return buf.data(runtime);
}
template <typename T>
T *extractArrayBuffer(jsi::Runtime &runtime, const jsi::Value &val)
{
    return (T *)extractArrayBuffer(runtime, val, sizeof(T));
}

void install(jsi::Runtime &jsiRuntime)
{
    std::cout << "Initializing react-native-sodium-jsi"
              << "\n";

    if (sodium_init() == -1)
        jsi::detail::throwJSError(jsiRuntime, "[react-native-sodium-jsi] sodium_init() failed");

    auto jsi_crypto_aead_xchacha20poly1305_ietf_keygen = jsi::Function::createFromHostFunction(
        jsiRuntime,
        jsi::PropNameID::forUtf8(jsiRuntime, "crypto_aead_xchacha20poly1305_ietf_keygen"),
        0, // no arguments
        [](jsi::Runtime &runtime, const jsi::Value &thisValue, const jsi::Value *arguments, size_t count) -> jsi::Value
        {
            unsigned char k[crypto_aead_xchacha20poly1305_ietf_KEYBYTES];
            crypto_aead_xchacha20poly1305_ietf_keygen(k);
            char k_hex[crypto_aead_xchacha20poly1305_ietf_KEYBYTES * 2 + 1];
            sodium_bin2hex(k_hex, sizeof(k_hex), k, sizeof(k));
            return jsi::String::createFromUtf8(runtime, k_hex);
        });
    jsiRuntime.global().setProperty(jsiRuntime, "crypto_aead_xchacha20poly1305_ietf_keygen", std::move(jsi_crypto_aead_xchacha20poly1305_ietf_keygen));

    auto jsi_randombytes_random = jsi::Function::createFromHostFunction(
        jsiRuntime,
        jsi::PropNameID::forUtf8(jsiRuntime, "randombytes_random"),
        0, // no arguments
        [](jsi::Runtime &runtime, const jsi::Value &thisValue, const jsi::Value *arguments, size_t count) -> jsi::Value
        {
            uint32_t res = randombytes_random();
            return jsi::Value((int)res);
        });
    jsiRuntime.global().setProperty(jsiRuntime, "randombytes_random", std::move(jsi_randombytes_random));

    auto jsi_randombytes_buf = jsi::Function::createFromHostFunction(
        jsiRuntime,
        jsi::PropNameID::forUtf8(jsiRuntime, "randombytes_buf"),
        1, // integer
        [](jsi::Runtime &runtime, const jsi::Value &thisValue, const jsi::Value *arguments, size_t count) -> jsi::Value
        {
            if (arguments[0].isNull())
            {
                jsi::detail::throwJSError(runtime, "[react-native-sodium-jsi] size cannot be null in randombytes_buf");
                return {};
            }
            size_t size = arguments[0].asNumber();
            std::vector<uint8_t> buf(size);
            randombytes_buf(buf.data(), size);
            return jsi::String::createFromUtf8(runtime, binToHex(buf));
        });
    jsiRuntime.global().setProperty(jsiRuntime, "randombytes_buf", std::move(jsi_randombytes_buf));

    auto jsi_crypto_aead_xchacha20poly1305_ietf_encrypt = jsi::Function::createFromHostFunction(
        jsiRuntime,
        jsi::PropNameID::forUtf8(jsiRuntime, "crypto_aead_xchacha20poly1305_ietf_encrypt"),
        4, // 4 arguments (message as utf8 string, nonce as hex string, key as hex string, assoc_data as utf8 string)
        [](jsi::Runtime &runtime, const jsi::Value &thisValue, const jsi::Value *arguments, size_t count) -> jsi::Value
        {
            if (arguments[0].isNull() || arguments[1].isNull() || arguments[2].isNull())
            {
                jsi::detail::throwJSError(runtime, "[react-native-sodium-jsi] jsi_crypto_aead_xchacha20poly1305_ietf_encrypt arguments are null");
            }

            std::string message = arguments[0].asString(runtime).utf8(runtime);
            std::string public_nonce = arguments[1].asString(runtime).utf8(runtime);
            std::string key = arguments[2].asString(runtime).utf8(runtime);
            std::string assoc_data = arguments[3].asString(runtime).utf8(runtime);

            std::vector<uint8_t> npub = hexToBin(runtime, public_nonce);
            std::vector<uint8_t> k = hexToBin(runtime, key);

            if (npub.size() != crypto_aead_xchacha20poly1305_ietf_NPUBBYTES)
            {
                jsi::detail::throwJSError(runtime, "[react-native-sodium-jsi] crypto_aead_xchacha20poly1305_ietf_encrypt wrong nonce length");
            }
            if (k.size() != crypto_aead_xchacha20poly1305_IETF_KEYBYTES)
            {
                jsi::detail::throwJSError(runtime, "[react-native-sodium-jsi] crypto_aead_xchacha20poly1305_ietf_encrypt wrong key length");
            }

            std::vector<uint8_t> c;
            unsigned long long clen = crypto_aead_chacha20poly1305_IETF_ABYTES + message.size();
            c.resize(clen);

            int result = crypto_aead_xchacha20poly1305_ietf_encrypt(c.data(), &clen, (uint8_t *)message.data(), message.size(), (uint8_t *)assoc_data.data(), assoc_data.size(), NULL, npub.data(), k.data());
            if (result != 0)
            {
                return jsi::Value(nullptr);
            }
            else
            {
                return jsi::String::createFromUtf8(runtime, binToBase64(c.data(), clen, sodium_base64_VARIANT_ORIGINAL));
            }
        });
    jsiRuntime.global().setProperty(jsiRuntime, "crypto_aead_xchacha20poly1305_ietf_encrypt", std::move(jsi_crypto_aead_xchacha20poly1305_ietf_encrypt));

    auto jsi_crypto_aead_xchacha20poly1305_ietf_decrypt = jsi::Function::createFromHostFunction(
        jsiRuntime,
        jsi::PropNameID::forUtf8(jsiRuntime, "crypto_aead_xchacha20poly1305_ietf_decrypt"),
        4, // 4 arguments (ciphertext as base64 string, nonce as hex string, key as hex string, assoc_data as utf8 string)
        [](jsi::Runtime &runtime, const jsi::Value &thisValue, const jsi::Value *arguments, size_t count) -> jsi::Value
        {
            if (arguments[0].isNull() || arguments[1].isNull() || arguments[2].isNull())
            {
                jsi::detail::throwJSError(runtime, "[react-native-sodium-jsi] crypto_aead_xchacha20poly1305_ietf_decrypt arguments are null");
                return {};
            }

            std::string cipherText = arguments[0].asString(runtime).utf8(runtime);
            std::string public_nonce = arguments[1].asString(runtime).utf8(runtime);
            std::string key = arguments[2].asString(runtime).utf8(runtime);
            std::string assoc_data = arguments[3].asString(runtime).utf8(runtime);

            std::vector<uint8_t> c = base64ToBin(runtime, cipherText);
            std::vector<uint8_t> npub = hexToBin(runtime, public_nonce);
            std::vector<uint8_t> k = hexToBin(runtime, key);

            if (npub.size() != crypto_aead_xchacha20poly1305_ietf_NPUBBYTES)
            {
                jsi::detail::throwJSError(runtime, "[react-native-sodium-jsi] crypto_aead_xchacha20poly1305_ietf_decrypt wrong nonce length");
            }
            if (k.size() != crypto_aead_xchacha20poly1305_IETF_KEYBYTES)
            {
                jsi::detail::throwJSError(runtime, "[react-native-sodium-jsi] crypto_aead_xchacha20poly1305_ietf_decrypt wrong key length");
            }

            unsigned long long m_len = c.size();
            std::vector<uint8_t> m;
            m.resize(m_len);
            int result = crypto_aead_xchacha20poly1305_ietf_decrypt(m.data(), &m_len, nullptr, c.data(), c.size(), (uint8_t *)assoc_data.data(), assoc_data.size(), npub.data(), k.data());
            if (result != 0)
            {
                return jsi::Value(nullptr);
            }
            else
            {
                jsi::String resultString = jsi::String::createFromUtf8(runtime, m.data(), m_len);
                return resultString;
            }
        });
    jsiRuntime.global().setProperty(jsiRuntime, "crypto_aead_xchacha20poly1305_ietf_decrypt", std::move(jsi_crypto_aead_xchacha20poly1305_ietf_decrypt));

    auto jsi_crypto_pwhash = jsi::Function::createFromHostFunction(
        jsiRuntime,
        jsi::PropNameID::forUtf8(jsiRuntime, "crypto_pwhash"),
        5, // 5 arguments (desiredKeyLength as int, password as utf8 string, salt as hex string, iterations as int, memLimit as int)
        [](jsi::Runtime &runtime, const jsi::Value &thisValue, const jsi::Value *arguments, size_t count) -> jsi::Value
        {
            if (arguments[0].isNull() || arguments[1].isNull() || arguments[2].isNull() || arguments[3].isNull() || arguments[4].isNull())
            {
                jsi::detail::throwJSError(runtime, "[react-native-sodium-jsi] jsi_crypto_pwhash arguments are null");
            }

            unsigned long long length = arguments[0].asNumber();
            std::string password = arguments[1].asString(runtime).utf8(runtime);
            std::vector<uint8_t> salt = hexToBin(runtime, arguments[2].asString(runtime).utf8(runtime));
            unsigned long long iterations = arguments[3].asNumber();
            unsigned long long bytes = arguments[4].asNumber();

            if (length < crypto_pwhash_argon2id_BYTES_MIN || length > crypto_pwhash_argon2id_BYTES_MAX)
            {
                jsi::detail::throwJSError(runtime, "[react-native-sodium-jsi] crypto_pwhash wrong output length");
            }
            if (salt.size() != crypto_pwhash_argon2id_SALTBYTES)
            {
                jsi::detail::throwJSError(runtime, "[react-native-sodium-jsi] crypto_pwhash wrong salt length");
            }

            std::vector<uint8_t> ret;
            ret.resize(length);

            int result = crypto_pwhash(ret.data(), length, password.data(), password.size(), salt.data(), iterations, bytes, crypto_pwhash_ALG_ARGON2ID13);
            if (result != 0)
            {
                return jsi::Value(nullptr);
            }
            else
            {
                // returns hex string
                return jsi::String::createFromUtf8(runtime, binToHex(ret.data(), length));
            }
        });
    jsiRuntime.global().setProperty(jsiRuntime, "crypto_pwhash", std::move(jsi_crypto_pwhash));

    auto jsi_crypto_secretstream_xchacha20poly1305_init_push = jsi::Function::createFromHostFunction(
        jsiRuntime,
        jsi::PropNameID::forUtf8(jsiRuntime, "crypto_secretstream_xchacha20poly1305_init_push"),
        1, // 1 arguments (key as hex string)
        [](jsi::Runtime &runtime, const jsi::Value &thisValue, const jsi::Value *arguments, size_t count) -> jsi::Value
        {
            if (arguments[0].isNull())
            {
                jsi::detail::throwJSError(runtime, "[react-native-sodium-jsi] crypto_secretstream_xchacha20poly1305_init_push arguments are null");
            }

            std::vector<uint8_t> k = hexToBin(runtime, arguments[0].asString(runtime).utf8(runtime));
            if (k.size() != crypto_secretstream_xchacha20poly1305_keybytes())
            {
                jsi::detail::throwJSError(runtime, "[react-native-sodium-jsi] crypto_secretstream_xchacha20poly1305_init_push wrong key length");
            }

            jsi::Value state = createArrayBuffer(runtime, sizeof(crypto_secretstream_xchacha20poly1305_state));
            auto state_pointer = extractArrayBuffer<crypto_secretstream_xchacha20poly1305_state>(runtime, state);

            uint8_t header[crypto_secretstream_xchacha20poly1305_HEADERBYTES];

            int result = crypto_secretstream_xchacha20poly1305_init_push(state_pointer, header, k.data());
            if (result != 0)
            {
                return jsi::Value(nullptr);
            }
            else
            {
                // returns {state: crypto_secretstream_xchacha20poly1305_state, header: base64 string}
                jsi::Object ret(runtime);
                ret.setProperty(runtime, "state", state);
                ret.setProperty(runtime, "header", jsi::String::createFromUtf8(runtime, binToBase64(header, sizeof(header), sodium_base64_VARIANT_ORIGINAL)));
                return ret;
            }
        });
    jsiRuntime.global().setProperty(jsiRuntime, "crypto_secretstream_xchacha20poly1305_init_push", std::move(jsi_crypto_secretstream_xchacha20poly1305_init_push));

    auto jsi_crypto_secretstream_xchacha20poly1305_push = jsi::Function::createFromHostFunction(
        jsiRuntime,
        jsi::PropNameID::forUtf8(jsiRuntime, "crypto_secretstream_xchacha20poly1305_push"),
        4, // 4 arguments (    state: crypto_secretstream_xchacha20poly1305_state, plainBuffer: Uint8Array, assocData: Utf8String, tag: int | CRYPTO_SECRETSTREAM_XCHACHA20POLY1305_TAG_PUSH | crypto_secretstream_xchacha20poly1305_TAG_FINAL,)
        [](jsi::Runtime &runtime, const jsi::Value &thisValue, const jsi::Value *arguments, size_t count) -> jsi::Value
        {
            if (arguments[0].isNull())
            {
                jsi::detail::throwJSError(runtime, "[react-native-sodium-jsi] crypto_secretstream_xchacha20poly1305_push arguments are null");
            }

            auto *state_pointer = extractArrayBuffer<crypto_secretstream_xchacha20poly1305_state>(runtime, arguments[0]);
            jsi::ArrayBuffer message = asArrayBuffer(runtime, arguments[1]);
            std::string assoc_data = arguments[2].asString(runtime).utf8(runtime);
            uint8_t tag = arguments[3].asNumber();

            size_t ret_size = crypto_secretstream_xchacha20poly1305_ABYTES + message.size(runtime);
            jsi::Value ret = createArrayBuffer(runtime, ret_size);
            uint8_t *ret_ptr = extractArrayBuffer(runtime, ret, ret_size);

            int result = crypto_secretstream_xchacha20poly1305_push(state_pointer, ret_ptr, nullptr, message.data(runtime), message.size(runtime), (uint8_t *)assoc_data.data(), assoc_data.size(), tag);
            if (result != 0)
            {
                return jsi::Value(nullptr);
            }
            else
            {
                // returns raw byte data/uint8array
                return runtime.global().getPropertyAsFunction(runtime, "Uint8Array").callAsConstructor(runtime, ret);
            }
        });
    jsiRuntime.global().setProperty(jsiRuntime, "crypto_secretstream_xchacha20poly1305_push", std::move(jsi_crypto_secretstream_xchacha20poly1305_push));

    auto jsi_crypto_secretstream_xchacha20poly1305_init_pull = jsi::Function::createFromHostFunction(
        jsiRuntime,
        jsi::PropNameID::forUtf8(jsiRuntime, "crypto_secretstream_xchacha20poly1305_init_pull"),
        2, // 2 arguments ( header: base64string, key: hex string)
        [](jsi::Runtime &runtime, const jsi::Value &thisValue, const jsi::Value *arguments, size_t count) -> jsi::Value
        {
            if (arguments[0].isNull())
            {
                jsi::detail::throwJSError(runtime, "[react-native-sodium-jsi] crypto_secretstream_xchacha20poly1305_init_pull arguments are null");
            }

            std::vector<uint8_t> header = base64ToBin(runtime, arguments[0].asString(runtime).utf8(runtime));
            if (header.size() != crypto_secretstream_xchacha20poly1305_HEADERBYTES)
            {
                jsi::detail::throwJSError(runtime, "[react-native-sodium-jsi] crypto_secretstream_xchacha20poly1305_init_pull wrong header length");
            }

            std::vector<uint8_t> key = hexToBin(runtime, arguments[1].asString(runtime).utf8(runtime));
            if (key.size() != crypto_secretstream_xchacha20poly1305_keybytes())
            {
                jsi::detail::throwJSError(runtime, "[react-native-sodium-jsi] crypto_secretstream_xchacha20poly1305_init_push wrong key length");
            }

            jsi::Value state = createArrayBuffer(runtime, sizeof(crypto_secretstream_xchacha20poly1305_state));
            auto state_pointer = extractArrayBuffer<crypto_secretstream_xchacha20poly1305_state>(runtime, state);

            int result = crypto_secretstream_xchacha20poly1305_init_pull(state_pointer, header.data(), key.data());
            if (result != 0)
            {
                return jsi::Value(nullptr);
            }
            else
            {
                jsi::Object ret(runtime);
                ret.setProperty(runtime, "state", state);
                return ret;
            }
        });
    jsiRuntime.global().setProperty(jsiRuntime, "crypto_secretstream_xchacha20poly1305_init_pull", std::move(jsi_crypto_secretstream_xchacha20poly1305_init_pull));

    auto jsi_crypto_secretstream_xchacha20poly1305_pull = jsi::Function::createFromHostFunction(
        jsiRuntime,
        jsi::PropNameID::forUtf8(jsiRuntime, "crypto_secretstream_xchacha20poly1305_pull"),
        3, // 3 arguments ( state: crypto_secretstream_xchacha20poly1305_state, encryptedBuffer: uint8array, assocData: utf8string)
        [](jsi::Runtime &runtime, const jsi::Value &thisValue, const jsi::Value *arguments, size_t count) -> jsi::Value
        {
            if (arguments[0].isNull())
            {
                jsi::detail::throwJSError(runtime, "[react-native-sodium-jsi] crypto_secretstream_xchacha20poly1305_pull arguments are null");
            }

            auto *state_pointer = extractArrayBuffer<crypto_secretstream_xchacha20poly1305_state>(runtime, arguments[0]);
            jsi::ArrayBuffer ciphertext = asArrayBuffer(runtime, arguments[1]);
            std::string assoc_data = arguments[2].asString(runtime).utf8(runtime);

            if (ciphertext.size(runtime) < crypto_secretstream_xchacha20poly1305_ABYTES)
                jsi::detail::throwJSError(runtime, "[react-native-sodium-jsi] crypto_secretstream_xchacha20poly1305_pull too short ciphertext");
            size_t ret_size = ciphertext.size(runtime) - crypto_secretstream_xchacha20poly1305_ABYTES;
            jsi::Value message = createArrayBuffer(runtime, ret_size);
            uint8_t *message_ptr = extractArrayBuffer(runtime, message, ret_size);
            uint8_t tag;

            int result_flag = crypto_secretstream_xchacha20poly1305_pull(state_pointer, message_ptr, nullptr, &tag, ciphertext.data(runtime), ciphertext.size(runtime), (uint8_t *)assoc_data.data(), assoc_data.size());
            if (result_flag != 0)
            {
                return jsi::Value(nullptr);
            }
            else
            {
                // returns { message: Uint8Array; tag: int/CRYPTO_SECRETSTREAM_XCHACHA20POLY1305_TAG }
                jsi::Object return_value(runtime);
                return_value.setProperty(runtime, "message", message);
                return_value.setProperty(runtime, "tag", (int)tag);
                return return_value;
            }
        });
    jsiRuntime.global().setProperty(jsiRuntime, "crypto_secretstream_xchacha20poly1305_pull", std::move(jsi_crypto_secretstream_xchacha20poly1305_pull));

    auto jsi_to_base64 = jsi::Function::createFromHostFunction(
        jsiRuntime,
        jsi::PropNameID::forUtf8(jsiRuntime, "to_base64"),
        2, // utf8string, (int)variant
        [](jsi::Runtime &runtime, const jsi::Value &thisValue, const jsi::Value *arguments, size_t count) -> jsi::Value
        {
            if (arguments[0].isNull())
            {
                jsi::detail::throwJSError(runtime, "[react-native-sodium-jsi] string cannot be null in to_base64");
                return {};
            }
            if (arguments[1].isNull())
            {
                jsi::detail::throwJSError(runtime, "[react-native-sodium-jsi] variant cannot be null in to_base64");
                return {};
            }

            std::string utf8string = arguments[0].asString(runtime).utf8(runtime);
            uint8_t variant = arguments[1].asNumber();
            std::string base64string = binToBase64((uint8_t *)utf8string.data(), utf8string.size(), variant);
            return jsi::String::createFromUtf8(runtime, base64string);
        });
    jsiRuntime.global().setProperty(jsiRuntime, "to_base64", std::move(jsi_to_base64));

    auto jsi_from_base64 = jsi::Function::createFromHostFunction(
        jsiRuntime,
        jsi::PropNameID::forUtf8(jsiRuntime, "from_base64"),
        1, // base64string
        [](jsi::Runtime &runtime, const jsi::Value &thisValue, const jsi::Value *arguments, size_t count) -> jsi::Value
        {
            if (arguments[0].isNull())
            {
                jsi::detail::throwJSError(runtime, "[react-native-sodium-jsi] string cannot be null in from_base64");
                return {};
            }

            std::string base64string = arguments[0].asString(runtime).utf8(runtime);
            std::vector<uint8_t> utf8string = base64ToBin(runtime, base64string);

            return jsi::String::createFromUtf8(runtime, utf8string.data(), utf8string.size());
        });
    jsiRuntime.global().setProperty(jsiRuntime, "from_base64", std::move(jsi_from_base64));
}

void cleanup() {}
