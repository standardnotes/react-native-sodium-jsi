# react-native-sodium-jsi

Precompiled binaries of [libsodium](https://libsodium.org) will be linked by default.

Optionally, you can choose to compile libsodium by yourself (run **npm&nbsp;run&nbsp;rebuild** in package directory). Source code will be downloaded and verified before compilation.

Supported Libsodium functions:

- `crypto_aead_xchacha20poly1305_ietf_encrypt`
- `crypto_aead_xchacha20poly1305_ietf_decrypt`
- `crypto_pwhash`
- `crypto_aead_xchacha20poly1305_ietf_keygen`
- `randombytes_buf`
- `randombytes_random`
- `to_base64`
- `from_base64`

### Source compilation

###### General prerequisites

- gpg (macports, homebrew)
- minisign (homebrew)

###### MacOS prerequisites

- libtool (macports, homebrew)
- autoconf (macports, homebrew)
- automake (macports, homebrew)
- Xcode (12 or newer)

###### Android prerequisites

- Android NDK
- CMake
- LLDB

### Recompile and repackage

1. `yarn rebundle`

### Usage

Using hermes on Android is required.

1. `npm install react-native-sodium-jsi`
2. `npx pod-install ios`
3. Run your app.

### Example app

1. `yarn bootstrap`
2. `yarn example`
3. `yarn ios` or `yarn android`
