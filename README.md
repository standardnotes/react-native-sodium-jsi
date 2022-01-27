# react-native-sodium

Precompiled binaries of [libsodium](https://libsodium.org) will be linked by default.
Optionally, you can choose to compile libsodium by yourself (run __npm&nbsp;run&nbsp;rebuild__ in package directory). Source code will be downloaded and verified before compilation.

### Source compilation
###### General prerequisites
* gpg (macports, homebrew)
* minisign (homebrew)

###### MacOS prerequisites
* libtool (macports, homebrew)
* autoconf (macports, homebrew)
* automake (macports, homebrew)
* Xcode (12 or newer)


###### Android prerequisites
* Android NDK
* CMake
* LLDB

### Recompile and repackage
1. `yarn rebundle`

### Usage

1. `npm install react-native-sodium`
2. `npx pod-install ios`
3. Run your app.

### Example app

1. `yarn bootstrap`
2. `yarn example`
3. `yarn ios` or `yarn android` 


### Credits
This repo is based on [react-native-sodium](https://github.com/lyubo/react-native-sodium) by @lyubo.
