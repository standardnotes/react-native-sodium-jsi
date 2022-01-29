cmake_minimum_required(VERSION 3.9.0)

set (PACKAGE_NAME "react-native-sodium-jsi")
set (BUILD_DIR ${CMAKE_SOURCE_DIR}/build)

set(ARCH_DIR ${ANDROID_ARCH_NAME})

if( ANDROID_ABI STREQUAL "armeabi-v7a")
  set( ARCH_DIR "armv7-a" )
elseif ( ANDROID_ABI STREQUAL "arm64-v8a")
  set( ARCH_DIR "armv8-a" )
elseif ( ANDROID_ABI STREQUAL "x86")
  set ( ARCH_DIR "i686" )
elseif ( ANDROID_ABI STREQUAL "x86_64")
  set ( ARCH_DIR "westmere" )
endif()

add_library(sodium SHARED IMPORTED)
include_directories( ${PROJECT_SOURCE_DIR}/../libsodium/libsodium-android-${ARCH_DIR}/include/ )
set_target_properties( sodium PROPERTIES IMPORTED_LOCATION ${PROJECT_SOURCE_DIR}/../libsodium/libsodium-android-${ARCH_DIR}/lib/libsodium.so )
file(COPY ${PROJECT_SOURCE_DIR}/../libsodium/libsodium-android-${ARCH_DIR}/lib/libsodium.so DESTINATION "${PROJECT_SOURCE_DIR}/lib/${ANDROID_ABI}")

if(${REACT_NATIVE_VERSION} LESS 66)
  set (
          INCLUDE_JSI_CPP
          "${NODE_MODULES_DIR}/react-native/ReactCommon/jsi/jsi/jsi.cpp"
  )
endif()

add_library(cpp
            SHARED
            cpp-adapter.cpp
)

include_directories(
        "../cpp"
        "${NODE_MODULES_DIR}/react-native/React"
        "${NODE_MODULES_DIR}/react-native/React/Base"
        "${NODE_MODULES_DIR}/react-native/ReactCommon/jsi"
)

add_library(reactnativesodiumjsi
        SHARED
        cpp-adapter.cpp
        ${INCLUDE_JSI_CPP}
        )
set_target_properties(
        reactnativesodiumjsi PROPERTIES
        CXX_STANDARD 14
        CXX_EXTENSIONS OFF
        POSITION_INDEPENDENT_CODE ON
)

file (GLOB LIBRN_DIR "${PREBUILT_DIR}/${ANDROID_ABI}")

find_library(
        log-lib
        log
)

find_library(
        REACT_NATIVE_JNI_LIB
        reactnativejni
        PATHS ${LIBRN_DIR}
        NO_CMAKE_FIND_ROOT_PATH
)

if(${REACT_NATIVE_VERSION} LESS 66)
  # JSI lib didn't exist on RN 0.65 and before. Simply omit it.
  set (JSI_LIB "")
else()
  # RN 0.66 distributes libjsi.so, can be used instead of compiling jsi.cpp manually.
  find_library(
          JSI_LIB
          jsi
          PATHS ${LIBRN_DIR}
          NO_CMAKE_FIND_ROOT_PATH
  )
endif()

target_link_libraries(
        reactnativesodiumjsi
        ${log-lib}
        ${JSI_LIB}
        ${REACT_NATIVE_JNI_LIB}
        android
)
